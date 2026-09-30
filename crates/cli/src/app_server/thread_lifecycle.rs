//! History operations owned by the resident session's verified tenant and workspace.
//!
//! Public requests contain identities, never record-store or workspace paths. Archive restores
//! presentation visibility; permanent erasure uses the record owner's durable recovery receipt.

use std::path::{Path, PathBuf};

use base64::Engine;

use iteron_protocol::thread_lifecycle::{
    MAX_THREAD_EXPORT_BYTES, THREAD_LIFECYCLE_VERSION, ThreadLifecycleCommandV1,
};
use iteron_protocol::{RunId, TenantId};
use serde_json::{Value, json};

use crate::runtime::Agent;

use super::{ControlReply, thread_presentation};

const MAX_PHYSICAL_EXPORT_BYTES: u64 = 8 * 1024 * 1024;

pub(super) fn apply(agent: &mut Agent, command: ThreadLifecycleCommandV1) -> ControlReply {
    let result = HistoryScope::from_agent(agent).and_then(|scope| scope.execute(command));
    match result {
        Ok(value) => {
            if value["type"] == "thread_deleted_v1" {
                agent.lifecycle_event(
                    "session.deleted",
                    None,
                    iteron_protocol::LifecyclePayload {
                        outcome_code: Some("deleted".into()),
                        reason_code: Some("operator_erasure".into()),
                        ..iteron_protocol::LifecyclePayload::default()
                    },
                );
            }
            ControlReply::ThreadLifecycle(value)
        }
        Err(reason) => ControlReply::Refused(reason),
    }
}

struct HistoryScope {
    runs: PathBuf,
    workspace: PathBuf,
    tenant: TenantId,
    current: RunId,
}

impl HistoryScope {
    fn from_agent(agent: &Agent) -> Result<Self, String> {
        Ok(Self {
            runs: agent
                .rollout
                .path()
                .parent()
                .ok_or("record store unavailable")?
                .to_owned(),
            workspace: agent
                .workspace
                .canonicalize()
                .map_err(|_| "workspace unavailable")?,
            tenant: agent.rollout.tenant().clone(),
            current: agent.rollout.run_id().clone(),
        })
    }

    fn metadata(&self, run: &RunId) -> Result<iteron_record::SessionMeta, String> {
        let meta = iteron_record::session::meta(&self.runs, run)
            .map_err(|_| "thread unavailable in this workspace".to_owned())?;
        if meta.tenant != self.tenant || !same_workspace(&meta.cwd, &self.workspace) {
            return Err("thread unavailable in this workspace".into());
        }
        Ok(meta)
    }

    fn execute(&self, command: ThreadLifecycleCommandV1) -> Result<Value, String> {
        command.validate().map_err(str::to_owned)?;
        if let ThreadLifecycleCommandV1::List { cursor, limit } = command {
            return self.list(cursor.as_deref(), limit);
        }
        let run = command
            .run_id()
            .expect("non-list command has an exact identity")
            .clone();
        let meta = self.metadata(&run)?;
        match command {
            ThreadLifecycleCommandV1::List { .. } => {
                unreachable!("list was dispatched before per-thread metadata access")
            }
            ThreadLifecycleCommandV1::Read { .. } => self.view(&meta),
            ThreadLifecycleCommandV1::Rename { title, .. } => {
                thread_presentation::update(
                    &self.runs,
                    &run.0,
                    thread_presentation::Mutation::Rename(title),
                )?;
                self.view(&meta)
            }
            ThreadLifecycleCommandV1::Archive { archived, .. } => {
                thread_presentation::update(
                    &self.runs,
                    &run.0,
                    thread_presentation::Mutation::Archive(archived),
                )?;
                self.view(&meta)
            }
            ThreadLifecycleCommandV1::Pin { pinned, .. } => {
                thread_presentation::update(
                    &self.runs,
                    &run.0,
                    thread_presentation::Mutation::Pin(pinned),
                )?;
                self.view(&meta)
            }
            ThreadLifecycleCommandV1::Export { .. } => self.export(&run),
            ThreadLifecycleCommandV1::Delete { .. } => self.delete(&run),
        }
    }

    fn list(&self, cursor: Option<&str>, limit: u16) -> Result<Value, String> {
        let cursor = cursor
            .map(|cursor| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(cursor)
                    .map_err(|_| "invalid thread cursor")?;
                serde_json::from_slice::<iteron_record::SessionPageCursor>(&bytes)
                    .map_err(|_| "invalid thread cursor")
            })
            .transpose()?;
        let page = iteron_record::session::page(
            &self.runs,
            &self.tenant,
            Some(&self.workspace),
            cursor,
            Some(limit as usize),
        );
        let threads = page
            .sessions
            .iter()
            .map(|meta| self.view(meta))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = page
            .next_cursor
            .map(|cursor| {
                serde_json::to_vec(&cursor)
                    .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
            })
            .transpose()
            .map_err(|_| "thread cursor serialization failed")?;
        Ok(json!({
            "type":"thread_list_v1", "contract_version":THREAD_LIFECYCLE_VERSION,
            "threads":threads, "next_cursor":next_cursor, "has_more":page.has_more,
            "index_ready":page.index_ready, "cursor_stale":page.cursor_stale,
            "rebuild_recommended":page.rebuild_recommended,
        }))
    }

    fn view(&self, meta: &iteron_record::SessionMeta) -> Result<Value, String> {
        let view = thread_presentation::load(&self.runs, &meta.run_id.0)?;
        Ok(json!({
            "type": "thread_history_v1",
            "contract_version": THREAD_LIFECYCLE_VERSION,
            "run_id": meta.run_id,
            "title": iteron_record::redact::scrub(view.title.as_deref().unwrap_or(&meta.title)),
            "pinned": view.pinned,
            "archived": view.archived,
            "turns": meta.turns,
            "created_at": meta.created_at,
            "updated_at": meta.updated_at,
            "active": meta.run_id == self.current,
            "retention": {"archive_reversible": true, "permanent_erasure_reversible": false},
        }))
    }

    fn export(&self, run: &RunId) -> Result<Value, String> {
        // Export one physical journal. Fork ancestry remains an explicit provenance reference;
        // export does not recursively materialize an unbounded graph or silently omit lineage.
        let path = self.runs.join(format!("{}.jsonl", run.0));
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| "thread export unavailable")?;
        if !metadata.is_file() || metadata.len() > MAX_PHYSICAL_EXPORT_BYTES {
            return Err("thread export exceeds its bounded physical journal limit".into());
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        options.create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        let writer_path = path.with_extension("jsonl.lock");
        #[cfg(not(windows))]
        let writer_path = path.clone();
        let writer_gate = options
            .open(&writer_path)
            .map_err(|_| "thread export unavailable")?;
        writer_gate
            .try_lock()
            .map_err(|_| "thread export unavailable while its journal is active")?;
        if std::fs::metadata(&path)
            .map_err(|_| "thread export unavailable")?
            .len()
            > MAX_PHYSICAL_EXPORT_BYTES
        {
            return Err("thread export exceeds its physical byte limit".into());
        }
        let owner = iteron_record::acquire_verified_rollout_owner(&path)
            .map_err(|_| "thread export unavailable while its journal is active")?;
        if owner.tenant() != &self.tenant {
            return Err("thread export unavailable in this workspace".into());
        }
        let events = iteron_record::replay(&path).map_err(|_| "thread export integrity failed")?;
        let export = json!({
            "schema": "iteron.physical-thread-export.v1",
            "run_id": run,
            "ancestry": "referenced_in_genesis",
            "events": events,
        });
        let text =
            serde_json::to_string(&export).map_err(|_| "thread export serialization failed")?;
        if text.len() > MAX_THREAD_EXPORT_BYTES {
            return Err("thread export exceeds its response byte limit".into());
        }
        Ok(json!({
            "type": "thread_export_v1",
            "contract_version": THREAD_LIFECYCLE_VERSION,
            "run_id": run,
            "mime_type": "application/json",
            "content": iteron_record::redact::scrub(&text),
        }))
    }

    fn delete(&self, run: &RunId) -> Result<Value, String> {
        if run == &self.current {
            return Err("cannot erase the resident thread; switch away first".into());
        }
        // Rollout writers use a sidecar lease on Windows. The record erasure operation also
        // checks its journal lock; keep the real writer lease alive across that operation.
        #[cfg(windows)]
        let _writer_gate = {
            let path = self.runs.join(format!("{}.jsonl.lock", run.0));
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .map_err(|_| "thread writer lease unavailable")?;
            file.try_lock()
                .map_err(|_| "thread is active in another process")?;
            file
        };
        let operation = format!(
            "thread.delete.{}.{}",
            std::process::id(),
            crate::erasure_now_unix_ms()
        );
        let authority = iteron_record::erasure::authorize_local_erasure(&self.runs)
            .map_err(|_| "thread erasure authority unavailable")?;
        let request = iteron_protocol::ErasureRequest {
            operation_id: iteron_protocol::ErasureOperationId::new(operation)
                .map_err(|error| error.to_string())?,
            authority_id: authority.id().clone(),
            requested_at_unix_ms: crate::erasure_now_unix_ms(),
            target: iteron_protocol::ErasureTarget::ExactSession {
                scope_id: iteron_protocol::ErasureScopeId::new(self.tenant.0.clone())
                    .map_err(|error| error.to_string())?,
                run_id: iteron_protocol::ErasureTargetId::new(run.0.clone())
                    .map_err(|error| error.to_string())?,
            },
        };
        let receipt = iteron_record::erasure::execute_erasure(&self.runs, request)
            .map_err(|_| "thread erasure failed; inspect the durable erasure receipt")?;
        if receipt.state() != iteron_protocol::ErasureState::Verified {
            return Err(format!("thread erasure refused: {:?}", receipt.failure()));
        }
        thread_presentation::remove(&self.runs, &run.0)?;
        Ok(
            json!({"type":"thread_deleted_v1", "contract_version":THREAD_LIFECYCLE_VERSION, "run_id":run, "receipt":receipt}),
        )
    }
}

fn same_workspace(found: &Path, expected: &Path) -> bool {
    found.canonicalize().is_ok_and(|path| path == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{Effort, Event, EventKind, Seq, TurnId};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "iteron-thread-control-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(path.join("workspace")).unwrap();
            std::fs::create_dir_all(path.join("other")).unwrap();
            Self(path)
        }

        fn scope(&self) -> HistoryScope {
            HistoryScope {
                runs: self.0.join("runs"),
                workspace: self.0.join("workspace").canonicalize().unwrap(),
                tenant: TenantId::default(),
                current: RunId("resident".into()),
            }
        }

        fn write(&self, id: &str, workspace: &str, tenant: TenantId) -> iteron_record::Rollout {
            let mut rollout =
                iteron_record::Rollout::open(&self.0.join("runs"), &RunId(id.into()), tenant)
                    .unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::RunStart {
                        cwd: self.0.join(workspace).to_string_lossy().into_owned(),
                        model: "fixture".into(),
                        effort: Effort::Low,
                        created_at: 1,
                        environment: None,
                        parent_run: None,
                        forked_at: None,
                        parent_hash_at_seq: None,
                        config_digest: String::new(),
                        agent_definition_tag: None,
                        max_usd: None,
                    },
                })
                .unwrap();
            rollout
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn public_history_controls_are_tenant_and_workspace_scoped() {
        let fixture = Fixture::new();
        drop(fixture.write("mine", "workspace", TenantId::default()));
        drop(fixture.write("otherrepo", "other", TenantId::default()));
        drop(fixture.write("othertenant", "workspace", TenantId("other-tenant".into())));
        let scope = fixture.scope();
        for id in ["otherrepo", "othertenant", "../mine"] {
            assert!(
                scope
                    .execute(ThreadLifecycleCommandV1::Rename {
                        run_id: RunId(id.into()),
                        title: "forged".into()
                    })
                    .is_err()
            );
        }
        let result = scope
            .execute(ThreadLifecycleCommandV1::Rename {
                run_id: RunId("mine".into()),
                title: "renamed".into(),
            })
            .unwrap();
        assert_eq!(result["title"], "renamed");
        assert_eq!(
            thread_presentation::load(&scope.runs, "mine")
                .unwrap()
                .title
                .as_deref(),
            Some("renamed")
        );
    }

    #[test]
    fn archive_is_reversible_and_permanent_erasure_is_explicit_and_durable() {
        let fixture = Fixture::new();
        drop(fixture.write("mine", "workspace", TenantId::default()));
        drop(fixture.write("resident", "workspace", TenantId::default()));
        let scope = fixture.scope();
        for archived in [true, false] {
            let reply = scope
                .execute(ThreadLifecycleCommandV1::Archive {
                    run_id: RunId("mine".into()),
                    archived,
                })
                .unwrap();
            assert_eq!(reply["archived"], archived);
            assert!(scope.runs.join("mine.jsonl").exists());
        }
        assert!(
            scope
                .execute(ThreadLifecycleCommandV1::Delete {
                    run_id: RunId("mine".into()),
                    confirm_permanent_erasure: false
                })
                .is_err()
        );
        assert!(
            scope
                .execute(ThreadLifecycleCommandV1::Delete {
                    run_id: RunId("resident".into()),
                    confirm_permanent_erasure: true
                })
                .is_err()
        );
        let reply = scope
            .execute(ThreadLifecycleCommandV1::Delete {
                run_id: RunId("mine".into()),
                confirm_permanent_erasure: true,
            })
            .unwrap();
        assert_eq!(reply["type"], "thread_deleted_v1");
        assert!(!scope.runs.join("mine.jsonl").exists());
        assert_eq!(
            iteron_record::erasure::list_erasure_receipts(&scope.runs, 16)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn history_pages_keep_scope_and_reject_foreign_cursor_shapes() {
        let fixture = Fixture::new();
        drop(fixture.write("mine", "workspace", TenantId::default()));
        drop(fixture.write("otherrepo", "other", TenantId::default()));
        let scope = fixture.scope();
        iteron_record::session::reindex(&scope.runs).unwrap();
        let page = scope
            .execute(ThreadLifecycleCommandV1::List {
                cursor: None,
                limit: 25,
            })
            .unwrap();
        assert_eq!(page["index_ready"], true);
        assert_eq!(page["threads"].as_array().unwrap().len(), 1);
        assert_eq!(page["threads"][0]["run_id"], "mine");
        assert!(
            scope
                .execute(ThreadLifecycleCommandV1::List {
                    cursor: Some("not-a-cursor".into()),
                    limit: 25
                })
                .is_err()
        );
        assert!(
            scope
                .execute(ThreadLifecycleCommandV1::List {
                    cursor: None,
                    limit: 101
                })
                .is_err()
        );
    }

    #[test]
    fn export_refuses_active_journals_and_returns_verified_bounded_content() {
        let fixture = Fixture::new();
        let writer = fixture.write("mine", "workspace", TenantId::default());
        let scope = fixture.scope();
        assert!(
            scope
                .execute(ThreadLifecycleCommandV1::Export {
                    run_id: RunId("mine".into())
                })
                .is_err()
        );
        drop(writer);
        let reply = scope
            .execute(ThreadLifecycleCommandV1::Export {
                run_id: RunId("mine".into()),
            })
            .unwrap();
        assert_eq!(reply["type"], "thread_export_v1");
        let export: Value = serde_json::from_str(reply["content"].as_str().unwrap()).unwrap();
        assert_eq!(export["run_id"], "mine");
        assert!(!export["events"].as_array().unwrap().is_empty());
    }
}
