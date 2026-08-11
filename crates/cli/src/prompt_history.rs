//! Bounded, repository-scoped prompt history for the interactive frontend.
//!
//! Prompt text is operator data. The operator-owned history namespace persists handles only; each
//! entry is a source-run derivative whose scrubbed bytes are encrypted in the record content store.
//! Exact-session deletion therefore refuses while a live history derivative still retains that
//! run. Content revocation closes and prunes only entries descended from the revoked source, while
//! independently lineaged entries from other runs remain readable. Attachments are never
//! serialized, and `Disabled` creates no store.

use crate::config::PromptHistoryMode;
use iteron_protocol::{RunId, TenantId};
use iteron_record::{
    PrivateContentClass, PrivateContentDerivativeStore, PrivateContentHandle,
    PrivateContentNamespace, PrivateContentRetention, PrivateContentSource,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) const MAX_ENTRIES: usize = 200;
const MAX_ENTRY_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 1024 * 1024;
const LEGACY_STATE_VERSION: u32 = 1;
const UNLINEAGED_STATE_VERSION: u32 = 2;
const STATE_VERSION: u32 = 3;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(crate) fn source_run_from_rollout(path: &Path) -> Option<RunId> {
    path.file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|run| !run.is_empty())
        .map(|run| RunId(run.to_owned()))
}

mod private_storage;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub(crate) schema_version: u32,
    pub(crate) history: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) draft: Option<String>,
}

impl State {
    pub(crate) fn new(history: Vec<String>, draft: Option<String>) -> Self {
        Self {
            schema_version: STATE_VERSION,
            history,
            draft,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    schema_version: u32,
    history: Vec<PersistedEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    draft: Option<PersistedEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedEntry {
    handle: PrivateContentHandle,
    source: SourceBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBinding {
    source: PrivateContentSource,
    /// Present only for a pre-submit/draft source owned by this history/run namespace. Record
    /// sources already carry their physical reference in the rollout graph.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    synthetic_seq: Option<u64>,
}

#[derive(Clone, Debug, Default)]
struct LineageState {
    history: Vec<(String, SourceBinding)>,
    draft: Option<(String, SourceBinding)>,
}

#[derive(Deserialize)]
struct VersionProbe {
    schema_version: u32,
}

#[derive(Clone)]
pub(crate) struct Store {
    path: PathBuf,
    private: PrivateContentDerivativeStore,
    runs_dir: PathBuf,
    tenant: TenantId,
    source_seq_base: u64,
    lineage: Arc<Mutex<LineageState>>,
}

impl Store {
    pub(crate) fn resolve(
        mode: PromptHistoryMode,
        config_home: Option<PathBuf>,
        workspace: &Path,
    ) -> anyhow::Result<Option<Self>> {
        if mode == PromptHistoryMode::Disabled {
            return Ok(None);
        }
        let Some(config_home) = config_home else {
            return Ok(None);
        };
        let runs_dir = iteron_protocol::home::path(&config_home, "runs");
        Self::resolve_with_runs_dir(mode, config_home, workspace, runs_dir)
    }

    pub(crate) fn resolve_with_runs_dir(
        mode: PromptHistoryMode,
        config_home: PathBuf,
        workspace: &Path,
        runs_dir: PathBuf,
    ) -> anyhow::Result<Option<Self>> {
        if mode == PromptHistoryMode::Disabled {
            return Ok(None);
        }
        let directory = iteron_protocol::home::path(&config_home, "history");
        let filename = match mode {
            PromptHistoryMode::Project => {
                let identity = workspace.canonicalize().map_err(|error| {
                    anyhow::anyhow!("cannot identify workspace for prompt history: {error}")
                })?;
                let digest = Sha256::digest(identity.to_string_lossy().as_bytes());
                let identity: String = digest[..16]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                format!("project-{identity}.json")
            }
            PromptHistoryMode::Global => "global.json".to_owned(),
            PromptHistoryMode::Disabled => unreachable!("returned above"),
        };
        let path = directory.join(filename);
        let owner_digest = Sha256::digest(path.to_string_lossy().as_bytes());
        let owner = RunId(format!(
            "prompt-history-{}",
            hex::encode(&owner_digest[..16])
        ));
        let tenant = TenantId::default();
        let private = PrivateContentDerivativeStore::open_registered(
            runs_dir.clone(),
            tenant.clone(),
            owner,
            PrivateContentNamespace::PromptHistory,
            PrivateContentClass::Transcript,
            PrivateContentRetention::ExplicitRevocation,
            MAX_ENTRY_BYTES,
        )?;
        // One configured history namespace is active for a run. The high 56 bits bind its
        // synthetic-source sequence range to the manifest path; the low byte is the entry slot.
        // Owning these pre-submit roots with the actual run makes exact-session deletion see (and
        // refuse to orphan) an unsent draft derivative.
        let source_seq_digest = Sha256::digest(path.to_string_lossy().as_bytes());
        let mut source_seq_bytes = [0_u8; 8];
        source_seq_bytes.copy_from_slice(&source_seq_digest[..8]);
        let source_seq_base = u64::from_be_bytes(source_seq_bytes) & !0xff;
        Ok(Some(Self {
            path,
            private,
            runs_dir,
            tenant,
            source_seq_base,
            lineage: Arc::new(Mutex::new(LineageState::default())),
        }))
    }

    pub(crate) fn load(&self, active_run: &RunId) -> anyhow::Result<State> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(State::default());
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!("prompt history must be a regular non-symlink file");
        }
        if metadata.len() > MAX_STATE_BYTES as u64 {
            anyhow::bail!("prompt history exceeds its {MAX_STATE_BYTES}-byte bound");
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        fs::File::open(&self.path)?
            .take((MAX_STATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_STATE_BYTES {
            anyhow::bail!("prompt history exceeds its {MAX_STATE_BYTES}-byte bound");
        }
        let version: VersionProbe = serde_json::from_slice(&bytes)?;
        match version.schema_version {
            STATE_VERSION => self.hydrate(serde_json::from_slice(&bytes)?, active_run),
            LEGACY_STATE_VERSION => {
                let state = bound_and_scrub(serde_json::from_slice(&bytes)?);
                // Migrate before exposing legacy plaintext. A failed CAS write leaves this
                // history unavailable instead of serving an unrevocable derivative.
                self.save(state.clone(), active_run)?;
                Ok(state)
            }
            UNLINEAGED_STATE_VERSION => anyhow::bail!(
                "prompt history schema version {UNLINEAGED_STATE_VERSION} has no source lineage; refusing to serve it"
            ),
            version => anyhow::bail!("unsupported prompt history schema version {version}"),
        }
    }

    fn save(&self, state: State, active_run: &RunId) -> anyhow::Result<()> {
        let prepared = prepare(state);
        let (history, draft) = self.stage_entries(&prepared, active_run)?;
        let persisted = PersistedState {
            schema_version: STATE_VERSION,
            history,
            draft,
        };
        self.publish(&persisted)?;
        self.reconcile(&persisted)?;
        self.remember(&prepared.state, &persisted)?;
        Ok(())
    }

    fn publish(&self, persisted: &PersistedState) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(&persisted)?;
        if bytes.len() > MAX_STATE_BYTES {
            anyhow::bail!("prompt history encoding exceeds its fixed bound");
        }
        let directory = self
            .path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("prompt history path has no parent"))?;
        if let Ok(metadata) = fs::symlink_metadata(directory)
            && metadata.file_type().is_symlink()
        {
            anyhow::bail!("prompt history directory cannot be a symlink");
        }
        fs::create_dir_all(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_symlink()
        {
            anyhow::bail!("prompt history file cannot be a symlink");
        }

        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = directory.join(format!(
            ".prompt-history-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        let result = (|| -> anyhow::Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.path)?;
            #[cfg(unix)]
            fs::File::open(directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        Ok(())
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }
}

struct PreparedState {
    state: State,
    history_sources: Vec<String>,
    draft_source: Option<String>,
}

/// One fixed-depth background writer. Keystrokes never wait for an fsync; when its single pending
/// slot is full, the newer snapshot is skipped and the normal-exit flush still writes final state.
pub(crate) struct Writer {
    sender: Option<std::sync::mpsc::SyncSender<(State, RunId)>>,
    task: Option<std::thread::JoinHandle<()>>,
}

impl Writer {
    pub(crate) fn new(store: Option<Store>) -> Self {
        let Some(store) = store else {
            return Self {
                sender: None,
                task: None,
            };
        };
        let (sender, receiver) = std::sync::mpsc::sync_channel::<(State, RunId)>(1);
        let task = std::thread::spawn(move || {
            while let Ok((state, active_run)) = receiver.recv() {
                let _ = store.save(state, &active_run);
            }
        });
        Self {
            sender: Some(sender),
            task: Some(task),
        }
    }

    pub(crate) fn schedule(&self, state: State, active_run: RunId) {
        if let Some(sender) = &self.sender {
            let _ = sender.try_send((state, active_run));
        }
    }

    pub(crate) fn finish(mut self, state: State, active_run: RunId) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send((state, active_run));
            drop(sender);
        }
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn prepare(state: State) -> PreparedState {
    let mut retained = Vec::new();
    let mut total = 0_usize;
    for entry in state.history.into_iter().rev() {
        let source = iteron_record::redact::scrub(&entry);
        let scrubbed = sanitize(&source);
        if scrubbed.trim().is_empty() || scrubbed.len() > MAX_ENTRY_BYTES {
            continue;
        }
        let Some(next) = total.checked_add(scrubbed.len()) else {
            break;
        };
        if retained.len() == MAX_ENTRIES || next > MAX_STATE_BYTES / 2 {
            break;
        }
        total = next;
        retained.push((scrubbed, source));
    }
    retained.reverse();
    let (history, history_sources): (Vec<_>, Vec<_>) = retained.into_iter().unzip();
    let draft = state
        .draft
        .map(|draft| {
            let source = iteron_record::redact::scrub(&draft);
            (sanitize(&source), source)
        })
        .filter(|(draft, _)| !draft.is_empty() && draft.len() <= MAX_ENTRY_BYTES);
    let (draft, draft_source) = draft
        .map(|(draft, source)| (Some(draft), Some(source)))
        .unwrap_or((None, None));
    PreparedState {
        state: State::new(history, draft),
        history_sources,
        draft_source,
    }
}

fn bound_and_scrub(state: State) -> State {
    prepare(state).state
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            let scalar = *character as u32;
            *character == '\n'
                || *character == '\t'
                || !matches!(
                    scalar,
                    0x00..=0x1f
                        | 0x7f
                        | 0x80..=0x9f
                        | 0x200b..=0x200f
                        | 0x202a..=0x202e
                        | 0x2060..=0x2064
                        | 0xfeff
                )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{
        Effort, ErasureAuthorityId, ErasureFailureCode, ErasureOperationId, ErasureRequest,
        ErasureScopeId, ErasureState, ErasureTarget, ErasureTargetId, Event, EventKind, Message,
        Seq, TurnId,
    };

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "core-prompt-history-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn source_run(name: &str) -> RunId {
        RunId(format!("history-test-{name}"))
    }

    fn append_prompt(runs: &Path, repo: &Path, run: &RunId, text: &str) {
        let mut rollout = iteron_record::Rollout::open(runs, run, TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: repo.to_string_lossy().into_owned(),
                    model: "model-a".into(),
                    effort: Effort::Medium,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: "cfg".into(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text(text),
                },
            })
            .unwrap();
    }

    fn revoke_content(runs: &Path, operation: &str, digest: iteron_protocol::ErasureContentDigest) {
        let authority = iteron_record::erasure::authorize_local_erasure(runs).unwrap();
        let receipt = iteron_record::erasure::execute_erasure(
            runs,
            ErasureRequest {
                operation_id: ErasureOperationId::new(operation).unwrap(),
                authority_id: ErasureAuthorityId::new(authority.id().as_str()).unwrap(),
                requested_at_unix_ms: 1,
                target: ErasureTarget::ContentRevocation {
                    scope_id: ErasureScopeId::new("default").unwrap(),
                    content_digest: digest,
                },
            },
        )
        .unwrap();
        assert_eq!(receipt.state(), ErasureState::Verified);
    }

    #[test]
    fn project_global_and_private_modes_have_distinct_path_semantics() {
        let home = scratch("modes-home");
        let first = scratch("modes-first");
        let second = scratch("modes-second");
        let a = Store::resolve(PromptHistoryMode::Project, Some(home.clone()), &first)
            .unwrap()
            .unwrap();
        let b = Store::resolve(PromptHistoryMode::Project, Some(home.clone()), &second)
            .unwrap()
            .unwrap();
        assert_ne!(a.path(), b.path());
        assert!(
            Store::resolve(PromptHistoryMode::Disabled, Some(home.clone()), &first)
                .unwrap()
                .is_none()
        );
        let global_a = Store::resolve(PromptHistoryMode::Global, Some(home.clone()), &first)
            .unwrap()
            .unwrap();
        let global_b = Store::resolve(PromptHistoryMode::Global, Some(home), &second)
            .unwrap()
            .unwrap();
        assert_eq!(global_a.path(), global_b.path());
    }

    #[test]
    fn round_trip_is_bounded_scrubbed_and_private() {
        let home = scratch("roundtrip-home");
        let repo = scratch("roundtrip-repo");
        let store = Store::resolve(PromptHistoryMode::Project, Some(home), &repo)
            .unwrap()
            .unwrap();
        let credential_shape = format!("use {}", concat!("sk-", "abcdefghijklmnopqrstuvwxyz"));
        store
            .save(
                State::new(
                    vec!["hello\u{200b} world".into(), credential_shape.clone()],
                    Some("draft\x1b text".into()),
                ),
                &source_run("roundtrip"),
            )
            .unwrap();
        let loaded = store.load(&source_run("roundtrip")).unwrap();
        assert_eq!(loaded.history[0], "hello world");
        assert!(loaded.history[1].contains("[REDACTED:"));
        assert!(!loaded.history[1].contains(&credential_shape["use ".len()..]));
        assert_eq!(loaded.draft.as_deref(), Some("draft text"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(store.path()).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn background_writer_preserves_order_and_normal_exit_flushes_the_final_draft() {
        let home = scratch("writer-home");
        let repo = scratch("writer-repo");
        let store = Store::resolve(PromptHistoryMode::Project, Some(home), &repo)
            .unwrap()
            .unwrap();
        let writer = Writer::new(Some(store.clone()));
        writer.schedule(
            State::new(vec!["first".into()], Some("stale".into())),
            source_run("writer"),
        );
        writer.finish(
            State::new(
                vec!["first".into(), "second".into()],
                Some("final 多行\ndraft".into()),
            ),
            source_run("writer"),
        );

        let loaded = store.load(&source_run("writer")).unwrap();
        assert_eq!(loaded.history, vec!["first", "second"]);
        assert_eq!(loaded.draft.as_deref(), Some("final 多行\ndraft"));
    }

    #[test]
    fn sanitized_history_is_lineaged_to_the_record_and_source_revocation_refuses_old_manifest() {
        let home = scratch("lineage-home");
        let repo = scratch("lineage-repo");
        let runs = iteron_protocol::home::path(&home, "runs");
        let run = source_run("lineage");
        let raw = "hello\u{200b} source";
        let mut rollout = iteron_record::Rollout::open(&runs, &run, TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: repo.to_string_lossy().into_owned(),
                    model: "model-a".into(),
                    effort: Effort::Medium,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: "cfg".into(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        let store = Store::resolve(PromptHistoryMode::Project, Some(home.clone()), &repo)
            .unwrap()
            .unwrap();
        store
            .save(State::new(vec![raw.to_owned()], None), &run)
            .unwrap();
        let synthetic: PersistedState =
            serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();
        assert_eq!(synthetic.history[0].source.source.owner, run);
        assert!(synthetic.history[0].source.synthetic_seq.is_some());

        // Simulate the crash boundary: the pre-append background snapshot is durable, then the
        // journal Message lands, but no normal-exit history flush runs.
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text(raw),
                },
            })
            .unwrap();
        drop(rollout);
        drop(store);

        let store = Store::resolve(PromptHistoryMode::Project, Some(home.clone()), &repo)
            .unwrap()
            .unwrap();
        assert_eq!(store.load(&run).unwrap().history, ["hello source"]);
        let manifest: PersistedState =
            serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();
        assert_eq!(manifest.history.len(), 1);
        assert_eq!(manifest.history[0].source.source.owner, run);
        assert!(manifest.history[0].source.synthetic_seq.is_none());
        assert_ne!(
            manifest.history[0].handle.digest, manifest.history[0].source.source.digest,
            "the sanitize transform must be represented by durable source→derivative lineage"
        );
        let history_path = store.path().to_path_buf();
        let source_digest = manifest.history[0].source.source.digest.clone();
        drop(store);

        let authority = iteron_record::erasure::authorize_local_erasure(&runs).unwrap();
        let receipt = iteron_record::erasure::execute_erasure(
            &runs,
            ErasureRequest {
                operation_id: ErasureOperationId::new("history-source-revoke").unwrap(),
                authority_id: ErasureAuthorityId::new(authority.id().as_str()).unwrap(),
                requested_at_unix_ms: 1,
                target: ErasureTarget::ContentRevocation {
                    scope_id: ErasureScopeId::new("default").unwrap(),
                    content_digest: source_digest,
                },
            },
        )
        .unwrap();
        assert_eq!(receipt.state(), ErasureState::Verified);
        assert!(
            history_path.exists(),
            "the stale manifest remains a useful read-gate oracle"
        );

        let reopened = Store::resolve(PromptHistoryMode::Project, Some(home), &repo)
            .unwrap()
            .unwrap();
        assert!(
            reopened.load(&run).unwrap().history.is_empty(),
            "a copied old history manifest must not serve its entry after source revocation"
        );
    }

    #[test]
    fn source_revoked_after_append_before_reload_is_never_served() {
        let home = scratch("crash-revoke-home");
        let repo = scratch("crash-revoke-repo");
        let runs = iteron_protocol::home::path(&home, "runs");
        let run = source_run("crash-revoke");
        let raw = "crash​ boundary";
        let mut rollout = iteron_record::Rollout::open(&runs, &run, TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: repo.to_string_lossy().into_owned(),
                    model: "model-a".into(),
                    effort: Effort::Medium,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: "cfg".into(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        let store = Store::resolve(PromptHistoryMode::Project, Some(home.clone()), &repo)
            .unwrap()
            .unwrap();
        store
            .save(State::new(vec![raw.into()], None), &run)
            .unwrap();
        let synthetic: PersistedState =
            serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();
        let source_digest = synthetic.history[0].source.source.digest.clone();
        assert!(synthetic.history[0].source.synthetic_seq.is_some());

        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text(raw),
                },
            })
            .unwrap();
        drop(rollout);
        drop(store);

        // This is the exact crash window: the RecordField is durable but the v3 manifest still
        // says synthetic. Revocation wins before the next process gets any chance to hydrate.
        revoke_content(&runs, "crash-boundary-revoke", source_digest);
        let reopened = Store::resolve(PromptHistoryMode::Project, Some(home), &repo)
            .unwrap()
            .unwrap();
        assert!(
            reopened.load(&run).unwrap().history.is_empty(),
            "reload must reconcile or refuse before reading plaintext through stale authority"
        );
    }

    #[test]
    fn unsent_draft_blocks_exact_delete_until_its_source_is_revoked() {
        let home = scratch("draft-delete-home");
        let repo = scratch("draft-delete-repo");
        let runs = iteron_protocol::home::path(&home, "runs");
        let run = source_run("draft-delete");
        let mut rollout = iteron_record::Rollout::open(&runs, &run, TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: repo.to_string_lossy().into_owned(),
                    model: "model-a".into(),
                    effort: Effort::Medium,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: "cfg".into(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        drop(rollout);
        let store = Store::resolve(PromptHistoryMode::Project, Some(home.clone()), &repo)
            .unwrap()
            .unwrap();
        store
            .save(State::new(Vec::new(), Some("unsent draft".into())), &run)
            .unwrap();
        let persisted: PersistedState =
            serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();
        let source_digest = persisted.draft.unwrap().source.source.digest;
        drop(store);

        let authority = iteron_record::erasure::authorize_local_erasure(&runs).unwrap();
        let exact = |operation: &str| ErasureRequest {
            operation_id: ErasureOperationId::new(operation).unwrap(),
            authority_id: ErasureAuthorityId::new(authority.id().as_str()).unwrap(),
            requested_at_unix_ms: 1,
            target: ErasureTarget::ExactSession {
                scope_id: ErasureScopeId::new("default").unwrap(),
                run_id: ErasureTargetId::new(run.0.clone()).unwrap(),
            },
        };
        let refused =
            iteron_record::erasure::execute_erasure(&runs, exact("draft-delete-refused")).unwrap();
        assert_eq!(refused.state(), ErasureState::Failed);
        assert_eq!(
            refused.failure(),
            Some(ErasureFailureCode::RetainedByDerivatives),
            "exact deletion must fail closed while an unsent draft derivative remains live"
        );
        assert!(runs.join(format!("{}.jsonl", run.0)).exists());

        let revoked = iteron_record::erasure::execute_erasure(
            &runs,
            ErasureRequest {
                operation_id: ErasureOperationId::new("draft-source-revoke").unwrap(),
                authority_id: ErasureAuthorityId::new(authority.id().as_str()).unwrap(),
                requested_at_unix_ms: 2,
                target: ErasureTarget::ContentRevocation {
                    scope_id: ErasureScopeId::new("default").unwrap(),
                    content_digest: source_digest,
                },
            },
        )
        .unwrap();
        assert_eq!(revoked.state(), ErasureState::Verified);
        let stale = Store::resolve(PromptHistoryMode::Project, Some(home), &repo)
            .unwrap()
            .unwrap();
        assert!(stale.load(&run).unwrap().draft.is_none());
        drop(stale);

        let deleted =
            iteron_record::erasure::execute_erasure(&runs, exact("draft-delete-after-revoke"))
                .unwrap();
        assert_eq!(deleted.state(), ErasureState::Verified);
        assert!(!runs.join(format!("{}.jsonl", run.0)).exists());
    }

    #[test]
    fn adopted_run_binds_only_new_entries_and_revocation_is_entry_scoped() {
        let home = scratch("adopt-lineage-home");
        let repo = scratch("adopt-lineage-repo");
        let runs = iteron_protocol::home::path(&home, "runs");
        let run_a = source_run("adopt-a");
        let run_b = source_run("adopt-b");
        append_prompt(&runs, &repo, &run_a, "prompt from A");
        append_prompt(&runs, &repo, &run_b, "prompt from B");

        let store = Store::resolve(PromptHistoryMode::Project, Some(home.clone()), &repo)
            .unwrap()
            .unwrap();
        store
            .save(State::new(vec!["prompt from A".into()], None), &run_a)
            .unwrap();
        // Model session adoption: a full-state rewrite carries A forward and appends B while the
        // active rollout identity changes. Only the new entry may acquire B's source authority.
        store
            .save(
                State::new(vec!["prompt from A".into(), "prompt from B".into()], None),
                &run_b,
            )
            .unwrap();
        let manifest: PersistedState =
            serde_json::from_slice(&fs::read(store.path()).unwrap()).unwrap();
        assert_eq!(manifest.history[0].source.source.owner, run_a);
        assert_eq!(manifest.history[1].source.source.owner, run_b);
        let digest_a = manifest.history[0].source.source.digest.clone();
        let digest_b = manifest.history[1].source.source.digest.clone();
        drop(store);

        revoke_content(&runs, "adopt-revoke-b", digest_b);
        let after_b = Store::resolve(PromptHistoryMode::Project, Some(home.clone()), &repo)
            .unwrap()
            .unwrap();
        assert_eq!(
            after_b.load(&run_b).unwrap().history,
            ["prompt from A"],
            "revoking B must not close A's independently lineaged entry"
        );
        drop(after_b);

        revoke_content(&runs, "adopt-revoke-a", digest_a);
        let after_a = Store::resolve(PromptHistoryMode::Project, Some(home), &repo)
            .unwrap()
            .unwrap();
        assert!(after_a.load(&run_b).unwrap().history.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_history_file_is_refused() {
        use std::os::unix::fs::symlink;
        let home = scratch("symlink-home");
        let repo = scratch("symlink-repo");
        let store = Store::resolve(PromptHistoryMode::Project, Some(home), &repo)
            .unwrap()
            .unwrap();
        fs::create_dir_all(store.path().parent().unwrap()).unwrap();
        let target = scratch("symlink-target").join("target.json");
        fs::write(&target, b"{}\n").unwrap();
        symlink(target, store.path()).unwrap();
        assert!(
            store
                .load(&source_run("symlink"))
                .unwrap_err()
                .to_string()
                .contains("non-symlink")
        );
    }
}
