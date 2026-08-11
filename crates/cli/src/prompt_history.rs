//! Bounded, repository-scoped prompt history for the interactive frontend.
//!
//! Prompt text is operator data. The history manifest lives below the operator-owned Core home and
//! contains handles only; scrubbed bytes are encrypted in the active run store so content
//! revocation has one graph. Attachments are never serialized, and `Disabled` creates no store.

use crate::config::PromptHistoryMode;
use iteron_protocol::{RunId, TenantId};
use iteron_record::{
    ContentReferenceSurface, PrivateContentClass, PrivateContentDerivativeStore,
    PrivateContentHandle, PrivateContentRetention,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const MAX_ENTRIES: usize = 200;
const MAX_ENTRY_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 1024 * 1024;
const LEGACY_STATE_VERSION: u32 = 1;
const STATE_VERSION: u32 = 2;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    schema_version: u32,
    history: Vec<PrivateContentHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    draft: Option<PrivateContentHandle>,
}

#[derive(Deserialize)]
struct VersionProbe {
    schema_version: u32,
}

#[derive(Clone)]
pub(crate) struct Store {
    path: PathBuf,
    private: PrivateContentDerivativeStore,
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
        let private = PrivateContentDerivativeStore::open(
            runs_dir,
            tenant,
            owner,
            ContentReferenceSurface::PromptHistory,
            PrivateContentClass::Transcript,
            PrivateContentRetention::ExplicitRevocation,
            MAX_ENTRY_BYTES,
        )?;
        Ok(Some(Self { path, private }))
    }

    pub(crate) fn load(&self) -> anyhow::Result<State> {
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
            STATE_VERSION => self.hydrate(serde_json::from_slice(&bytes)?),
            LEGACY_STATE_VERSION => {
                let state = bound_and_scrub(serde_json::from_slice(&bytes)?);
                // Migrate before exposing legacy plaintext. A failed CAS write leaves this
                // history unavailable instead of serving an unrevocable derivative.
                self.save(state.clone())?;
                Ok(state)
            }
            version => anyhow::bail!("unsupported prompt history schema version {version}"),
        }
    }

    fn save(&self, state: State) -> anyhow::Result<()> {
        let state = bound_and_scrub(state);
        let history = state
            .history
            .iter()
            .enumerate()
            .map(|(index, entry)| self.store_text(index, entry))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let draft = state
            .draft
            .as_deref()
            .map(|draft| self.store_text(MAX_ENTRIES, draft))
            .transpose()?;
        let persisted = PersistedState {
            schema_version: STATE_VERSION,
            history,
            draft,
        };
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
        self.reconcile(&persisted)?;
        Ok(())
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }
}

/// One fixed-depth background writer. Keystrokes never wait for an fsync; when its single pending
/// slot is full, the newer snapshot is skipped and the normal-exit flush still writes final state.
pub(crate) struct Writer {
    sender: Option<std::sync::mpsc::SyncSender<State>>,
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
        let (sender, receiver) = std::sync::mpsc::sync_channel::<State>(1);
        let task = std::thread::spawn(move || {
            while let Ok(state) = receiver.recv() {
                let _ = store.save(state);
            }
        });
        Self {
            sender: Some(sender),
            task: Some(task),
        }
    }

    pub(crate) fn schedule(&self, state: State) {
        if let Some(sender) = &self.sender {
            let _ = sender.try_send(state);
        }
    }

    pub(crate) fn finish(mut self, state: State) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(state);
            drop(sender);
        }
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn bound_and_scrub(state: State) -> State {
    let mut retained = Vec::new();
    let mut total = 0_usize;
    for entry in state.history.into_iter().rev() {
        let entry = sanitize(&iteron_record::redact::scrub(&entry));
        if entry.trim().is_empty() || entry.len() > MAX_ENTRY_BYTES {
            continue;
        }
        let Some(next) = total.checked_add(entry.len()) else {
            break;
        };
        if retained.len() == MAX_ENTRIES || next > MAX_STATE_BYTES / 2 {
            break;
        }
        total = next;
        retained.push(entry);
    }
    retained.reverse();
    let draft = state
        .draft
        .map(|draft| sanitize(&iteron_record::redact::scrub(&draft)))
        .filter(|draft| !draft.is_empty() && draft.len() <= MAX_ENTRY_BYTES);
    State::new(retained, draft)
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

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "core-prompt-history-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
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
            .save(State::new(
                vec!["hello\u{200b} world".into(), credential_shape.clone()],
                Some("draft\x1b text".into()),
            ))
            .unwrap();
        let loaded = store.load().unwrap();
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
        writer.schedule(State::new(vec!["first".into()], Some("stale".into())));
        writer.finish(State::new(
            vec!["first".into(), "second".into()],
            Some("final 多行\ndraft".into()),
        ));

        let loaded = store.load().unwrap();
        assert_eq!(loaded.history, vec!["first", "second"]);
        assert_eq!(loaded.draft.as_deref(), Some("final 多行\ndraft"));
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
                .load()
                .unwrap_err()
                .to_string()
                .contains("non-symlink")
        );
    }
}
