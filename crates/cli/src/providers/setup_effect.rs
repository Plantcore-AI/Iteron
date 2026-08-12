//! Durable, content-free write-ahead evidence for provider inference performed by `iteron setup`.
//!
//! Setup runs before a rollout exists, so pretending its authentication probe belongs to a run
//! would corrupt both identities. This journal owns a separate setup-operation namespace. It
//! records no credential, prompt, response, model text, or provider error body: only a bounded
//! provider slug, a one-way model-route digest, physical-attempt intent, retry policy, and a typed
//! terminal.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const SCHEMA: u8 = 1;
const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MODEL_ID_BYTES: usize = 512;
const MAX_RECORD_BYTES: usize = 2 * 1024;
const LOCK_ATTEMPTS: usize = 200;
const LOCK_WAIT: Duration = Duration::from_millis(10);
const POLICY_ID: &str = "provider-setup-single-v1";
const POLICY_CANONICAL: &[u8] = b"provider-setup-single-v1\0single_attempt\0max_attempts=1\0total_deadline_milliseconds=60000\0attempt_semantics=single";
const MAX_ATTEMPTS: u8 = 1;
const TOTAL_DEADLINE_MILLISECONDS: u64 = 60_000;
const OPERATION_PREFIX: &str = "provider-setup-v1:";
const OPERATION_ORDINAL_WIDTH: usize = 20;
#[cfg(test)]
static NEXT_TEST_ROOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetupRetrySchedule {
    SingleAttempt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Intent {
        schema: u8,
        operation_id: String,
        attempt_id: String,
        provider_id: String,
        model_id_sha256: String,
        policy_id: String,
        policy_digest_sha256: String,
        retry_schedule: SetupRetrySchedule,
        max_attempts: u8,
        total_deadline_milliseconds: u64,
    },
    Terminal {
        schema: u8,
        operation_id: String,
        attempt_id: String,
        outcome: SetupAttemptOutcome,
        reason: SetupAttemptReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SetupAttemptOutcome {
    Succeeded,
    FailedDefinite,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SetupAttemptReason {
    Accepted,
    ProviderFailedDefinite,
    ProviderOutcomeUnobservable,
    SetupDeadline,
    ProcessRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SetupAttempt {
    operation_id: String,
    attempt_id: String,
}

/// Exclusive append owner. Holding the kernel's advisory lock on the journal across the physical
/// request makes intent and terminal order total across cooperating setup processes. A suspended
/// live owner therefore cannot be mistaken for a stale sidecar file.
pub(super) struct SetupEffectJournal {
    file: File,
    path: PathBuf,
    max_log_bytes: u64,
    next_operation_ordinal: u64,
    pending_attempt: Option<SetupAttempt>,
}

impl SetupEffectJournal {
    pub(super) fn open() -> Result<Self, String> {
        let base = crate::config::config_home().ok_or_else(|| {
            "no config root for the durable provider setup-operation journal".to_owned()
        })?;
        let directory = iteron_protocol::home::path(&base, "operations");
        Self::open_path(&directory.join("provider-setup-effects-v1.jsonl"))
    }

    fn open_path(path: &Path) -> Result<Self, String> {
        Self::open_path_with_limit(path, MAX_LOG_BYTES)
    }

    fn open_path_with_limit(path: &Path, max_log_bytes: u64) -> Result<Self, String> {
        if max_log_bytes == 0 || max_log_bytes > MAX_LOG_BYTES {
            return Err(
                "provider setup journal byte ceiling is outside its supported bound".into(),
            );
        }
        let parent = path
            .parent()
            .ok_or_else(|| "provider setup journal path has no parent".to_owned())?;
        prepare_private_directory(parent)?;
        (|| {
            let existed = match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err("provider setup journal must not be a symbolic link".to_owned());
                }
                Ok(metadata) if !metadata.file_type().is_file() => {
                    return Err("provider setup journal must be a regular file".to_owned());
                }
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => {
                    return Err(format!("provider setup journal unavailable: {error}"));
                }
            };
            let mut options = OpenOptions::new();
            options.read(true).append(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
                options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            }
            let file = options
                .open(path)
                .map_err(|error| format!("provider setup journal unavailable: {error}"))?;
            let metadata = file
                .metadata()
                .map_err(|error| format!("provider setup journal unavailable: {error}"))?;
            if !metadata.is_file() {
                return Err("provider setup journal must be a regular file".to_owned());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(
                        "provider setup journal permissions expose operator-private metadata"
                            .to_owned(),
                    );
                }
            }
            acquire_lock(&file)?;
            if !existed {
                file.sync_all()
                    .map_err(|error| format!("provider setup journal unavailable: {error}"))?;
                sync_directory(parent)?;
            }
            let mut journal = Self {
                file,
                path: path.to_owned(),
                max_log_bytes,
                next_operation_ordinal: 1,
                pending_attempt: None,
            };
            journal.next_operation_ordinal = journal.reconcile_pending()?;
            Ok(journal)
        })()
    }

    pub(super) fn begin(
        &mut self,
        provider_id: &str,
        model_id: &str,
    ) -> Result<SetupAttempt, String> {
        if self.pending_attempt.is_some() {
            return Err(
                "provider setup journal already owns an unterminated physical attempt".into(),
            );
        }
        crate::config::validate_provider_id_slug(provider_id)?;
        validate_model_id(model_id)?;
        let ordinal = self.next_operation_ordinal;
        let next_ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| "provider setup operation ordinal is exhausted".to_owned())?;
        let operation_id = operation_id(ordinal)?;
        let attempt = SetupAttempt {
            attempt_id: format!("{operation_id}:attempt:1"),
            operation_id,
        };
        let intent = Record::Intent {
            schema: SCHEMA,
            operation_id: attempt.operation_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            provider_id: provider_id.to_owned(),
            model_id_sha256: identity_sha256(model_id),
            policy_id: POLICY_ID.into(),
            policy_digest_sha256: policy_digest_sha256(),
            retry_schedule: SetupRetrySchedule::SingleAttempt,
            max_attempts: MAX_ATTEMPTS,
            total_deadline_milliseconds: TOTAL_DEADLINE_MILLISECONDS,
        };
        let intent_bytes = encode_record(&intent)?;
        let terminal_reservation = maximum_terminal_bytes(&attempt)?;
        self.ensure_capacity(intent_bytes.len().saturating_add(terminal_reservation))?;
        self.append_encoded(&intent_bytes)?;
        self.next_operation_ordinal = next_ordinal;
        self.pending_attempt = Some(attempt.clone());
        Ok(attempt)
    }

    pub(super) fn terminal(
        &mut self,
        attempt: &SetupAttempt,
        outcome: SetupAttemptOutcome,
        reason: SetupAttemptReason,
    ) -> Result<(), String> {
        if !valid_terminal_pair(outcome, reason) {
            return Err("provider setup terminal outcome/reason pair is inconsistent".into());
        }
        if self.pending_attempt.as_ref() != Some(attempt) {
            return Err("provider setup terminal does not match the pending attempt".into());
        }
        self.append(&Record::Terminal {
            schema: SCHEMA,
            operation_id: attempt.operation_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            outcome,
            reason,
        })?;
        self.pending_attempt = None;
        Ok(())
    }

    fn reconcile_pending(&mut self) -> Result<u64, String> {
        let length = self
            .file
            .metadata()
            .map_err(|error| format!("provider setup journal unavailable: {error}"))?
            .len();
        if length > self.max_log_bytes {
            return Err("provider setup journal reached its hard byte ceiling".into());
        }
        let mut bytes = Vec::with_capacity(length as usize);
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.read_to_end(&mut bytes))
            .map_err(|error| format!("provider setup journal unreadable: {error}"))?;
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(
                "provider setup journal has a torn tail; refusing provider dispatch".into(),
            );
        }
        let mut intents = BTreeMap::new();
        let mut terminals = BTreeSet::new();
        let mut maximum_ordinal = 0_u64;
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            if line.len() > MAX_RECORD_BYTES {
                return Err("provider setup journal record exceeds its byte ceiling".into());
            }
            let record: Record = serde_json::from_slice(line)
                .map_err(|_| "provider setup journal contains an invalid record".to_owned())?;
            match record {
                Record::Intent {
                    schema,
                    operation_id,
                    attempt_id,
                    provider_id,
                    model_id_sha256,
                    policy_id,
                    policy_digest_sha256: recorded_policy_digest,
                    retry_schedule,
                    max_attempts,
                    total_deadline_milliseconds,
                } => {
                    let Some(ordinal) = parse_operation_id(&operation_id) else {
                        return Err("provider setup journal intent is inconsistent".into());
                    };
                    if schema != SCHEMA
                        || attempt_id != format!("{operation_id}:attempt:1")
                        || policy_id != POLICY_ID
                        || recorded_policy_digest != policy_digest_sha256()
                        || retry_schedule != SetupRetrySchedule::SingleAttempt
                        || max_attempts != MAX_ATTEMPTS
                        || total_deadline_milliseconds != TOTAL_DEADLINE_MILLISECONDS
                        || crate::config::validate_provider_id_slug(&provider_id).is_err()
                        || !valid_sha256(&model_id_sha256)
                        || intents.insert(attempt_id, operation_id).is_some()
                    {
                        return Err("provider setup journal intent is inconsistent".into());
                    }
                    maximum_ordinal = maximum_ordinal.max(ordinal);
                }
                Record::Terminal {
                    schema,
                    operation_id,
                    attempt_id,
                    outcome,
                    reason,
                } => {
                    if schema != SCHEMA
                        || terminals.contains(&attempt_id)
                        || intents.get(&attempt_id) != Some(&operation_id)
                        || !valid_terminal_pair(outcome, reason)
                    {
                        return Err("provider setup journal terminal is inconsistent".into());
                    }
                    terminals.insert(attempt_id);
                }
            }
        }
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|error| format!("provider setup journal unavailable: {error}"))?;
        let pending = intents
            .into_iter()
            .filter(|(attempt_id, _)| !terminals.contains(attempt_id))
            .collect::<Vec<_>>();
        if pending.len() > 1 {
            return Err(
                "provider setup journal contains multiple pending physical attempts".into(),
            );
        }
        for (attempt_id, operation_id) in pending {
            self.append(&Record::Terminal {
                schema: SCHEMA,
                operation_id,
                attempt_id,
                outcome: SetupAttemptOutcome::Unknown,
                reason: SetupAttemptReason::ProcessRecovery,
            })?;
        }
        maximum_ordinal
            .checked_add(1)
            .ok_or_else(|| "provider setup operation ordinal is exhausted".to_owned())
    }

    fn append(&mut self, record: &Record) -> Result<(), String> {
        let bytes = encode_record(record)?;
        self.ensure_capacity(bytes.len())?;
        self.append_encoded(&bytes)
    }

    fn ensure_capacity(&self, additional_bytes: usize) -> Result<(), String> {
        let current = self
            .file
            .metadata()
            .map_err(|error| format!("provider setup journal unavailable: {error}"))?
            .len();
        if current.saturating_add(additional_bytes as u64) > self.max_log_bytes {
            return Err("provider setup journal reached its hard byte ceiling".into());
        }
        Ok(())
    }

    fn append_encoded(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.file
            .write_all(bytes)
            .and_then(|_| self.file.sync_all())
            .map_err(|error| format!("provider setup journal durability failed: {error}"))
    }
}

pub(super) const fn physical_deadline() -> Duration {
    Duration::from_millis(TOTAL_DEADLINE_MILLISECONDS)
}

impl Drop for SetupEffectJournal {
    fn drop(&mut self) {
        let _ = self.file.sync_all();
        if let Some(parent) = self.path.parent() {
            let _ = sync_directory(parent);
        }
    }
}

fn validate_model_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_MODEL_ID_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err("provider setup model identity is outside its byte/character bound".into());
    }
    Ok(())
}

fn identity_sha256(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
    hex::encode(digest.finalize())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encode_record(record: &Record) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(record)
        .map_err(|_| "provider setup journal record could not be encoded".to_owned())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RECORD_BYTES {
        return Err("provider setup journal record exceeds its byte ceiling".into());
    }
    Ok(bytes)
}

fn maximum_terminal_bytes(attempt: &SetupAttempt) -> Result<usize, String> {
    [
        (SetupAttemptOutcome::Succeeded, SetupAttemptReason::Accepted),
        (
            SetupAttemptOutcome::FailedDefinite,
            SetupAttemptReason::ProviderFailedDefinite,
        ),
        (
            SetupAttemptOutcome::Unknown,
            SetupAttemptReason::ProviderOutcomeUnobservable,
        ),
        (
            SetupAttemptOutcome::Unknown,
            SetupAttemptReason::SetupDeadline,
        ),
        (
            SetupAttemptOutcome::Unknown,
            SetupAttemptReason::ProcessRecovery,
        ),
    ]
    .into_iter()
    .map(|(outcome, reason)| {
        encode_record(&Record::Terminal {
            schema: SCHEMA,
            operation_id: attempt.operation_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            outcome,
            reason,
        })
        .map(|bytes| bytes.len())
    })
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .max()
    .ok_or_else(|| "provider setup terminal reservation is empty".to_owned())
}

fn operation_id(ordinal: u64) -> Result<String, String> {
    if ordinal == 0 {
        return Err("provider setup operation ordinal must be nonzero".into());
    }
    Ok(format!("{OPERATION_PREFIX}{ordinal:020}"))
}

fn parse_operation_id(value: &str) -> Option<u64> {
    let ordinal = value.strip_prefix(OPERATION_PREFIX)?;
    if ordinal.len() != OPERATION_ORDINAL_WIDTH
        || !ordinal.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let ordinal = ordinal.parse().ok()?;
    (ordinal != 0).then_some(ordinal)
}

fn policy_digest_sha256() -> String {
    hex::encode(Sha256::digest(POLICY_CANONICAL))
}

const fn valid_terminal_pair(outcome: SetupAttemptOutcome, reason: SetupAttemptReason) -> bool {
    matches!(
        (outcome, reason),
        (SetupAttemptOutcome::Succeeded, SetupAttemptReason::Accepted)
            | (
                SetupAttemptOutcome::FailedDefinite,
                SetupAttemptReason::ProviderFailedDefinite
            )
            | (
                SetupAttemptOutcome::Unknown,
                SetupAttemptReason::ProviderOutcomeUnobservable
                    | SetupAttemptReason::SetupDeadline
                    | SetupAttemptReason::ProcessRecovery
            )
    )
}

fn acquire_lock(file: &File) -> Result<(), String> {
    for _ in 0..LOCK_ATTEMPTS {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => std::thread::sleep(LOCK_WAIT),
            Err(TryLockError::Error(error)) => {
                return Err(format!("provider setup journal lock unavailable: {error}"));
            }
        }
    }
    Err("another provider setup operation owns the durable effect journal".into())
}

fn prepare_private_directory(path: &Path) -> Result<(), String> {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && !metadata.file_type().is_dir()
    {
        return Err("provider setup journal directory is not a real directory".into());
    }
    std::fs::create_dir_all(path)
        .map_err(|error| format!("provider setup journal directory unavailable: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("provider setup journal directory unavailable: {error}"))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("provider setup journal directory sync failed: {error}"))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "core-provider-setup-effect-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_ROOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    #[test]
    fn pending_intent_is_reconciled_unknown_before_a_new_dispatch_can_begin() {
        let root = root("recovery");
        let path = root.join("effects.jsonl");
        let first = {
            let mut journal = SetupEffectJournal::open_path(&path).unwrap();
            journal.begin("provider", "model").unwrap()
        };
        {
            let mut reopened = SetupEffectJournal::open_path(&path).unwrap();
            let second = reopened.begin("provider", "model").unwrap();
            reopened
                .terminal(
                    &second,
                    SetupAttemptOutcome::Succeeded,
                    SetupAttemptReason::Accepted,
                )
                .unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&first.attempt_id));
        assert!(text.contains("\"outcome\":\"unknown\""));
        assert!(text.contains("\"reason\":\"process_recovery\""));
        assert!(!text.contains("ping"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn terminal_is_fsynced_and_route_identity_is_bounded_without_content_fields() {
        let root = root("terminal");
        let path = root.join("effects.jsonl");
        let secret_model = "secret-model/../../prompt-SENTINEL-7d6da78a";
        let expected_model_digest = identity_sha256(secret_model);
        {
            let mut journal = SetupEffectJournal::open_path(&path).unwrap();
            assert!(
                journal
                    .begin("p", &"m".repeat(MAX_MODEL_ID_BYTES + 1))
                    .is_err()
            );
            assert!(journal.begin("../provider", "m").is_err());
            let attempt = journal.begin("p", secret_model).unwrap();
            journal
                .terminal(
                    &attempt,
                    SetupAttemptOutcome::FailedDefinite,
                    SetupAttemptReason::ProviderFailedDefinite,
                )
                .unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        for forbidden in ["credential", "prompt", "response", "body", "ping"] {
            assert!(
                !text.contains(forbidden),
                "journal leaked field `{forbidden}`"
            );
        }
        assert!(text.contains("\"retry_schedule\":\"single_attempt\""));
        assert!(text.contains("\"max_attempts\":1"));
        assert!(text.contains(&policy_digest_sha256()));
        assert!(!text.contains(secret_model));
        assert!(text.contains(&expected_model_digest));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capacity_is_reserved_for_the_largest_terminal_before_intent_or_dispatch() {
        let root = root("capacity-reservation");
        let path = root.join("effects.jsonl");
        let operation_id = operation_id(1).unwrap();
        let attempt = SetupAttempt {
            attempt_id: format!("{operation_id}:attempt:1"),
            operation_id,
        };
        let intent = Record::Intent {
            schema: SCHEMA,
            operation_id: attempt.operation_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            provider_id: "p".into(),
            model_id_sha256: identity_sha256("m"),
            policy_id: POLICY_ID.into(),
            policy_digest_sha256: policy_digest_sha256(),
            retry_schedule: SetupRetrySchedule::SingleAttempt,
            max_attempts: MAX_ATTEMPTS,
            total_deadline_milliseconds: TOTAL_DEADLINE_MILLISECONDS,
        };
        let required =
            encode_record(&intent).unwrap().len() + maximum_terminal_bytes(&attempt).unwrap();
        let mut journal =
            SetupEffectJournal::open_path_with_limit(&path, u64::try_from(required - 1).unwrap())
                .unwrap();

        let error = journal.begin("p", "m").unwrap_err();
        assert!(error.contains("hard byte ceiling"), "{error}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_without_terminal_capacity_fails_closed_and_cannot_add_an_intent() {
        let root = root("recovery-capacity");
        let path = root.join("effects.jsonl");
        {
            let mut journal = SetupEffectJournal::open_path(&path).unwrap();
            journal.begin("p", "m").unwrap();
        }
        let intent_only_len = std::fs::metadata(&path).unwrap().len();
        let error = SetupEffectJournal::open_path_with_limit(&path, intent_only_len)
            .err()
            .expect("recovery must fail closed if its terminal cannot be made durable");
        assert!(error.contains("hard byte ceiling"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operation_identity_is_monotone_across_reopen_and_symlinks_fail_closed() {
        let root = root("identity");
        let path = root.join("effects.jsonl");
        let first = {
            let mut journal = SetupEffectJournal::open_path(&path).unwrap();
            let attempt = journal.begin("p", "m").unwrap();
            journal
                .terminal(
                    &attempt,
                    SetupAttemptOutcome::Succeeded,
                    SetupAttemptReason::Accepted,
                )
                .unwrap();
            attempt
        };
        let second = {
            let mut journal = SetupEffectJournal::open_path(&path).unwrap();
            journal.begin("p", "m").unwrap()
        };
        assert_eq!(parse_operation_id(&first.operation_id), Some(1));
        assert_eq!(parse_operation_id(&second.operation_id), Some(2));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked = root.join("linked.jsonl");
            symlink(&path, &linked).unwrap();
            assert!(SetupEffectJournal::open_path(&linked).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_owner_is_refused_before_it_can_append_an_intent() {
        let root = root("concurrent-owner");
        let path = root.join("effects.jsonl");
        let first = SetupEffectJournal::open_path(&path).unwrap();
        let before = std::fs::metadata(&path).unwrap().len();

        let error = SetupEffectJournal::open_path(&path)
            .err()
            .expect("a second live setup owner must fail closed");
        assert!(error.contains("owns the durable effect journal"), "{error}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before);

        drop(first);
        let reopened = SetupEffectJournal::open_path(&path)
            .expect("the kernel releases the advisory lock when the owner closes");
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }
}
