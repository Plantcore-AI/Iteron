//! Durable, idempotent orchestration for record-erasure operations.
//!
//! Receipts live beside (not inside) rollout journals so deleting the target cannot delete the
//! minimum audit proof. One stable lock inode serializes each operation id across processes, and
//! every state transition is an atomic file replacement with a directory durability barrier.

use crate::session::{self, DeleteSessionError, PrunePolicy};
use iteron_protocol::{
    ErasureAuthorityId, ErasureFailureCode, ErasureOperationId, ErasureReceipt, ErasureRequest,
    ErasureScopeId, ErasureState, ErasureTarget, ErasureTargetId, ErasureValidationError,
    ErasureVerification, MAX_ERASURE_RECEIPT_BYTES, RunId, TenantId,
};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const ERASURE_DIR: &str = ".erasure";
const RECEIPTS_DIR: &str = "receipts";
const LOCKS_DIR: &str = "locks";
pub const MAX_ERASURE_RECEIPTS: usize = 4_096;

#[derive(Debug, thiserror::Error)]
pub enum ErasureError {
    #[error(transparent)]
    InvalidRequest(#[from] ErasureValidationError),
    #[error("erasure operation {operation_id} is active in another process")]
    OperationBusy { operation_id: ErasureOperationId },
    #[error("erasure operation {operation_id} already names a different immutable request")]
    ReceiptConflict { operation_id: ErasureOperationId },
    #[error("record erasure authority is not valid for this local record store")]
    AuthorityMismatch,
    #[error("record erasure is waiting for {count} active writer(s); retry the same operation id")]
    ActiveWriters { count: u32 },
    #[error("erasure receipt {operation_id} is corrupt or uses an unsupported schema")]
    ReceiptCorrupt { operation_id: ErasureOperationId },
    #[error("erasure receipt {operation_id} exceeds the {max_bytes}-byte bound")]
    ReceiptTooLarge {
        operation_id: ErasureOperationId,
        max_bytes: usize,
    },
    #[error("erasure receipt inventory exceeds the {max}-entry bound")]
    ReceiptInventoryBound { max: usize },
    /// Retryable: the last receipt state is already durable, so the same request resumes rather
    /// than converting an ambiguous partial storage effect into terminal proof.
    #[error("record erasure operation is incomplete: {0}")]
    Record(#[from] crate::RecordError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Content(#[from] crate::ContentStoreError),
}

/// Unforgeable-in-protocol local authority for one canonical record store.
///
/// The destructive entry point derives this value itself. On Unix the store must be owned by the
/// effective uid; merely supplying an `authority_id` string is not an authorization decision. The
/// canonical store identity prevents accidentally applying the proof to another repository. The
/// durable receipt keeps only the stable, content-free authority id.
#[derive(Debug, Clone)]
pub struct LocalErasureAuthority {
    runs_dir: PathBuf,
    id: ErasureAuthorityId,
}

impl LocalErasureAuthority {
    pub fn id(&self) -> &ErasureAuthorityId {
        &self.id
    }
}

/// Bind destructive record authority to the OS principal that owns this local store.
pub fn authorize_local_erasure(runs_dir: &Path) -> Result<LocalErasureAuthority, ErasureError> {
    crate::create_state_dir(runs_dir)?;
    let canonical = runs_dir.canonicalize()?;
    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_dir() {
        return Err(ErasureError::AuthorityMismatch);
    }
    #[cfg(unix)]
    let id = {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: `geteuid` takes no arguments and has no memory-safety preconditions.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            return Err(ErasureError::AuthorityMismatch);
        }
        ErasureAuthorityId::new(format!("local.uid.{effective_uid}"))?
    };
    #[cfg(not(unix))]
    let id = ErasureAuthorityId::new("local.operator")?;
    Ok(LocalErasureAuthority {
        runs_dir: canonical,
        id,
    })
}

/// Execute or resume one erasure request.
///
/// A repeated request with the same operation id, authority, and target returns the exact
/// persisted terminal receipt; a retry's transport timestamp is not identity. Reusing an operation
/// id for another authority or target fails before touching either target.
pub fn execute_erasure(
    runs_dir: &Path,
    mut request: ErasureRequest,
) -> Result<ErasureReceipt, ErasureError> {
    let authority = authorize_local_erasure(runs_dir)?;
    // The wire field is audit data, not authorization input. Replace it with the identity proven
    // from the local store and effective OS principal before request identity or idempotency is
    // evaluated, so a caller cannot mint its own destructive authority by choosing a string.
    request.authority_id = authority.id.clone();
    request.validate()?;
    ensure_layout(runs_dir)?;
    if runs_dir.canonicalize()? != authority.runs_dir {
        return Err(ErasureError::AuthorityMismatch);
    }
    let _operation_lock = lock_operation(runs_dir, &request.operation_id)?;

    let mut receipt = match read_erasure_receipt(runs_dir, &request.operation_id)? {
        Some(receipt) => {
            // Retry clocks are not identity. The first accepted request owns the durable time;
            // later deliveries may reconstruct a fresh envelope, but may not change authority or
            // target while reusing its idempotency key.
            if receipt.request().authority_id != request.authority_id
                || receipt.request().target != request.target
            {
                return Err(ErasureError::ReceiptConflict {
                    operation_id: request.operation_id,
                });
            }
            if receipt.state().is_terminal() {
                return Ok(receipt);
            }
            receipt
        }
        None => {
            let receipt = ErasureReceipt::requested(request, now_unix_ms())?;
            persist_receipt(runs_dir, &receipt)?;
            receipt
        }
    };

    let target = receipt.request().target.clone();
    match target {
        ErasureTarget::ExactSession { scope_id, run_id } => {
            execute_exact_session(runs_dir, &mut receipt, scope_id, run_id)
        }
        ErasureTarget::RetentionPrune {
            scope_id,
            max_age_secs,
            keep_last,
        } => execute_retention(runs_dir, &mut receipt, scope_id, max_age_secs, keep_last),
        ErasureTarget::ContentRevocation {
            scope_id,
            content_digest,
        } => execute_content_revocation(runs_dir, &mut receipt, scope_id, content_digest),
    }
}

/// Load one receipt without running or resuming its operation.
pub fn read_erasure_receipt(
    runs_dir: &Path,
    operation_id: &ErasureOperationId,
) -> Result<Option<ErasureReceipt>, ErasureError> {
    let path = receipt_path(runs_dir, operation_id);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take((MAX_ERASURE_RECEIPT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ERASURE_RECEIPT_BYTES {
        return Err(ErasureError::ReceiptTooLarge {
            operation_id: operation_id.clone(),
            max_bytes: MAX_ERASURE_RECEIPT_BYTES,
        });
    }
    let receipt = serde_json::from_slice::<ErasureReceipt>(&bytes).map_err(|_| {
        ErasureError::ReceiptCorrupt {
            operation_id: operation_id.clone(),
        }
    })?;
    receipt
        .validate()
        .map_err(|_| ErasureError::ReceiptCorrupt {
            operation_id: operation_id.clone(),
        })?;
    if receipt.request().operation_id != *operation_id {
        return Err(ErasureError::ReceiptCorrupt {
            operation_id: operation_id.clone(),
        });
    }
    Ok(Some(receipt))
}

/// Bounded receipt inventory, ordered by operation id for deterministic operator output.
pub fn list_erasure_receipts(
    runs_dir: &Path,
    limit: usize,
) -> Result<Vec<ErasureReceipt>, ErasureError> {
    let limit = limit.min(MAX_ERASURE_RECEIPTS);
    if limit == 0 {
        return Ok(Vec::new());
    }
    ensure_layout(runs_dir)?;
    let dir = runs_dir.join(ERASURE_DIR).join(RECEIPTS_DIR);
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(dir)?.take(MAX_ERASURE_RECEIPTS.saturating_add(1)) {
        if ids.len() == MAX_ERASURE_RECEIPTS {
            return Err(ErasureError::ReceiptInventoryBound {
                max: MAX_ERASURE_RECEIPTS,
            });
        }
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(stem) = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        if let Ok(id) = ErasureOperationId::new(stem) {
            ids.push(id);
        }
    }
    ids.sort();
    ids.truncate(limit);
    ids.into_iter()
        .map(|id| {
            read_erasure_receipt(runs_dir, &id)?
                .ok_or(ErasureError::ReceiptCorrupt { operation_id: id })
        })
        .collect()
}

fn execute_exact_session(
    runs_dir: &Path,
    receipt: &mut ErasureReceipt,
    scope_id: ErasureScopeId,
    target_id: ErasureTargetId,
) -> Result<ErasureReceipt, ErasureError> {
    let tenant = TenantId(scope_id.as_str().to_owned());
    let run = RunId(target_id.as_str().to_owned());
    let rollout_path = crate::validated_run_path(runs_dir, &run, ".jsonl").map_err(|_| {
        ErasureError::ReceiptCorrupt {
            operation_id: receipt.request().operation_id.clone(),
        }
    })?;

    if receipt.state() == ErasureState::Requested {
        match rollout_path.try_exists() {
            Ok(true) => advance(runs_dir, receipt, ErasureState::Quiescing)?,
            Ok(false) => {
                return fail(runs_dir, receipt, ErasureFailureCode::TargetNotFound);
            }
            Err(error) => return Err(error.into()),
        }
    }

    if receipt.state() == ErasureState::Quiescing {
        match session::delete(runs_dir, &tenant, &run) {
            Ok(()) => advance(runs_dir, receipt, ErasureState::Tombstoned)?,
            Err(DeleteSessionError::NotFound(_)) => match rollout_path.try_exists() {
                // A persisted Quiescing state plus an absent journal is the recovery case for a
                // crash after unlink and before the Tombstoned receipt replacement.
                Ok(false) => {
                    crate::content_store::ExactRunContentRelease::prepare(runs_dir, &tenant, &run)?
                        .commit()?;
                    session::complete_deleted_session_cleanup(runs_dir, &run)?;
                    advance(runs_dir, receipt, ErasureState::Tombstoned)?;
                }
                Ok(true) => {
                    return fail(runs_dir, receipt, ErasureFailureCode::TargetNotFound);
                }
                Err(error) => return Err(error.into()),
            },
            Err(DeleteSessionError::Active(_)) => {
                return fail(runs_dir, receipt, ErasureFailureCode::ActiveWriter);
            }
            Err(DeleteSessionError::HasDescendants { .. }) => {
                return fail(runs_dir, receipt, ErasureFailureCode::RetainedByDescendants);
            }
            Err(DeleteSessionError::HasDerivatives { .. }) => {
                return fail(runs_dir, receipt, ErasureFailureCode::RetainedByDerivatives);
            }
            Err(DeleteSessionError::Record(error)) => {
                if !rollout_path.try_exists()? {
                    crate::content_store::ExactRunContentRelease::prepare(runs_dir, &tenant, &run)?
                        .commit()?;
                    session::complete_deleted_session_cleanup(runs_dir, &run)?;
                    advance(runs_dir, receipt, ErasureState::Tombstoned)?;
                } else {
                    return Err(error.into());
                }
            }
        }
    }

    if receipt.state() != ErasureState::Tombstoned {
        return fail(runs_dir, receipt, ErasureFailureCode::VerificationFailure);
    }
    match rollout_path.try_exists() {
        Ok(false) => {
            session::complete_deleted_session_cleanup(runs_dir, &run)?;
            verify(runs_dir, receipt, ErasureVerification::ExactSessionAbsent)
        }
        Ok(true) => fail(runs_dir, receipt, ErasureFailureCode::VerificationFailure),
        Err(error) => Err(error.into()),
    }
}

fn execute_retention(
    runs_dir: &Path,
    receipt: &mut ErasureReceipt,
    scope_id: ErasureScopeId,
    max_age_secs: Option<u64>,
    keep_last: Option<u32>,
) -> Result<ErasureReceipt, ErasureError> {
    let tenant = TenantId(scope_id.as_str().to_owned());
    let policy = PrunePolicy {
        max_age_secs,
        keep_last: keep_last.map(|value| value as usize),
        dry_run: false,
    };
    // Selection is fixed to the record-owned acceptance clock, not a caller-controlled timestamp,
    // and therefore remains identical after a crash/restart.
    let evaluation_secs = receipt.accepted_at_unix_ms() / 1_000;

    if receipt.state() == ErasureState::Requested {
        advance(runs_dir, receipt, ErasureState::Quiescing)?;
    }
    if receipt.state() == ErasureState::Quiescing {
        // Preflight before the first unlink so a writer already known to be active cannot turn a
        // retention operation into a terminal partial delete. A writer may still race this pass;
        // the destructive pass below therefore keeps Quiescing retryable as well.
        let preflight = session::prune_at(
            runs_dir,
            &tenant,
            &PrunePolicy {
                dry_run: true,
                ..policy.clone()
            },
            evaluation_secs,
        )?;
        if !preflight.active.is_empty() {
            // An active writer found before anything was destroyed is an ordinary refusal, not a
            // transport failure: record it the way the exact-session path and the derivative case
            // beside it already do, so the operator gets one durable, idempotent receipt instead
            // of an error that leaves no trace of the attempt. The post-destructive check below
            // stays an error, because that one is a race, not a decision.
            return fail(runs_dir, receipt, ErasureFailureCode::ActiveWriter);
        }
        if !preflight.derivatives.is_empty() {
            return fail(runs_dir, receipt, ErasureFailureCode::RetainedByDerivatives);
        }
        let report = session::prune_at(runs_dir, &tenant, &policy, evaluation_secs)?;
        if !report.active.is_empty() {
            return Err(ErasureError::ActiveWriters {
                count: u32::try_from(report.active.len()).unwrap_or(u32::MAX),
            });
        }
        if !report.derivatives.is_empty() {
            return Err(ErasureError::Record(crate::RecordError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "retention deletion raced a newly retained private derivative",
                ),
            )));
        }
        advance(runs_dir, receipt, ErasureState::Tombstoned)?;
    }
    if receipt.state() != ErasureState::Tombstoned {
        return fail(runs_dir, receipt, ErasureFailureCode::VerificationFailure);
    }

    let verification_policy = PrunePolicy {
        dry_run: true,
        ..policy
    };
    let report = match session::prune_at(runs_dir, &tenant, &verification_policy, evaluation_secs) {
        Ok(report) => report,
        Err(error) => return Err(error.into()),
    };
    if !report.removed.is_empty() {
        return fail(runs_dir, receipt, ErasureFailureCode::VerificationFailure);
    }
    if !report.active.is_empty() {
        return fail(runs_dir, receipt, ErasureFailureCode::ActiveWriter);
    }
    if !report.derivatives.is_empty() {
        return fail(runs_dir, receipt, ErasureFailureCode::RetainedByDerivatives);
    }
    let Some((retained_sessions, active_sessions, ancestor_sessions)) = bounded_report(&report)
    else {
        return fail(runs_dir, receipt, ErasureFailureCode::ReceiptBoundExceeded);
    };
    verify(
        runs_dir,
        receipt,
        ErasureVerification::RetentionApplied {
            retained_sessions,
            active_sessions,
            ancestor_sessions,
        },
    )
}

fn execute_content_revocation(
    runs_dir: &Path,
    receipt: &mut ErasureReceipt,
    scope_id: ErasureScopeId,
    content_digest: iteron_protocol::ErasureContentDigest,
) -> Result<ErasureReceipt, ErasureError> {
    let tenant = TenantId(scope_id.as_str().to_owned());
    let guard = match crate::content_store::ContentRevocationGuard::begin(
        runs_dir,
        &tenant,
        content_digest,
    ) {
        Ok(Some(guard)) => guard,
        Ok(None) => return fail(runs_dir, receipt, ErasureFailureCode::TargetNotFound),
        Err(crate::ContentStoreError::ActiveWriter { .. }) => {
            return fail(runs_dir, receipt, ErasureFailureCode::ActiveWriter);
        }
        Err(
            crate::ContentStoreError::ReferenceBound { .. }
            | crate::ContentStoreError::RevocationBound { .. },
        ) => {
            return fail(
                runs_dir,
                receipt,
                ErasureFailureCode::ReferenceGraphBoundExceeded,
            );
        }
        Err(error) => return Err(error.into()),
    };

    if receipt.state() == ErasureState::Requested {
        advance(runs_dir, receipt, ErasureState::Quiescing)?;
    }
    if receipt.state() == ErasureState::Quiescing {
        let operation_id = receipt.request().operation_id.clone();
        let authority_id = receipt.request().authority_id.clone();
        match guard.tombstone(&operation_id, &authority_id, now_unix_ms()) {
            Ok(_) => {}
            Err(
                crate::ContentStoreError::ReferenceBound { .. }
                | crate::ContentStoreError::RevocationBound { .. },
            ) => {
                return fail(
                    runs_dir,
                    receipt,
                    ErasureFailureCode::ReferenceGraphBoundExceeded,
                );
            }
            Err(error) => return Err(error.into()),
        }
        advance(runs_dir, receipt, ErasureState::Tombstoned)?;
    }
    if receipt.state() == ErasureState::Tombstoned {
        guard.shred()?;
        advance(runs_dir, receipt, ErasureState::Shredded)?;
    }
    if receipt.state() == ErasureState::Shredded {
        advance(runs_dir, receipt, ErasureState::Propagating)?;
    }
    if receipt.state() != ErasureState::Propagating {
        return fail(runs_dir, receipt, ErasureFailureCode::VerificationFailure);
    }
    guard.propagate()?;
    let summary = match guard.verify() {
        Ok(summary) => summary,
        Err(
            crate::ContentStoreError::ReferenceBound { .. }
            | crate::ContentStoreError::RevocationBound { .. },
        ) => {
            return fail(
                runs_dir,
                receipt,
                ErasureFailureCode::ReferenceGraphBoundExceeded,
            );
        }
        Err(error) => return Err(error.into()),
    };
    verify(
        runs_dir,
        receipt,
        ErasureVerification::ContentRevoked {
            reference_count: summary.references,
            affected_sessions: summary.affected_sessions,
            revocation_generation: summary.generation,
            coverage: summary.coverage,
        },
    )
}

fn bounded_report(report: &session::PruneReport) -> Option<(u32, u32, u32)> {
    Some((
        u32::try_from(report.retained).ok()?,
        u32::try_from(report.active.len()).ok()?,
        u32::try_from(report.ancestors.len()).ok()?,
    ))
}

fn advance(
    runs_dir: &Path,
    receipt: &mut ErasureReceipt,
    state: ErasureState,
) -> Result<(), ErasureError> {
    receipt.advance(state, now_unix_ms())?;
    persist_receipt(runs_dir, receipt)
}

fn verify(
    runs_dir: &Path,
    receipt: &mut ErasureReceipt,
    verification: ErasureVerification,
) -> Result<ErasureReceipt, ErasureError> {
    receipt.mark_verified(verification, now_unix_ms())?;
    persist_receipt(runs_dir, receipt)?;
    Ok(receipt.clone())
}

fn fail(
    runs_dir: &Path,
    receipt: &mut ErasureReceipt,
    failure: ErasureFailureCode,
) -> Result<ErasureReceipt, ErasureError> {
    receipt.mark_failed(failure, now_unix_ms())?;
    persist_receipt(runs_dir, receipt)?;
    Ok(receipt.clone())
}

fn persist_receipt(runs_dir: &Path, receipt: &ErasureReceipt) -> Result<(), ErasureError> {
    receipt.validate()?;
    let bytes = serde_json::to_vec_pretty(receipt).map_err(|_| ErasureError::ReceiptCorrupt {
        operation_id: receipt.request().operation_id.clone(),
    })?;
    if bytes.len() > MAX_ERASURE_RECEIPT_BYTES {
        return Err(ErasureError::ReceiptTooLarge {
            operation_id: receipt.request().operation_id.clone(),
            max_bytes: MAX_ERASURE_RECEIPT_BYTES,
        });
    }
    crate::cache_io::atomic_replace(
        &receipt_path(runs_dir, &receipt.request().operation_id),
        &bytes,
    )?;
    Ok(())
}

fn ensure_layout(runs_dir: &Path) -> Result<(), ErasureError> {
    crate::create_state_dir(runs_dir)?;
    let root = runs_dir.join(ERASURE_DIR);
    let receipts = root.join(RECEIPTS_DIR);
    let locks = root.join(LOCKS_DIR);
    std::fs::create_dir_all(&receipts)?;
    std::fs::create_dir_all(&locks)?;
    crate::cache_io::sync_dir(&receipts)?;
    crate::cache_io::sync_dir(&locks)?;
    crate::cache_io::sync_dir(&root)?;
    crate::cache_io::sync_dir(runs_dir)?;
    Ok(())
}

fn receipt_path(runs_dir: &Path, operation_id: &ErasureOperationId) -> PathBuf {
    runs_dir
        .join(ERASURE_DIR)
        .join(RECEIPTS_DIR)
        .join(format!("{}.json", operation_id.as_str()))
}

fn lock_operation(
    runs_dir: &Path,
    operation_id: &ErasureOperationId,
) -> Result<OperationLock, ErasureError> {
    let path = runs_dir
        .join(ERASURE_DIR)
        .join(LOCKS_DIR)
        .join(format!("{}.lock", operation_id.as_str()));
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    file.sync_all()?;
    crate::cache_io::sync_dir(&runs_dir.join(ERASURE_DIR).join(LOCKS_DIR))?;
    match file.try_lock() {
        Ok(()) => Ok(OperationLock(file)),
        Err(TryLockError::WouldBlock) => Err(ErasureError::OperationBusy {
            operation_id: operation_id.clone(),
        }),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

struct OperationLock(File);

impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "erasure_tests.rs"]
mod tests;
