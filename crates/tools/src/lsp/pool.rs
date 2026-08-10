use super::input::SourceDocument;
use super::policy::{LspLanguageRoute, LspRuntimePolicy, MAX_LSP_POOL_SERVERS};
use super::session::{Driver, LiveResult, RunFailure};
use super::{LspHealth, LspToolError, QueryKind};
use core_sandbox::{Confinement, SandboxError, spawn_confined_process_from_workspace};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PoolKey {
    workspace: PathBuf,
    server_id: String,
    command: String,
}

#[derive(Default)]
struct ServerSlot {
    driver: Option<Driver>,
    consecutive_failures: u32,
    total_restarts: u32,
    next_restart: Option<tokio::time::Instant>,
    spawned_once: bool,
    unknown_outcome: bool,
}

pub(super) struct Launcher {
    instance: u32,
    next_sequence: AtomicU32,
    policy: Mutex<LspRuntimePolicy>,
    pool: Mutex<BTreeMap<PoolKey, Arc<AsyncMutex<ServerSlot>>>>,
    activated: AtomicBool,
}

impl Launcher {
    pub(super) fn new(policy: LspRuntimePolicy) -> Result<Self, LspToolError> {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| LspToolError::IdentityUnavailable)?;
        Ok(Self {
            instance: u32::from_le_bytes(bytes) | 1,
            next_sequence: AtomicU32::new(1),
            policy: Mutex::new(policy),
            pool: Mutex::new(BTreeMap::new()),
            activated: AtomicBool::new(false),
        })
    }

    pub(super) fn configure_policy(&self, policy: LspRuntimePolicy) -> Result<(), LspToolError> {
        let policy = LspRuntimePolicy::new(policy.routes, policy.recovery)
            .map_err(|_| LspToolError::InvalidPolicy)?;
        if self.activated.load(Ordering::Acquire) || !lock(&self.pool).is_empty() {
            return Err(LspToolError::PolicyLocked);
        }
        *lock(&self.policy) = policy;
        Ok(())
    }

    pub(super) fn policy(&self) -> LspRuntimePolicy {
        lock(&self.policy).clone()
    }

    pub(super) fn routes(&self) -> BTreeMap<String, LspLanguageRoute> {
        self.policy().by_language()
    }

    fn mint_epoch(&self) -> Result<u64, LspToolError> {
        let sequence = self
            .next_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| LspToolError::IdentityExhausted)?;
        Ok((u64::from(self.instance) << 32) | u64::from(sequence))
    }

    fn slot(&self, document: &SourceDocument) -> Result<Arc<AsyncMutex<ServerSlot>>, LspToolError> {
        let key = PoolKey {
            workspace: document.root().to_path_buf(),
            server_id: document.server_id().to_owned(),
            command: document.command().to_owned(),
        };
        let mut pool = lock(&self.pool);
        if let Some(slot) = pool.get(&key) {
            return Ok(Arc::clone(slot));
        }
        if pool.len() >= MAX_LSP_POOL_SERVERS {
            return Err(LspToolError::PoolFull {
                limit: MAX_LSP_POOL_SERVERS,
            });
        }
        let slot = Arc::new(AsyncMutex::new(ServerSlot::default()));
        pool.insert(key, Arc::clone(&slot));
        Ok(slot)
    }

    pub(super) async fn run_query_owned(
        self: Arc<Self>,
        document: Arc<SourceDocument>,
        query: QueryKind,
        sensitive_env_names: Vec<String>,
        deadline: tokio::time::Instant,
        mut cancelled: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<LiveResult, RunFailure> {
        self.activated.store(true, Ordering::Release);
        let policy = self.policy();
        let slot = self
            .slot(&document)
            .map_err(|error| RunFailure::new(error, false))?;
        let mut slot = tokio::select! {
            biased;
            _ = &mut cancelled => return Err(RunFailure::new(LspToolError::OperationCancelled, false)),
            _ = tokio::time::sleep_until(deadline) => return Err(RunFailure::new(LspToolError::OperationTimeout, false)),
            slot = slot.lock() => slot,
        };

        let reused_server = slot.driver.is_some();
        if slot.driver.is_none() {
            self.wait_for_restart(&mut slot, policy.recovery, deadline, &mut cancelled)
                .await?;
            let restarting = slot.spawned_once;
            // An initial spawn failure is still an attempted server lifetime. Mark it before the
            // fallible operation so repeated spawn/initialize failures consume the same bounded
            // restart budget instead of being misclassified as unlimited first attempts.
            slot.spawned_once = true;
            let epoch = self
                .mint_epoch()
                .map_err(|error| RunFailure::new(error, false))?;
            match spawn_initialized(
                epoch,
                &document,
                sensitive_env_names,
                policy.recovery.request_timeout_milliseconds,
                deadline,
                &mut cancelled,
            )
            .await
            {
                Ok(driver) => {
                    slot.driver = Some(driver);
                    if restarting {
                        slot.total_restarts = slot.total_restarts.saturating_add(1);
                    }
                }
                Err(failure) => {
                    slot.unknown_outcome |= failure.outcome_unknown;
                    note_failure(&mut slot, policy.recovery);
                    return Err(failure);
                }
            }
        }

        let request_timeout = Duration::from_millis(
            policy.recovery.request_timeout_milliseconds.min(
                deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            ),
        );
        let result = {
            let driver = slot
                .driver
                .as_mut()
                .expect("a pooled slot has a driver after successful admission");
            tokio::select! {
                biased;
                _ = &mut cancelled => Err(LspToolError::OperationCancelled),
                _ = tokio::time::sleep_until(deadline) => Err(LspToolError::OperationTimeout),
                result = driver.execute(&document, query, request_timeout) => result,
            }
        };
        match result {
            Ok(value) => {
                slot.consecutive_failures = 0;
                slot.next_restart = None;
                let driver = slot
                    .driver
                    .as_ref()
                    .expect("successful query retains driver");
                Ok(LiveResult {
                    value,
                    server_epoch: driver.epoch(),
                    backend: driver.backend(),
                    reused_server,
                    restart_count: slot.total_restarts,
                    server_id: document.server_id().to_owned(),
                })
            }
            Err(error) => {
                let mut driver = slot.driver.take().expect("failed query owned a driver");
                let _cleanup_confirmed = driver.force_cleanup().await;
                // The request crossed the server boundary but produced no accepted response.
                // Whether cleanup itself reconciled does not make that request outcome known.
                slot.unknown_outcome = true;
                note_failure(&mut slot, policy.recovery);
                // A spawned CodeExecuting peer may have performed workspace effects even though an
                // LSP request is logically read-only. Never retry this unknown attempt in-place.
                Err(RunFailure::new(error, true))
            }
        }
    }

    async fn wait_for_restart(
        &self,
        slot: &mut ServerSlot,
        recovery: super::policy::LspRecoveryPolicy,
        deadline: tokio::time::Instant,
        cancelled: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), RunFailure> {
        if slot.spawned_once && slot.consecutive_failures > recovery.max_restarts {
            return Err(RunFailure::new(
                LspToolError::RestartBudgetExhausted {
                    attempts: recovery.max_restarts,
                },
                false,
            ));
        }
        let Some(not_before) = slot.next_restart else {
            return Ok(());
        };
        if not_before >= deadline {
            return Err(RunFailure::new(LspToolError::OperationTimeout, false));
        }
        tokio::select! {
            biased;
            _ = cancelled => Err(RunFailure::new(LspToolError::OperationCancelled, false)),
            _ = tokio::time::sleep_until(deadline) => Err(RunFailure::new(LspToolError::OperationTimeout, false)),
            _ = tokio::time::sleep_until(not_before) => Ok(()),
        }
    }

    pub(super) async fn clean(&self) -> Vec<(String, bool)> {
        let slots = lock(&self.pool)
            .iter()
            .map(|(key, slot)| (key.server_id.clone(), Arc::clone(slot)))
            .collect::<Vec<_>>();
        let mut retired = Vec::with_capacity(slots.len());
        for (server_id, slot) in slots {
            let mut slot = slot.lock().await;
            let confirmed = if let Some(mut driver) = slot.driver.take() {
                driver.shutdown().await.is_ok() || driver.force_cleanup().await
            } else {
                true
            };
            slot.unknown_outcome |= !confirmed;
            retired.push((server_id, confirmed));
        }
        retired
    }

    pub(super) async fn health(&self) -> LspHealth {
        let configured_routes = self.policy().routes.len();
        let slots = lock(&self.pool).values().cloned().collect::<Vec<_>>();
        let mut running_servers = 0;
        let mut restart_count = 0_u64;
        let mut unknown_slots = 0;
        for slot in &slots {
            let slot = slot.lock().await;
            running_servers += usize::from(slot.driver.is_some());
            restart_count = restart_count.saturating_add(u64::from(slot.total_restarts));
            unknown_slots += usize::from(slot.unknown_outcome);
        }
        LspHealth {
            schema_version: 1,
            configured_routes,
            pool_slots: slots.len(),
            running_servers,
            restart_count,
            unknown_slots,
            freshness_attested_servers: 0,
            freshness_unattested_servers: running_servers,
        }
    }
}

async fn spawn_initialized(
    epoch: u64,
    document: &SourceDocument,
    sensitive_env_names: Vec<String>,
    timeout_milliseconds: u64,
    deadline: tokio::time::Instant,
    cancelled: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<Driver, RunFailure> {
    let mut confinement = Confinement::egress_off(document.root());
    confinement.timeout_secs = 24 * 60 * 60;
    confinement.sensitive_env_names = sensitive_env_names;
    let root_capability = document
        .root_capability()
        .map_err(|error| RunFailure::new(error, false))?;
    let spawn =
        spawn_confined_process_from_workspace(document.command(), &confinement, root_capability);
    let process = match tokio::select! {
        biased;
        _ = &mut *cancelled => return Err(RunFailure::new(LspToolError::OperationCancelled, false)),
        _ = tokio::time::sleep_until(deadline) => return Err(RunFailure::new(LspToolError::OperationTimeout, false)),
        result = spawn => result,
    } {
        Ok(process) => process,
        Err(SandboxError::Unsupported | SandboxError::Profile(_)) => {
            return Err(RunFailure::new(LspToolError::SandboxUnavailable, false));
        }
        Err(SandboxError::Spawn(_)) => {
            return Err(RunFailure::new(LspToolError::SpawnOutcomeUnknown, true));
        }
    };
    let mut driver = Driver::new(process, epoch).await?;
    let timeout = Duration::from_millis(timeout_milliseconds);
    let root_uri = document
        .root_uri()
        .map_err(|error| RunFailure::new(error, true))?;
    let initialized = tokio::select! {
        biased;
        _ = &mut *cancelled => Err(LspToolError::OperationCancelled),
        _ = tokio::time::sleep_until(deadline) => Err(LspToolError::OperationTimeout),
        result = driver.initialize(&root_uri, timeout) => result,
    };
    if let Err(error) = initialized {
        let _cleanup_confirmed = driver.force_cleanup().await;
        return Err(RunFailure::new(error, true));
    }
    Ok(driver)
}

fn note_failure(slot: &mut ServerSlot, recovery: super::policy::LspRecoveryPolicy) {
    slot.consecutive_failures = slot.consecutive_failures.saturating_add(1);
    let delay = recovery.delay_for(slot.consecutive_failures);
    slot.next_restart = tokio::time::Instant::now().checked_add(Duration::from_millis(delay));
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_policy_is_mutable_only_before_activation() {
        let launcher = Launcher::new(LspRuntimePolicy::default()).unwrap();
        assert!(
            launcher
                .configure_policy(LspRuntimePolicy::default())
                .is_ok()
        );
        launcher.activated.store(true, Ordering::Release);
        assert!(matches!(
            launcher.configure_policy(LspRuntimePolicy::default()),
            Err(LspToolError::PolicyLocked)
        ));
    }
}
