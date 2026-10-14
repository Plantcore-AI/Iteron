//! Sole bounded provider/account/model health state and evidence merging.
use super::{
    AccountAvailability, AccountProbe, AccountProbeResult, BalanceAvailability, MAX_HEALTH_ENTRIES,
    MAX_INSTANCE_ID_BYTES, MAX_MODEL_HEALTH_ENTRIES, MAX_MODEL_ID_BYTES,
    MODEL_HEALTH_ENTRIES_PER_PROVIDER,
};
use crate::{AvailabilityTransition, ProviderError};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHealth {
    pub availability: AccountAvailability,
    pub balance: BalanceAvailability,
    pub last_error_code: Option<String>,
    pub last_request_id: Option<String>,
}

/// Evidence that one model leaf, rather than the provider account, is unavailable. Entries exist
/// only for known-unavailable models and are removed after a successful turn for the same pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelHealth {
    pub last_error_code: Option<String>,
    pub last_request_id: Option<String>,
}

impl Default for ProviderHealth {
    fn default() -> Self {
        Self {
            availability: AccountAvailability::Unknown,
            balance: BalanceAvailability::Unknown,
            last_error_code: None,
            last_request_id: None,
        }
    }
}

/// Shared, bounded in-memory health state. It contains no credentials and deliberately starts
/// with an unknown balance. Oldest entries are evicted deterministically at the configured cap.
#[derive(Clone)]
pub struct ProviderHealthStore {
    inner: Arc<Mutex<HealthState>>,
    max_entries: usize,
    max_model_entries: usize,
}

#[derive(Default)]
struct HealthState {
    entries: BTreeMap<String, ProviderHealth>,
    order: VecDeque<String>,
    model_entries: BTreeMap<(String, String), ModelHealth>,
    model_order: VecDeque<(String, String)>,
}

impl ProviderHealthStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HealthState::default())),
            // `.max(1)`: the ceiling is operator-settable down to 0, and `clamp(1, 0)` is a
            // panic in the standard library, not a refusal.
            max_entries: max_entries.clamp(
                1,
                iteron_tunables::param_usize(
                    "provider.catalog.max_health_entries",
                    iteron_tunables::param_integer(
                        "provider.catalog.max_health_entries",
                        MAX_HEALTH_ENTRIES,
                    ),
                )
                .max(1),
            ),
            max_model_entries: max_entries
                .saturating_mul(iteron_tunables::param_usize(
                    "provider.catalog.model_health_entries_per_provider",
                    iteron_tunables::param_integer(
                        "provider.catalog.model_health_entries_per_provider",
                        MODEL_HEALTH_ENTRIES_PER_PROVIDER,
                    ),
                ))
                .clamp(
                    1,
                    iteron_tunables::param_usize(
                        "provider.catalog.max_model_health_entries",
                        iteron_tunables::param_integer(
                            "provider.catalog.max_model_health_entries",
                            MAX_MODEL_HEALTH_ENTRIES,
                        ),
                    )
                    .max(1),
                ),
        }
    }

    pub fn get(&self, provider_instance_id: &str) -> ProviderHealth {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(provider_instance_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn model_len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .model_entries
            .len()
    }

    pub fn model_health(&self, provider_instance_id: &str, model_id: &str) -> Option<ModelHealth> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .model_entries
            .get(&(provider_instance_id.to_string(), model_id.to_string()))
            .cloned()
    }

    pub fn is_model_unavailable(&self, provider_instance_id: &str, model_id: &str) -> bool {
        self.model_health(provider_instance_id, model_id).is_some()
    }

    /// Clear one learned model-leaf block after an explicit operator retry request.
    ///
    /// Account-wide authentication, billing, permission, credential, and configuration gates are
    /// deliberately untouched. A subsequent typed failure recreates the leaf immediately. This
    /// is the only recovery path that does not require a successful turn, avoiding the dead state
    /// where preflight rejection prevented the very request that could prove recovery.
    pub fn clear_model_unavailable_for_retry(
        &self,
        provider_instance_id: &str,
        model_id: &str,
    ) -> bool {
        if !valid_health_key(
            provider_instance_id,
            iteron_tunables::param_integer(
                "provider.catalog.max_instance_id_bytes",
                MAX_INSTANCE_ID_BYTES,
            ),
        ) || !valid_health_key(
            model_id,
            iteron_tunables::param_integer(
                "provider.catalog.max_model_id_bytes",
                MAX_MODEL_ID_BYTES,
            ),
        ) {
            return false;
        }
        let key = (provider_instance_id.to_string(), model_id.to_string());
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = state.model_entries.remove(&key).is_some();
        if removed {
            state.model_order.retain(|candidate| candidate != &key);
        }
        removed
    }

    /// Return only durable account blocks. Unknown, temporary rate limits, and degradation must
    /// reach the transport so they can recover naturally.
    pub fn blocked_account(&self, provider_instance_id: &str) -> Option<AccountAvailability> {
        let health = self.get(provider_instance_id);
        if health.balance == BalanceAvailability::Depleted {
            return Some(AccountAvailability::BillingBlocked);
        }
        matches!(
            health.availability,
            AccountAvailability::MissingCredential
                | AccountAvailability::AuthenticationBlocked
                | AccountAvailability::BillingBlocked
                | AccountAvailability::PermissionBlocked
                | AccountAvailability::ConfigurationError
        )
        .then_some(health.availability)
    }

    pub fn mark_ready(&self, provider_instance_id: &str) {
        self.update(provider_instance_id, |health| {
            // Catalog visibility is not proof that any durable inference/account failure has
            // recovered. It may clear only temporary/unknown states.
            if !provider_health_has_durable_block(health) {
                health.availability = AccountAvailability::Ready;
                // Catalog visibility proves credentials work, but not remaining balance.
                health.balance = BalanceAvailability::Unknown;
                health.last_error_code = None;
                health.last_request_id = None;
            }
        });
    }

    /// A paid turn is stronger evidence than catalog discovery: it proves this account/model pair
    /// works now and clears only that model leaf's prior unavailable marker.
    pub fn mark_turn_ready(&self, provider_instance_id: &str, model_id: &str) {
        self.update(provider_instance_id, |health| {
            // Concurrent requests can complete out of order. A generic success must not erase a
            // durable block observed by another request; authoritative control-plane recovery is
            // handled by `update_from_probe` with a typed probe kind.
            if !provider_health_has_durable_block(health) {
                health.availability = AccountAvailability::Ready;
                health.balance = BalanceAvailability::Unknown;
                health.last_error_code = None;
                health.last_request_id = None;
            }
        });
        self.remove_model(provider_instance_id, model_id);
    }

    pub fn mark_missing_credential(&self, provider_instance_id: &str) {
        self.update(provider_instance_id, |health| {
            health.availability = AccountAvailability::MissingCredential;
        });
    }

    pub fn update_from_error(&self, provider_instance_id: &str, error: &ProviderError) {
        self.update_error(provider_instance_id, None, error);
    }

    pub fn update_from_turn_error(
        &self,
        provider_instance_id: &str,
        model_id: &str,
        error: &ProviderError,
    ) {
        self.update_from_turn_error_with_scope(provider_instance_id, model_id, error, false);
    }

    pub fn update_from_turn_error_with_scope(
        &self,
        provider_instance_id: &str,
        model_id: &str,
        error: &ProviderError,
        account_failure_is_model_scoped: bool,
    ) {
        if account_failure_is_model_scoped
            && let Some(normalized) = error.normalized()
            && matches!(
                normalized.availability,
                AvailabilityTransition::Account(
                    AccountAvailability::BillingBlocked | AccountAvailability::PermissionBlocked
                )
            )
        {
            self.mark_model_unavailable(provider_instance_id, model_id, normalized);
            return;
        }
        self.update_error(provider_instance_id, Some(model_id), error);
    }

    fn update_error(
        &self,
        provider_instance_id: &str,
        model_id: Option<&str>,
        error: &ProviderError,
    ) {
        if let Some(normalized) = error.normalized()
            && normalized.availability == AvailabilityTransition::ModelUnavailable
        {
            if let Some(model_id) = model_id {
                self.mark_model_unavailable(provider_instance_id, model_id, normalized);
            }
            return;
        }
        self.update(provider_instance_id, |health| match error {
            ProviderError::MissingCredential { .. } | ProviderError::NoKey => {
                health.availability = merge_account_availability(
                    health.availability,
                    AccountAvailability::MissingCredential,
                );
            }
            ProviderError::Configuration(_) => {
                health.availability = merge_account_availability(
                    health.availability,
                    AccountAvailability::ConfigurationError,
                );
            }
            _ => {
                if let Some(normalized) = error.normalized() {
                    if let AvailabilityTransition::Account(availability) = normalized.availability {
                        health.availability =
                            merge_account_availability(health.availability, availability);
                        if availability == AccountAvailability::BillingBlocked {
                            health.balance = BalanceAvailability::Depleted;
                        }
                    }
                    health.last_error_code = normalized.code.clone();
                    health.last_request_id = normalized.request_id.clone();
                }
            }
        });
    }

    pub fn update_from_probe(
        &self,
        provider_instance_id: &str,
        probe: AccountProbe,
        result: AccountProbeResult,
    ) {
        self.update(provider_instance_id, |health| {
            // Catalog discovery and account probes run concurrently in the CLI. A successful or
            // inconclusive probe is not evidence that a catalog-auth/billing/permission failure
            // recovered, so completion order must not change the durable gate. A blocking probe,
            // however, is authoritative for its documented scope and may replace Ready.
            if provider_health_has_durable_block(health)
                && !account_result_has_durable_block(result)
            {
                let authoritative_recovery = match probe {
                    // DeepSeek documents `is_available:true` as positive balance evidence. It
                    // may clear only a prior billing/depleted state, never auth/config/permission.
                    AccountProbe::DeepSeekBalance => {
                        result.availability == AccountAvailability::Ready
                            && result.balance == BalanceAvailability::Sufficient
                            && matches!(
                                health.availability,
                                AccountAvailability::BillingBlocked
                                    | AccountAvailability::Unknown
                                    | AccountAvailability::Ready
                            )
                    }
                    // UNSUSPENDED proves only suspension state, not remaining credit. Do not let
                    // it erase a billing/auth/configuration failure from another operation.
                    AccountProbe::FireworksSuspendState => {
                        result.availability == AccountAvailability::Ready
                            && health.availability == AccountAvailability::PermissionBlocked
                            && health.balance != BalanceAvailability::Depleted
                    }
                };
                if !authoritative_recovery {
                    return;
                }
            }
            if provider_health_has_durable_block(health) && account_result_has_durable_block(result)
            {
                health.availability =
                    merge_account_availability(health.availability, result.availability);
                if result.balance == BalanceAvailability::Depleted {
                    health.balance = BalanceAvailability::Depleted;
                }
                return;
            }
            health.availability = result.availability;
            health.balance = result.balance;
            health.last_error_code = None;
            health.last_request_id = None;
        });
    }

    fn update(&self, provider_instance_id: &str, apply: impl FnOnce(&mut ProviderHealth)) {
        if provider_instance_id.is_empty()
            || provider_instance_id.len()
                > iteron_tunables::param_integer(
                    "provider.catalog.max_instance_id_bytes",
                    MAX_INSTANCE_ID_BYTES,
                )
        {
            return;
        }
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.entries.contains_key(provider_instance_id) {
            while state.entries.len() >= self.max_entries {
                if let Some(oldest) = state.order.pop_front() {
                    state.entries.remove(&oldest);
                } else {
                    break;
                }
            }
            state.order.push_back(provider_instance_id.to_string());
        }
        let health = state
            .entries
            .entry(provider_instance_id.to_string())
            .or_default();
        apply(health);
    }

    fn mark_model_unavailable(
        &self,
        provider_instance_id: &str,
        model_id: &str,
        normalized: &crate::NormalizedFailure,
    ) {
        if !valid_health_key(
            provider_instance_id,
            iteron_tunables::param_integer(
                "provider.catalog.max_instance_id_bytes",
                MAX_INSTANCE_ID_BYTES,
            ),
        ) || !valid_health_key(
            model_id,
            iteron_tunables::param_integer(
                "provider.catalog.max_model_id_bytes",
                MAX_MODEL_ID_BYTES,
            ),
        ) {
            return;
        }
        let key = (provider_instance_id.to_string(), model_id.to_string());
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.model_entries.contains_key(&key) {
            while state.model_entries.len() >= self.max_model_entries {
                if let Some(oldest) = state.model_order.pop_front() {
                    state.model_entries.remove(&oldest);
                } else {
                    break;
                }
            }
            state.model_order.push_back(key.clone());
        }
        state.model_entries.insert(
            key,
            ModelHealth {
                last_error_code: normalized.code.clone(),
                last_request_id: normalized.request_id.clone(),
            },
        );
    }

    fn remove_model(&self, provider_instance_id: &str, model_id: &str) {
        self.clear_model_unavailable_for_retry(provider_instance_id, model_id);
    }
}

fn account_availability_is_durable_block(availability: AccountAvailability) -> bool {
    matches!(
        availability,
        AccountAvailability::MissingCredential
            | AccountAvailability::AuthenticationBlocked
            | AccountAvailability::BillingBlocked
            | AccountAvailability::PermissionBlocked
            | AccountAvailability::ConfigurationError
    )
}

fn durable_availability_priority(availability: AccountAvailability) -> u8 {
    match availability {
        AccountAvailability::ConfigurationError => 5,
        AccountAvailability::MissingCredential => 4,
        AccountAvailability::AuthenticationBlocked => 3,
        AccountAvailability::BillingBlocked => 2,
        AccountAvailability::PermissionBlocked => 1,
        AccountAvailability::Unknown
        | AccountAvailability::Discovering
        | AccountAvailability::Ready
        | AccountAvailability::RateLimited
        | AccountAvailability::Degraded => 0,
    }
}

fn merge_account_availability(
    current: AccountAvailability,
    observed: AccountAvailability,
) -> AccountAvailability {
    if account_availability_is_durable_block(current)
        && account_availability_is_durable_block(observed)
    {
        if durable_availability_priority(observed) > durable_availability_priority(current) {
            observed
        } else {
            current
        }
    } else {
        observed
    }
}

fn provider_health_has_durable_block(health: &ProviderHealth) -> bool {
    health.balance == BalanceAvailability::Depleted
        || account_availability_is_durable_block(health.availability)
}

fn account_result_has_durable_block(result: AccountProbeResult) -> bool {
    result.balance == BalanceAvailability::Depleted
        || account_availability_is_durable_block(result.availability)
}

fn valid_health_key(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}
