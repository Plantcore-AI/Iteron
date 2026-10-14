//! Private account-probe evidence, bounded observation collection and exact reuse/backoff decision.
use super::cache_storage::{
    CatalogCacheScopeKey, credential_scope, valid_credential_scope, write_private_file_atomic,
};
use super::{
    MAX_PROBE_CACHE_BYTES, MAX_PROBE_CACHE_ENTRIES, MAX_PROBE_FAILURE_EXPONENT, PROBE_CACHE_FILE,
    PROBE_CACHE_VERSION, ProviderDiscoveryPolicy, ProviderEntry, valid_cached_text,
};
use iteron_provider::{AccountAvailability, AccountProbe, AccountProbeResult, BalanceAvailability};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};
/// Persisted account-probe evidence, kept beside the catalog cache in its own versioned file.
///
/// The catalog cache short-circuits only the `/models` request; the account probe used to run on
/// every launch even on a cache hit, and a failed probe was never written back at all. A key that
/// has been rejected for weeks therefore still cost a round trip each time `iteron` started.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProbeCache {
    version: u32,
    entries: Vec<CachedProbe>,
}

impl Default for ProbeCache {
    fn default() -> Self {
        Self {
            version: PROBE_CACHE_VERSION,
            entries: Vec::new(),
        }
    }
}

/// One provider's last probe outcome, bound to the exact endpoint, probe kind and credential that
/// produced it. A rotated key or a re-pointed root does not inherit the old verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CachedProbe {
    pub(super) provider_id: String,
    pub(super) api_root: String,
    pub(super) probe: String,
    pub(super) credential_scope: String,
    pub(super) observed_at_unix_secs: u64,
    pub(super) outcome: CachedProbeOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum CachedProbeOutcome {
    /// The provider answered. Reusable until the TTL expires.
    Observed {
        availability: CachedAvailability,
        balance: CachedBalance,
    },
    /// The provider did not answer, or answered with an error. Counted so the retry interval can
    /// grow instead of paying the same failed round trip on every launch.
    Failed { consecutive_failures: u32 },
}

/// A closed serialization vocabulary for probe evidence. `AccountAvailability` is a provider-crate
/// enum; mapping it explicitly means adding a variant there cannot silently change what a cache
/// file written by an older binary is understood to mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CachedAvailability {
    Unknown,
    Discovering,
    Ready,
    MissingCredential,
    AuthenticationBlocked,
    BillingBlocked,
    PermissionBlocked,
    RateLimited,
    Degraded,
    ConfigurationError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CachedBalance {
    Unknown,
    Sufficient,
    Depleted,
}

impl CachedAvailability {
    pub(super) fn from_live(value: AccountAvailability) -> Self {
        match value {
            AccountAvailability::Unknown => Self::Unknown,
            AccountAvailability::Discovering => Self::Discovering,
            AccountAvailability::Ready => Self::Ready,
            AccountAvailability::MissingCredential => Self::MissingCredential,
            AccountAvailability::AuthenticationBlocked => Self::AuthenticationBlocked,
            AccountAvailability::BillingBlocked => Self::BillingBlocked,
            AccountAvailability::PermissionBlocked => Self::PermissionBlocked,
            AccountAvailability::RateLimited => Self::RateLimited,
            AccountAvailability::Degraded => Self::Degraded,
            AccountAvailability::ConfigurationError => Self::ConfigurationError,
        }
    }

    fn to_live(self) -> AccountAvailability {
        match self {
            Self::Unknown => AccountAvailability::Unknown,
            Self::Discovering => AccountAvailability::Discovering,
            Self::Ready => AccountAvailability::Ready,
            Self::MissingCredential => AccountAvailability::MissingCredential,
            Self::AuthenticationBlocked => AccountAvailability::AuthenticationBlocked,
            Self::BillingBlocked => AccountAvailability::BillingBlocked,
            Self::PermissionBlocked => AccountAvailability::PermissionBlocked,
            Self::RateLimited => AccountAvailability::RateLimited,
            Self::Degraded => AccountAvailability::Degraded,
            Self::ConfigurationError => AccountAvailability::ConfigurationError,
        }
    }
}

impl CachedBalance {
    pub(super) fn from_live(value: BalanceAvailability) -> Self {
        match value {
            BalanceAvailability::Unknown => Self::Unknown,
            BalanceAvailability::Sufficient => Self::Sufficient,
            BalanceAvailability::Depleted => Self::Depleted,
        }
    }

    fn to_live(self) -> BalanceAvailability {
        match self {
            Self::Unknown => BalanceAvailability::Unknown,
            Self::Sufficient => BalanceAvailability::Sufficient,
            Self::Depleted => BalanceAvailability::Depleted,
        }
    }
}

/// Exact cache key for one probe: provider id, endpoint, probe kind, credential scope.
pub(super) type ProbeIdentity = (String, String, String, String);

/// What this launch should do about one provider's account probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProbeDecision {
    /// A still-fresh observation stands in for the request.
    Reuse(AccountProbeResult),
    /// A recent failure is still inside its backoff window. Make no request and learn nothing new.
    Skip,
    /// Probe now; `failures` is the consecutive-failure run this attempt would extend.
    Run { failures: u32 },
}

impl ProbeCache {
    pub(super) fn load(path: &Path) -> Self {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return Self::default();
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len()
                > iteron_tunables::param_integer(
                    "cli.providers.max_probe_cache_bytes",
                    MAX_PROBE_CACHE_BYTES,
                ) as u64
        {
            return Self::default();
        }
        let Ok(file) = File::open(path) else {
            return Self::default();
        };
        #[cfg(unix)]
        let Ok(opened_metadata) = file.metadata() else {
            return Self::default();
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != opened_metadata.dev()
                || metadata.ino() != opened_metadata.ino()
                || opened_metadata.mode() & 0o077 != 0
            {
                return Self::default();
            }
        }
        // Same metadata/read-gap rule as the catalog cache: the bounded read, not the stat, is
        // what actually caps the allocation.
        let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
        let Ok(_) = file
            .take(
                (iteron_tunables::param_integer(
                    "cli.providers.max_probe_cache_bytes",
                    MAX_PROBE_CACHE_BYTES,
                ) + 1) as u64,
            )
            .read_to_end(&mut bytes)
        else {
            return Self::default();
        };
        if bytes.len()
            > iteron_tunables::param_integer(
                "cli.providers.max_probe_cache_bytes",
                MAX_PROBE_CACHE_BYTES,
            )
        {
            return Self::default();
        }
        serde_json::from_slice::<Self>(&bytes)
            .ok()
            .filter(Self::is_valid)
            .unwrap_or_default()
    }

    pub(super) fn is_valid(&self) -> bool {
        if self.version != PROBE_CACHE_VERSION || self.entries.len() > MAX_PROBE_CACHE_ENTRIES {
            return false;
        }
        let mut identities = BTreeSet::new();
        self.entries
            .iter()
            .all(|entry| entry.is_valid() && identities.insert(entry.identity()))
    }

    /// Decide the probe for one entry without making any request.
    pub(super) fn decide(
        &self,
        identity: &ProbeIdentity,
        now: u64,
        policy: ProviderDiscoveryPolicy,
    ) -> ProbeDecision {
        let Some(cached) = self
            .entries
            .iter()
            .rev()
            .find(|cached| &cached.identity() == identity)
        else {
            return ProbeDecision::Run { failures: 0 };
        };
        // A record stamped in the future is a clock change, not evidence. Re-probe.
        let Some(age) = now.checked_sub(cached.observed_at_unix_secs) else {
            return ProbeDecision::Run { failures: 0 };
        };
        match cached.outcome {
            CachedProbeOutcome::Observed {
                availability,
                balance,
            } if age < policy.positive_ttl_seconds() => ProbeDecision::Reuse(AccountProbeResult {
                availability: availability.to_live(),
                balance: balance.to_live(),
            }),
            CachedProbeOutcome::Observed { .. } => ProbeDecision::Run { failures: 0 },
            CachedProbeOutcome::Failed {
                consecutive_failures,
            } if age < probe_backoff_secs(policy, consecutive_failures) => ProbeDecision::Skip,
            CachedProbeOutcome::Failed {
                consecutive_failures,
            } => ProbeDecision::Run {
                failures: consecutive_failures,
            },
        }
    }

    /// One current record per identity, newest wins, oldest evicted at the cap.
    pub(super) fn upsert(&mut self, record: CachedProbe) {
        if !record.is_valid() {
            return;
        }
        let identity = record.identity();
        self.entries
            .retain(|existing| existing.identity() != identity);
        self.entries.push(record);
        while self.entries.len() > MAX_PROBE_CACHE_ENTRIES {
            self.entries.remove(0);
        }
    }

    pub(super) fn save_atomic(&mut self, path: &Path) -> io::Result<()> {
        self.version = PROBE_CACHE_VERSION;
        let bytes = loop {
            let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
            if bytes.len()
                <= iteron_tunables::param_integer(
                    "cli.providers.max_probe_cache_bytes",
                    MAX_PROBE_CACHE_BYTES,
                )
            {
                break bytes;
            }
            if self.entries.len() <= 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "provider account-probe cache entry exceeds byte bound",
                ));
            }
            self.entries.remove(0);
        };
        write_private_file_atomic(path, &bytes, PROBE_CACHE_FILE)
    }
}

impl CachedProbe {
    fn identity(&self) -> ProbeIdentity {
        (
            self.provider_id.clone(),
            self.api_root.clone(),
            self.probe.clone(),
            self.credential_scope.clone(),
        )
    }

    pub(super) fn is_valid(&self) -> bool {
        valid_cached_text(&self.provider_id, 128, false)
            && valid_cached_text(&self.api_root, 2_048, false)
            && account_probe_from_key(&self.probe).is_some()
            && valid_credential_scope(&self.credential_scope)
    }
}

/// One minute, doubling per consecutive failure, capped at a day. Zero failures never backs off.
pub(super) fn probe_backoff_secs(
    policy: ProviderDiscoveryPolicy,
    consecutive_failures: u32,
) -> u64 {
    if consecutive_failures == 0 {
        return 0;
    }
    let exponent = (consecutive_failures - 1).min(iteron_tunables::param_integer(
        "cli.providers.max_probe_failure_exponent",
        MAX_PROBE_FAILURE_EXPONENT,
    ));
    policy
        .failure_backoff_base_seconds()
        .checked_shl(exponent)
        .unwrap_or(policy.failure_backoff_cap_seconds())
        .min(policy.failure_backoff_cap_seconds())
}

fn account_probe_key(probe: AccountProbe) -> &'static str {
    match probe {
        AccountProbe::DeepSeekBalance => "deepseek-balance",
        AccountProbe::FireworksSuspendState => "fireworks-suspend-state",
    }
}

fn account_probe_from_key(key: &str) -> Option<AccountProbe> {
    match key {
        "deepseek-balance" => Some(AccountProbe::DeepSeekBalance),
        "fireworks-suspend-state" => Some(AccountProbe::FireworksSuspendState),
        _ => None,
    }
}

pub(super) fn probe_identity(
    entry: &ProviderEntry,
    probe: AccountProbe,
    scope_key: &CatalogCacheScopeKey,
) -> Option<ProbeIdentity> {
    Some((
        entry.id().to_owned(),
        entry.instance.api_root().as_str().to_owned(),
        account_probe_key(probe).to_owned(),
        credential_scope(&entry.instance, scope_key)?,
    ))
}

/// Probe outcomes observed by this launch, collected across concurrently resolving instances and
/// written back once. A best-effort cache must never be able to block or fail discovery.
#[derive(Clone, Default)]
pub(super) struct ProbeUpdates {
    records: Arc<Mutex<Vec<CachedProbe>>>,
}

impl ProbeUpdates {
    pub(super) fn record(
        &self,
        identity: ProbeIdentity,
        observed_at_unix_secs: u64,
        outcome: CachedProbeOutcome,
    ) {
        let (provider_id, api_root, probe, credential_scope) = identity;
        let record = CachedProbe {
            provider_id,
            api_root,
            probe,
            credential_scope,
            observed_at_unix_secs,
            outcome,
        };
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(record);
    }

    pub(super) fn take(&self) -> Vec<CachedProbe> {
        std::mem::take(
            &mut *self
                .records
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
}

#[cfg(test)]
impl ProbeCache {
    pub(super) fn fixture_parts(version: u32, entries: Vec<CachedProbe>) -> Self {
        Self { version, entries }
    }
    pub(super) fn fixture_entries(&self) -> &[CachedProbe] {
        &self.entries
    }
}
