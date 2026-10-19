//! Consumed discovery writeback lifetime over actual scoped cache snapshots and probe observations.
use super::ProviderEntry;
use super::cache_storage::CatalogCacheScopeKey;
use super::catalog_cache::CatalogCache;
use super::probe_cache::{ProbeCache, ProbeUpdates};
use std::{path::PathBuf, sync::Arc};
/// Everything the write-back of a completed discovery needs. Bundled so it can be moved wholesale
/// into the post-paint task without duplicating the inline path.
pub(super) struct DiscoveryPersistence {
    cache: Arc<CatalogCache>,
    cache_scope_key: Option<CatalogCacheScopeKey>,
    cache_path: Option<PathBuf>,
    probe_cache: Arc<ProbeCache>,
    probe_cache_path: Option<PathBuf>,
    probe_updates: ProbeUpdates,
}

impl DiscoveryPersistence {
    pub(super) fn new(
        cache: Arc<CatalogCache>,
        cache_scope_key: Option<CatalogCacheScopeKey>,
        cache_path: Option<PathBuf>,
        probe_cache: Arc<ProbeCache>,
        probe_cache_path: Option<PathBuf>,
        probe_updates: ProbeUpdates,
    ) -> Self {
        Self {
            cache,
            cache_scope_key,
            cache_path,
            probe_cache,
            probe_cache_path,
            probe_updates,
        }
    }

    /// A cache write is best-effort operational state: a read-only home or full disk must not take
    /// a working provider offline.
    pub(super) fn commit(self, discovered: &[ProviderEntry]) {
        if let (Some(path), Some(scope_key)) = (&self.cache_path, self.cache_scope_key.as_ref()) {
            let mut next_cache = (*self.cache).clone();
            let mut changed = false;
            for entry in discovered {
                changed |= next_cache.upsert(entry, scope_key);
            }
            if changed && next_cache.save_atomic(path).is_err() {
                eprintln!("warning: provider catalog cache could not be persisted");
            }
        }
        let observed = self.probe_updates.take();
        if let (Some(path), false) = (&self.probe_cache_path, observed.is_empty()) {
            let mut next_cache = (*self.probe_cache).clone();
            for record in observed {
                next_cache.upsert(record);
            }
            if next_cache.save_atomic(path).is_err() {
                eprintln!("warning: provider account-probe cache could not be persisted");
            }
        }
    }
}
