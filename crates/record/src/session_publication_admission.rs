//! In-process ordering between authoritative work and rebuildable session publications.
//! The OS content-store leases still enforce cross-process ownership and revocation.

use crate::{RecordError, session};
use iteron_protocol::TenantId;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak as PublicationWeak};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::Instant;

type Key = (PathBuf, String);
static SCOPES: OnceLock<Mutex<HashMap<Key, Weak<Scope>>>> = OnceLock::new();
static PENDING: AtomicUsize = AtomicUsize::new(0);

std::thread_local! {
    // A publication calls several staging helpers on its own native thread. Reuse its permit,
    // including across staged index rows, without waiting on the publication itself.
    static PUBLICATIONS: RefCell<HashMap<Key, PublicationWeak<Publication>>> = RefCell::new(HashMap::new());
}

#[derive(Default)]
struct State {
    foreground: usize,
    waiting: usize,
    publishing: bool,
    queued: bool,
    worker_running: bool,
    pending: BTreeMap<String, session::SessionMeta>,
    #[cfg(test)]
    publication_hook: Option<Box<dyn FnOnce() + Send>>,
    #[cfg(test)]
    foreground_wait_hook: Option<Box<dyn FnOnce() + Send>>,
}

pub(crate) struct Scope {
    key: Key,
    state: Mutex<State>,
    changed: Condvar,
}

fn scope(runs: &Path, tenant: &TenantId) -> Result<Arc<Scope>, RecordError> {
    let key = (runs.canonicalize()?, tenant.0.clone());
    let mut scopes = SCOPES
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    scopes.retain(|_, value| value.strong_count() != 0);
    if let Some(existing) = scopes.get(&key).and_then(Weak::upgrade) {
        return Ok(existing);
    }
    // Reuse the existing maintenance admission bound for live store registrations as well as
    // queued proposals. Exhaustion refuses admission; it never bypasses coordination.
    if scopes.len() >= crate::session_maintenance::QUEUE_CAPACITY {
        return Err(crate::session_maintenance::unavailable());
    }
    let scope = Arc::new(Scope {
        key: key.clone(),
        state: Mutex::new(State::default()),
        changed: Condvar::new(),
    });
    scopes.insert(key, Arc::downgrade(&scope));
    Ok(scope)
}

impl Drop for Scope {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        PENDING.fetch_sub(state.pending.len(), Ordering::Relaxed);
    }
}

/// Owned, `Send` activity window. Nested parent/child windows share a count rather than an
/// exclusive lock. No mutex guard or file lease is retained across the caller's awaits.
pub struct ForegroundActivity {
    scope: Arc<Scope>,
}

impl ForegroundActivity {
    pub(crate) fn scope(&self) -> Arc<Scope> {
        Arc::clone(&self.scope)
    }
}

pub(crate) fn foreground(
    runs: &Path,
    tenant: &TenantId,
) -> Result<ForegroundActivity, RecordError> {
    foreground_in(scope(runs, tenant)?)
}

/// A live writer already pins a canonical runs directory and tenant at open. Reuse that exact
/// registration for nested activity windows instead of resolving the same path for every event.
pub(crate) fn foreground_in(scope: Arc<Scope>) -> Result<ForegroundActivity, RecordError> {
    let started = Instant::now();
    let limit = crate::session_maintenance::wait_limit();
    let mut state = scope
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.waiting += 1;
    #[cfg(test)]
    if state.publishing
        && let Some(hook) = state.foreground_wait_hook.take()
    {
        drop(state);
        hook();
        state = scope
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    while state.publishing {
        let remaining = limit.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            state.waiting -= 1;
            drop(state);
            schedule(&scope);
            return Err(crate::session_maintenance::unavailable());
        }
        (state, _) = scope
            .changed
            .wait_timeout(state, remaining)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    state.waiting -= 1;
    state.foreground += 1;
    drop(state);
    Ok(ForegroundActivity { scope })
}

impl Drop for ForegroundActivity {
    fn drop(&mut self) {
        let mut state = self
            .scope
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.foreground -= 1;
        drop(state);
        schedule(&self.scope);
    }
}

pub(crate) struct Publication {
    scope: Arc<Scope>,
}

impl Publication {
    pub(crate) fn published(&self, meta: &session::SessionMeta) {
        let mut state = self
            .scope
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .pending
            .get(&meta.run_id.0)
            .is_some_and(|pending| pending.record_bytes <= meta.record_bytes)
        {
            state.pending.remove(&meta.run_id.0);
            PENDING.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Cache maintenance never waits while holding an index lock. Busy foreground work defers the
/// proposal; a synchronous repair may report unavailable and retain its ordinary dirty marker.
pub(crate) fn publication(
    runs: &Path,
    tenant: &TenantId,
) -> Result<Option<Rc<Publication>>, RecordError> {
    acquire_publication(runs, tenant, false)
}

/// Explicit refreshes serialize with other publications without counting each other as
/// foreground work. A real foreground activity or waiter still takes priority and defers the
/// refresh; waiting only for another publication uses the existing absolute maintenance limit.
pub(crate) fn sync_publication(
    runs: &Path,
    tenant: &TenantId,
) -> Result<Option<Rc<Publication>>, RecordError> {
    acquire_publication(runs, tenant, true)
}

fn acquire_publication(
    runs: &Path,
    tenant: &TenantId,
    wait_for_publication: bool,
) -> Result<Option<Rc<Publication>>, RecordError> {
    let scope = scope(runs, tenant)?;
    if let Some(existing) = PUBLICATIONS.with(|publications| {
        let mut publications = publications.borrow_mut();
        publications.retain(|_, value| value.strong_count() != 0);
        publications
            .get(&scope.key)
            .and_then(PublicationWeak::upgrade)
    }) {
        return Ok(Some(existing));
    }
    let started = Instant::now();
    let limit = crate::session_maintenance::wait_limit();
    let mut state = scope
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        if state.foreground != 0 || state.waiting != 0 {
            return Ok(None);
        }
        if !state.publishing {
            break;
        }
        if !wait_for_publication {
            return Ok(None);
        }
        let remaining = limit.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(crate::session_maintenance::unavailable());
        }
        (state, _) = scope
            .changed
            .wait_timeout(state, remaining)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    state.publishing = true;
    drop(state);
    Ok(Some(publication_handle(scope)))
}

fn publication_handle(scope: Arc<Scope>) -> Rc<Publication> {
    #[cfg(test)]
    let hook = scope
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .publication_hook
        .take();
    let publication = Rc::new(Publication { scope });
    PUBLICATIONS.with(|publications| {
        publications
            .borrow_mut()
            .insert(publication.scope.key.clone(), Rc::downgrade(&publication));
    });
    #[cfg(test)]
    if let Some(hook) = hook {
        hook();
    }
    publication
}

impl Drop for Publication {
    fn drop(&mut self) {
        let mut state = self
            .scope
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.publishing = false;
        self.scope.changed.notify_all();
        drop(state);
        schedule(&self.scope);
    }
}

pub(crate) fn enqueue(runs: PathBuf, meta: session::SessionMeta) -> bool {
    let Ok(scope) = scope(&runs, &meta.tenant) else {
        return false;
    };
    let mut state = scope
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match state.pending.get(&meta.run_id.0) {
        // A late read-time repair cannot replace a newer authoritative append proposal.
        Some(previous) if previous.record_bytes > meta.record_bytes => {
            drop(state);
            return schedule(&scope);
        }
        Some(_) => {}
        None => {
            if PENDING
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    (count < crate::session_maintenance::QUEUE_CAPACITY).then_some(count + 1)
                })
                .is_err()
            {
                return false;
            }
        }
    }
    state.pending.insert(meta.run_id.0.clone(), meta);
    drop(state);
    schedule(&scope)
}

fn schedule(scope: &Arc<Scope>) -> bool {
    let mut state = scope
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.pending.is_empty()
        || state.queued
        || state.worker_running
        || state.foreground != 0
        || state.waiting != 0
        || state.publishing
    {
        return true;
    }
    state.queued = true;
    drop(state);
    if crate::session_maintenance::schedule(Arc::clone(scope)) {
        return true;
    }
    scope
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .queued = false;
    false
}

pub(crate) fn publish_pending(scope: Arc<Scope>) {
    {
        let mut state = scope
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.queued = false;
        state.worker_running = true;
    }
    // Yield to queued Flush/other scopes after one finite batch even if producers keep adding
    // proposals. The last foreground release or this command's tail schedules any remainder.
    for _ in 0..crate::session_maintenance::QUEUE_CAPACITY {
        if scope
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .is_empty()
        {
            break;
        }
        let Ok(Some(permit)) = publication(&scope.key.0, &TenantId(scope.key.1.clone())) else {
            break;
        };
        let next = scope
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .pop_first()
            .map(|(_, meta)| meta);
        let Some(meta) = next else {
            break;
        };
        PENDING.fetch_sub(1, Ordering::Relaxed);
        // The pending marker survives a rejected/stale/failed derivative publication.
        let _ = session::write_meta_if_current(&scope.key.0, &meta);
        drop(permit);
    }
    scope
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .worker_running = false;
    schedule(&scope);
}

#[cfg(test)]
pub(crate) struct TestHookGuard {
    _scope: Arc<Scope>,
}

#[cfg(test)]
pub(crate) fn install_publication_hook(
    runs: &Path,
    tenant: &TenantId,
    hook: Box<dyn FnOnce() + Send>,
) -> Result<TestHookGuard, RecordError> {
    let scope = scope(runs, tenant)?;
    scope
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .publication_hook = Some(hook);
    Ok(TestHookGuard { _scope: scope })
}

#[cfg(test)]
pub(crate) fn install_foreground_wait_hook(
    runs: &Path,
    tenant: &TenantId,
    hook: Box<dyn FnOnce() + Send>,
) -> Result<TestHookGuard, RecordError> {
    let scope = scope(runs, tenant)?;
    scope
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .foreground_wait_hook = Some(hook);
    Ok(TestHookGuard { _scope: scope })
}
