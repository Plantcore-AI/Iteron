//! Sole owner of dormant discovery work, the actual physical refresh task and settled catalog
//! publication. The directory receives immutable entries through a typed settlement; it cannot
//! modify pending phases or start a second network task through a shared state lock.

use super::cache_writeback::DiscoveryPersistence;
use super::{
    ProviderEntry, ResolveContext, SELECTED_PROVIDER_REFRESH_WAIT, current_unix_ms,
    ordered_entries, resolve_entry,
};
use futures_util::future::join_all;
use iteron_provider::{
    EffortApplication, Provider, ProviderAttemptSemantics, ProviderControlCapabilities,
    ProviderError, ProviderNotice, StreamItem, TurnRequest, TurnResult,
};
use std::collections::BTreeSet;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering as AtomicOrdering},
};

pub(super) enum DiscoverySettlement {
    Settled(Arc<Vec<ProviderEntry>>),
    Pending,
    Abandoned,
}

#[derive(Clone, Default)]
pub(super) struct ProviderRefreshActivity {
    inner: Arc<Mutex<ProviderRefreshActivityState>>,
}

#[derive(Default)]
struct ProviderRefreshActivityState {
    tx: Option<tokio::sync::mpsc::Sender<iteron_protocol::ActivityEvent>>,
    started_at_unix_ms: u64,
    state: Option<iteron_protocol::ActivityState>,
    saturated: u64,
}

impl ProviderRefreshActivity {
    pub(super) fn pending() -> Self {
        Self::default()
    }

    fn start(&self) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.state.is_some() {
            return;
        }
        state.started_at_unix_ms = current_unix_ms();
        state.state = Some(iteron_protocol::ActivityState::Running);
        Self::publish_locked(&mut state);
    }

    pub(super) fn install(&self, tx: tokio::sync::mpsc::Sender<iteron_protocol::ActivityEvent>) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.tx = Some(tx);
        Self::publish_locked(&mut state);
    }

    fn complete(&self, result: iteron_protocol::ActivityState) {
        debug_assert!(result.is_terminal());
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.state = Some(result);
        Self::publish_locked(&mut state);
    }

    fn publish_locked(state: &mut ProviderRefreshActivityState) {
        let (Some(tx), Some(activity_state)) = (&state.tx, state.state) else {
            return;
        };
        let started_at_unix_ms = state.started_at_unix_ms;
        let event = iteron_protocol::ActivityEvent {
            schema_version: iteron_protocol::ACTIVITY_SCHEMA_VERSION,
            id: "startup:provider_refresh".into(),
            parent_id: None,
            kind: iteron_protocol::ActivityKind::Startup,
            state: activity_state,
            owner: iteron_protocol::ActivityOwner::Provider,
            started_at_unix_ms,
            updated_at_unix_ms: current_unix_ms().max(started_at_unix_ms),
            attempt: 1,
            limit: 1,
            next_retry_at_unix_ms: None,
            deadline_unix_ms: None,
            cancelability: iteron_protocol::ActivityCancelability::Cooperative,
            detail_code: Some(iteron_protocol::ActivityDetailCode::ProviderRefresh),
            progress: None,
        };
        if tx.try_send(event).is_err() {
            state.saturated = state.saturated.saturating_add(1);
        }
    }
}

/// The post-paint half of a split discovery. Merely constructing this object is network-inert;
/// exactly one caller starts the task from [`super::ProviderDirectory::settle`], after the TUI has drawn
/// its first frame. Every other clone joins that task or reads the settled vector it published.
pub(super) struct ProviderDiscoveryOwner {
    /// Ids whose network resolution is still outstanding. A caller that is about to ROUTE through
    /// one of them has to settle first, and only the id set can say so: a deferred instance may
    /// already carry a cache-primed catalog and still be missing its account probe.
    pending: BTreeSet<String>,
    activity: ProviderRefreshActivity,
    state: tokio::sync::Mutex<DeferredState>,
    post_paint_started: AtomicBool,
    post_paint_notify: tokio::sync::Notify,
}

enum DeferredState {
    Dormant(Box<DeferredWork>),
    Pending(tokio::task::JoinHandle<Vec<ProviderEntry>>),
    Settled(Arc<Vec<ProviderEntry>>),
    /// The task was cancelled or panicked. The eagerly resolved view stands; never retry silently,
    /// because a retry would re-run exactly the requests that just failed to complete.
    Abandoned,
}

/// Network work retained without polling until a post-paint caller explicitly starts discovery.
struct DeferredWork {
    pending: Vec<(usize, ProviderEntry, bool)>,
    resolved: Vec<(usize, ProviderEntry)>,
    context: ResolveContext,
    persistence: DiscoveryPersistence,
}

impl ProviderDiscoveryOwner {
    pub(super) fn new(
        pending_ids: BTreeSet<String>,
        pending: Vec<(usize, ProviderEntry, bool)>,
        resolved: Vec<(usize, ProviderEntry)>,
        context: ResolveContext,
        persistence: DiscoveryPersistence,
        activity: ProviderRefreshActivity,
    ) -> Self {
        Self {
            pending: pending_ids,
            activity,
            state: tokio::sync::Mutex::new(DeferredState::Dormant(Box::new(DeferredWork {
                pending,
                resolved,
                context,
                persistence,
            }))),
            post_paint_started: AtomicBool::new(false),
            post_paint_notify: tokio::sync::Notify::new(),
        }
    }
    pub(super) fn is_pending(&self, provider: &str) -> bool {
        self.pending.contains(provider)
    }
    pub(super) fn admit_provider(self: &Arc<Self>, inner: Arc<dyn Provider>) -> Arc<dyn Provider> {
        Arc::new(PostPaintAdmittedProvider {
            inner,
            deferred: Arc::clone(self),
        })
    }
    pub(super) async fn settle(&self) -> DiscoverySettlement {
        self.settle_with_wait(Some(iteron_tunables::param_duration(
            "cli.providers.selected_provider_refresh_wait",
            SELECTED_PROVIDER_REFRESH_WAIT,
        )))
        .await
    }
    pub(super) async fn settle_complete(&self) -> DiscoverySettlement {
        self.settle_with_wait(None).await
    }
    async fn settle_with_wait(&self, wait: Option<std::time::Duration>) -> DiscoverySettlement {
        if !self.begin_after_paint() {
            self.activity
                .complete(iteron_protocol::ActivityState::Failed);
            return DiscoverySettlement::Abandoned;
        }
        let mut state = self.state.lock().await;
        let mut handle = match std::mem::replace(&mut *state, DeferredState::Abandoned) {
            DeferredState::Dormant(_) => unreachable!("begin_after_paint owns dormant transition"),
            DeferredState::Pending(handle) => handle,
            DeferredState::Settled(entries) => {
                *state = DeferredState::Settled(entries.clone());
                return DiscoverySettlement::Settled(entries);
            }
            DeferredState::Abandoned => {
                self.activity
                    .complete(iteron_protocol::ActivityState::Failed);
                return DiscoverySettlement::Abandoned;
            }
        };
        let completed = if let Some(wait) = wait {
            match tokio::time::timeout(wait, &mut handle).await {
                Ok(completed) => completed,
                Err(_) => {
                    // The same physical refresh remains joinable; timeout never dispatches twice.
                    *state = DeferredState::Pending(handle);
                    return DiscoverySettlement::Pending;
                }
            }
        } else {
            (&mut handle).await
        };
        let entries = match completed {
            Ok(entries) => Arc::new(entries),
            Err(_) => {
                self.activity
                    .complete(iteron_protocol::ActivityState::Failed);
                return DiscoverySettlement::Abandoned;
            }
        };
        *state = DeferredState::Settled(entries.clone());
        self.activity
            .complete(iteron_protocol::ActivityState::Succeeded);
        DiscoverySettlement::Settled(entries)
    }
    /// Cross the no-network-before-paint boundary without depending on a spawned task being polled.
    ///
    /// This method performs only an in-memory state transition plus `tokio::spawn`: the retained
    /// discovery future is moved from `Dormant` to `Pending`, then the selected-route admission
    /// signal is published. The network work may run afterward, but a model request can no longer
    /// race a merely scheduled settler and incorrectly conclude that refresh never started.
    pub(super) fn begin_after_paint(&self) -> bool {
        let Ok(mut state) = self.state.try_lock() else {
            // Another clone is already starting or joining the one shared task. It owns the state
            // transition; publishing the monotone post-paint boundary lets route admission wait
            // for that owner rather than fail because this caller lost a scheduler race.
            self.signal_post_paint_start();
            return true;
        };
        let work = match std::mem::replace(&mut *state, DeferredState::Abandoned) {
            DeferredState::Dormant(work) => work,
            DeferredState::Pending(handle) => {
                *state = DeferredState::Pending(handle);
                self.signal_post_paint_start();
                return true;
            }
            DeferredState::Settled(entries) => {
                *state = DeferredState::Settled(entries);
                self.signal_post_paint_start();
                return true;
            }
            DeferredState::Abandoned => return false,
        };

        self.activity.start();
        let background_activity = self.activity.clone();
        let DeferredWork {
            pending,
            resolved,
            context,
            persistence,
        } = *work;
        let handle = tokio::spawn(async move {
            let settled = join_all(pending.into_iter().map(|(index, entry, served)| {
                let context = context.clone();
                async move { (index, resolve_entry(entry, served, &context).await) }
            }))
            .await;
            let discovered = ordered_entries(resolved.into_iter().chain(settled).collect());
            persistence.commit(&discovered);
            background_activity.complete(iteron_protocol::ActivityState::Succeeded);
            discovered
        });
        *state = DeferredState::Pending(handle);
        self.signal_post_paint_start();
        true
    }

    fn signal_post_paint_start(&self) {
        self.post_paint_started.store(true, AtomicOrdering::Release);
        self.post_paint_notify.notify_waiters();
    }

    async fn await_selected_route_admission(&self) -> Result<(), ProviderError> {
        while !self.post_paint_started.load(AtomicOrdering::Acquire) {
            let notified = self.post_paint_notify.notified();
            if self.post_paint_started.load(AtomicOrdering::Acquire) {
                break;
            }
            tokio::time::timeout(SELECTED_PROVIDER_REFRESH_WAIT, notified)
                .await
                .map_err(|_| {
                    ProviderError::Configuration(
                        "selected provider refresh was not started after first paint; refusing inference before route admission"
                            .into(),
                    )
                })?;
        }

        // The post-paint settler owns this mutex through its bounded refresh attempt. Waiting for
        // it means inference cannot race ahead of route admission. `Pending` after that bound is
        // usable only because `build` already validated the cached/static/operator-explicit route;
        // a route with no such evidence never constructs this wrapper.
        let state = self.state.lock().await;
        match &*state {
            DeferredState::Settled(_) | DeferredState::Pending(_) => Ok(()),
            DeferredState::Dormant(_) => Err(ProviderError::Configuration(
                "selected provider refresh remained dormant; refusing unproved route".into(),
            )),
            DeferredState::Abandoned => Err(ProviderError::Configuration(
                "selected provider refresh failed before route admission".into(),
            )),
        }
    }
}

/// A provider selected from local evidence while its network catalog/account refresh is dormant.
/// Pure capability queries remain immediate, but the first paid turn cannot overtake the TUI's
/// post-paint refresh signal and bounded route-admission attempt.
struct PostPaintAdmittedProvider {
    inner: Arc<dyn Provider>,
    deferred: Arc<ProviderDiscoveryOwner>,
}

#[async_trait::async_trait]
impl Provider for PostPaintAdmittedProvider {
    fn physical_input_token_ceiling(&self, model: &str) -> Option<u64> {
        self.inner.physical_input_token_ceiling(model)
    }

    fn usage_bound_semantics(&self) -> iteron_provider::ProviderUsageBoundSemantics {
        self.inner.usage_bound_semantics()
    }

    fn provider_instance_id(&self) -> Option<&str> {
        self.inner.provider_instance_id()
    }

    fn attempt_semantics(&self) -> ProviderAttemptSemantics {
        self.inner.attempt_semantics()
    }

    fn supports_image_input(&self) -> bool {
        self.inner.supports_image_input()
    }

    fn control_capabilities(&self) -> ProviderControlCapabilities {
        self.inner.control_capabilities()
    }

    fn physical_output_token_ceiling(
        &self,
        budget: iteron_provider::output_ceiling::ProviderOutputBudget<'_>,
    ) -> Result<Option<u32>, ProviderError> {
        self.inner.physical_output_token_ceiling(budget)
    }

    fn effort_application(&self, req: &TurnRequest) -> EffortApplication {
        self.inner.effort_application(req)
    }

    fn run_notice(&self, req: &TurnRequest) -> Option<ProviderNotice> {
        self.inner.run_notice(req)
    }

    fn preflight_notice(&self, req: &TurnRequest) -> Option<ProviderNotice> {
        self.inner.preflight_notice(req)
    }

    async fn turn(
        &self,
        req: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        self.deferred.await_selected_route_admission().await?;
        self.inner.turn(req, on_item).await
    }

    async fn turn_observed(
        &self,
        req: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
        observer: &dyn iteron_provider::request_capture::ProviderRequestObserver,
    ) -> Result<TurnResult, ProviderError> {
        self.deferred.await_selected_route_admission().await?;
        self.inner.turn_observed(req, on_item, observer).await
    }
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;
