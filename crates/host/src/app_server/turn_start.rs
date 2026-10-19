//! Durable product-start custody between public clients, the SQ and the resident runtime.
//!
//! Queue receipts never authorize execution. A new V2 turn crosses the record authority's
//! atomic admission before its first runtime poll; duplicate and recovery receipts only observe.

use super::{AppServerClient, SubmitError};
use iteron_protocol::product_contract::{PRODUCT_CONTRACT_VERSION, ProductTurnId, TurnStateV1};
use iteron_protocol::{Outcome, RunId, SessionId, SubmissionId, TenantId};
use iteron_record::turn_start_store::{
    AdmissionIdentity, PreparedRequest, RefusalReason, Reservation, StoreDecision, StoreReceipt,
    StoreRefusal, StoreState, TerminalState, TurnStartStore, prepare,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
const MAX_IN_FLIGHT: usize = 32;
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |now| u64::try_from(now.as_millis()).unwrap_or(u64::MAX))
}

/// Lazily opened at resident admission. Generic and keyed turns share one durable ID allocator;
/// one-shot runtime calls without a product turn do not create a product authority.
pub(super) struct TurnStartService {
    root: PathBuf,
    tenant: TenantId,
    store: OnceLock<TurnStartStore>,
    pending: Mutex<PendingCustody>,
}

struct PendingCustody {
    alive: bool,
    entries: BTreeMap<u64, PendingStart>,
}

struct PendingStart {
    reservation: Reservation,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
impl PendingStart {
    fn can_start(&self) -> bool {
        Instant::now() < self.deadline && !self.cancelled.load(Ordering::Acquire)
    }
}

impl std::fmt::Debug for TurnStartService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnStartService").finish_non_exhaustive()
    }
}

impl TurnStartService {
    pub(super) fn new(root: PathBuf, tenant: TenantId) -> Self {
        Self {
            root,
            tenant,
            store: OnceLock::new(),
            pending: Mutex::new(PendingCustody {
                alive: true,
                entries: BTreeMap::new(),
            }),
        }
    }

    pub(super) fn matches(&self, root: &Path, tenant: &TenantId) -> bool {
        self.root == root && &self.tenant == tenant
    }

    fn store(&self) -> Result<&TurnStartStore, ()> {
        if let Some(store) = self.store.get() {
            return Ok(store);
        }
        // A transient open failure is not a permanent in-memory unknown. A same-key retry must
        // be able to re-read the repaired authority; concurrent successful opens are equivalent.
        let store = TurnStartStore::open(&self.root, &self.tenant).map_err(|_| ())?;
        let _ = self.store.set(store);
        self.store.get().ok_or(())
    }

    pub(super) fn runtime_custody(self: &Arc<Self>) -> RuntimeCustody {
        RuntimeCustody(self.clone())
    }

    pub(super) fn is_pending(&self, id: SubmissionId) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .contains_key(&id.0)
    }

    pub(super) fn allocate_product_turn(
        &self,
        candidate: ProductTurnId,
    ) -> Result<ProductTurnId, ()> {
        self.store()?
            .allocate_product_turn(candidate, now_ms())
            .map_err(|_| ())
    }

    fn submit(
        &self,
        client: &AppServerClient,
        request: PreparedRequest,
        text: String,
        cancelled: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Value {
        let Ok(store) = self.store() else {
            return unknown(&request);
        };
        // The root-wide admission guard remains held by this physical request, including when
        // an async caller times out while its bounded blocking operation is still unwinding.
        let _ingress = match store.enter_request(&request, now_ms()) {
            Ok(guard) => guard,
            Err(decision) => return decision_value(decision, &request),
        };
        match store.lookup(&request, now_ms()) {
            StoreDecision::Vacant => {}
            decision => return decision_value(decision, &request),
        }
        let Some(snapshot) = client.thread_snapshot_v1() else {
            return refused(
                Some(request.request_key()),
                RefusalReason::ThreadUnavailable,
                false,
            );
        };
        if &snapshot.thread_id != request.thread_id() {
            return refused(
                Some(request.request_key()),
                RefusalReason::ThreadUnavailable,
                false,
            );
        }
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            return unknown(&request);
        }
        let active = snapshot
            .turn
            .as_ref()
            .is_some_and(|turn| turn.state == TurnStateV1::Running);
        let reservation = match store.reserve(&request, &snapshot.run_id, active, now_ms()) {
            StoreDecision::Reserved(reservation) => *reservation,
            decision => return decision_value(decision, &request),
        };
        // Hold this lock across enqueue and attachment: the runtime can receive on another
        // worker immediately, but cannot mistake a V2 envelope for an ordinary submission.
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !pending.alive || cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            return decision_value(
                store.release_pending(&reservation, RefusalReason::RuntimeDisconnected, now_ms()),
                &request,
            );
        }
        match client.submit_identified(iteron_protocol::Op::UserInput { text }) {
            Ok(id) => {
                pending.entries.insert(
                    id.0,
                    PendingStart {
                        reservation,
                        deadline,
                        cancelled,
                    },
                );
            }
            Err(error) => {
                let reason = match error {
                    SubmitError::Busy => RefusalReason::Busy,
                    SubmitError::Disconnected => RefusalReason::RuntimeDisconnected,
                };
                return decision_value(
                    store.release_pending(&reservation, reason, now_ms()),
                    &request,
                );
            }
        }
        drop(pending);
        decision_value(store.lookup(&request, now_ms()), &request)
    }

    pub(super) fn reject_pending(&self, id: SubmissionId) {
        let reservation = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .remove(&id.0);
        if let Some(pending) = reservation
            && let Ok(store) = self.store()
        {
            let _ = store.release_pending(
                &pending.reservation,
                RefusalReason::RuntimeDisconnected,
                now_ms(),
            );
        }
    }

    pub(super) fn admit(
        self: &Arc<Self>,
        id: SubmissionId,
        run_id: &RunId,
        candidate_turn: ProductTurnId,
    ) -> Result<Option<ProductExecution>, ()> {
        let reservation = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .remove(&id.0);
        let Some(pending) = reservation else {
            return Ok(None);
        };
        let reservation = &pending.reservation;
        if reservation.target_run() != run_id {
            return Err(());
        }
        let store = self.store()?;
        if !pending.can_start() {
            let _ =
                store.release_pending(reservation, RefusalReason::RuntimeDisconnected, now_ms());
            return Err(());
        }
        let identity = AdmissionIdentity {
            run_id: run_id.clone(),
            submission_id: id,
            turn_id: candidate_turn,
        };
        let StoreDecision::Admitted(receipt) = store.admit(reservation, identity, now_ms()) else {
            return Err(());
        };
        let Some(identity) = receipt.identity else {
            return Err(());
        };
        if !pending.can_start() {
            let _ = store.abandon(reservation.request(), &identity, now_ms());
            return Err(());
        }
        let execution = ProductExecution {
            service: self.clone(),
            reservation: pending.reservation,
            identity,
            deadline: pending.deadline,
            cancelled: pending.cancelled,
            started: AtomicBool::new(false),
        };
        Ok(Some(execution))
    }
}

/// Client handles can outlive a dead runtime. Only the runtime's lifetime may retain queued
/// reservations; dropping this guard releases their live leases without claiming admission.
pub(super) struct RuntimeCustody(Arc<TurnStartService>);
impl Drop for RuntimeCustody {
    fn drop(&mut self) {
        let mut pending = self
            .0
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.alive = false;
        pending.entries.clear();
    }
}

/// The reservation's kernel owner lease proves this exact runtime still owns the live turn.
/// Dropping it before a durable terminal makes recovery unknown and retains thread occupancy.
pub(super) struct ProductExecution {
    service: Arc<TurnStartService>,
    reservation: Reservation,
    identity: AdmissionIdentity,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    started: AtomicBool,
}
impl ProductExecution {
    pub(super) fn turn_id(&self) -> ProductTurnId {
        self.identity.turn_id
    }

    pub(super) fn begin(&self) -> bool {
        if self.started.load(Ordering::Acquire) {
            return true;
        }
        if Instant::now() >= self.deadline || self.cancelled.load(Ordering::Acquire) {
            return false;
        }
        let Ok(store) = self.service.store() else {
            return false;
        };
        let running = matches!(store.mark_running(self.reservation.request(), &self.identity, now_ms()),
            StoreDecision::Receipt(StoreReceipt { state:StoreState::Running,identity:Some(ref identity),.. })
            if identity == &self.identity);
        if !running || Instant::now() >= self.deadline || self.cancelled.load(Ordering::Acquire) {
            return false;
        }
        self.started.store(true, Ordering::Release);
        true
    }

    pub(super) fn finish(self, outcome: &Outcome, cleanup_known: bool) -> bool {
        let Ok(store) = self.service.store() else {
            return false;
        };
        if !cleanup_known || !self.started.load(Ordering::Acquire) {
            let _ = store.abandon(self.reservation.request(), &self.identity, now_ms());
            return false;
        }
        let terminal = match outcome {
            Outcome::Done => TerminalState::Completed,
            Outcome::Interrupted => TerminalState::Interrupted,
            Outcome::Drained => TerminalState::Drained,
            Outcome::BudgetExhausted(_) => TerminalState::BudgetExhausted,
            Outcome::Stuck => TerminalState::Stuck,
            Outcome::HarnessError => TerminalState::Failed,
        };
        matches!(store.finish(self.reservation.request(), &self.identity, terminal, now_ms()),
            StoreDecision::Receipt(StoreReceipt { state, identity: Some(ref identity), .. })
            if identity == &self.identity && state == terminal.into())
    }
}

struct InFlight;
impl InFlight {
    fn acquire() -> Option<Self> {
        IN_FLIGHT
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_IN_FLIGHT).then_some(count + 1)
            })
            .ok()
            .map(|_| Self)
    }
}
impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}
struct CancelOnDrop {
    signal: Arc<AtomicBool>,
    armed: bool,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.signal.store(true, Ordering::Release);
        }
    }
}

impl AppServerClient {
    pub fn turn_start_v2(&self, thread: SessionId, key: String, text: String) -> Value {
        let request = match prepare(&key, &thread, &text) {
            Ok(request) => request,
            Err(error) => return refusal_value(error),
        };
        let Some(service) = self.contract.turn_start_service() else {
            return unknown(&request);
        };
        service.submit(
            self,
            request,
            text,
            Arc::new(AtomicBool::new(false)),
            Instant::now() + REQUEST_DEADLINE,
        )
    }

    pub async fn turn_start_v2_async(&self, thread: SessionId, key: String, text: String) -> Value {
        // Digest conflict has precedence even over ingress rate/concurrency limits.
        let request = match prepare(&key, &thread, &text) {
            Ok(request) => request,
            Err(error) => return refusal_value(error),
        };
        let Some(slot) = InFlight::acquire() else {
            return refused(Some(&key), RefusalReason::RateLimited, false);
        };
        let Some(service) = self.contract.turn_start_service() else {
            return unknown(&request);
        };
        let client = self.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut guard = CancelOnDrop {
            signal: cancelled.clone(),
            armed: true,
        };
        let deadline = Instant::now() + REQUEST_DEADLINE;
        let work_request = request.clone();
        let work = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            service.submit(&client, work_request, text, cancelled, deadline)
        });
        let result = match tokio::time::timeout(REQUEST_DEADLINE, work).await {
            Ok(Ok(reply)) => {
                guard.armed = false;
                reply
            }
            _ => unknown(&request),
        };
        drop(guard);
        result
    }
}

fn decision_value(decision: StoreDecision, request: &PreparedRequest) -> Value {
    match decision {
        StoreDecision::Receipt(receipt) | StoreDecision::Admitted(receipt) => {
            receipt_value(receipt)
        }
        StoreDecision::Refused(error) => refusal_value(error),
        // A caller can observe this only when no live queue custody can be established.
        StoreDecision::Vacant | StoreDecision::Reserved(_) => unknown(request),
    }
}
fn receipt_value(receipt: StoreReceipt) -> Value {
    json!({"type":"turn_start_receipt_v2", "contract_version":PRODUCT_CONTRACT_VERSION,
        "request_key":receipt.request_key, "thread_id":receipt.thread_id, "state":receipt.state,
        "submission_id":receipt.identity.as_ref().map(|identity| identity.submission_id),
        "run_id":receipt.identity.as_ref().map(|identity| &identity.run_id),
        "turn_id":receipt.identity.as_ref().map(|identity| identity.turn_id), "window_closed":receipt.window_closed})
}
fn refusal_value(error: StoreRefusal) -> Value {
    refused(
        error.request_key.as_deref(),
        error.reason,
        error.definitely_unregistered,
    )
}
fn refused(key: Option<&str>, reason: RefusalReason, definitely_unregistered: bool) -> Value {
    json!({"type":"turn_start_refused_v2", "contract_version":PRODUCT_CONTRACT_VERSION,
        "request_key":key,"reason_code":reason.as_str(),"definitely_unregistered":definitely_unregistered})
}
fn unknown(request: &PreparedRequest) -> Value {
    receipt_value(StoreReceipt {
        request_key: request.request_key().into(),
        thread_id: request.thread_id().clone(),
        state: StoreState::AdmissionUnknown,
        identity: None,
        window_closed: request.window_closed(now_ms()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::AtomicU64;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "iteron-product-custody-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn client() -> (
        AppServerClient,
        tokio::sync::mpsc::Receiver<crate::runtime::TurnSubmission>,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let client = AppServerClient::connect(iteron_protocol::PROTOCOL_VERSION, sender).unwrap();
        client.seed_contract_identity_for_test(
            SessionId("session-custody".into()),
            RunId("custody-run".into()),
        );
        (client, receiver)
    }
    fn fixture_request(salt: u8) -> PreparedRequest {
        let timestamp = now_ms();
        let mut uuid = [0u8; 16];
        uuid[..6].copy_from_slice(&timestamp.to_be_bytes()[2..]);
        uuid[6] = 0x70;
        uuid[8] = 0x80;
        uuid[15] = salt;
        let id = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            uuid[0],
            uuid[1],
            uuid[2],
            uuid[3],
            uuid[4],
            uuid[5],
            uuid[6],
            uuid[7],
            uuid[8],
            uuid[9],
            uuid[10],
            uuid[11],
            uuid[12],
            uuid[13],
            uuid[14],
            uuid[15]
        );
        let thread = SessionId("session-custody".into());
        let text = "read the synthetic fixture";
        let mut hash = Sha256::new();
        hash.update(uuid);
        hash.update((thread.0.len() as u64).to_be_bytes());
        hash.update(thread.0.as_bytes());
        hash.update((text.len() as u64).to_be_bytes());
        hash.update(text.as_bytes());
        prepare(&format!("{id}:{:x}", hash.finalize()), &thread, text).unwrap()
    }
    fn queued(
        service: &Arc<TurnStartService>,
        client: &AppServerClient,
        request: &PreparedRequest,
    ) -> Value {
        service.submit(
            client,
            request.clone(),
            "read the synthetic fixture".into(),
            Arc::new(AtomicBool::new(false)),
            Instant::now() + REQUEST_DEADLINE,
        )
    }

    #[test]
    fn dead_runtime_releases_pending_custody_even_when_clients_and_service_live() {
        let fixture = Fixture::new();
        let service = Arc::new(TurnStartService::new(
            fixture.0.clone(),
            TenantId("custody-tenant".into()),
        ));
        let guard = service.runtime_custody();
        let (client, mut receiver) = client();
        let request = fixture_request(1);
        assert_eq!(queued(&service, &client, &request)["state"], "pending");
        assert!(receiver.try_recv().is_ok());
        drop(guard);
        assert!(matches!(
            service.store().unwrap().lookup(&request, now_ms()),
            StoreDecision::Vacant
        ));
        // A late blocking request cannot attach a fresh reservation after runtime teardown.
        let retry = queued(&service, &client, &request);
        assert_eq!(retry["reason_code"], "runtime_disconnected");
        assert_eq!(retry["definitely_unregistered"], true);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn cancelled_or_expired_pending_requests_never_obtain_execution_authority() {
        let fixture = Fixture::new();
        let service = Arc::new(TurnStartService::new(
            fixture.0.clone(),
            TenantId("custody-tenant".into()),
        ));
        let _guard = service.runtime_custody();
        let (client, mut receiver) = client();
        for (salt, cancel) in [(2, false), (3, true)] {
            let request = fixture_request(salt);
            assert_eq!(queued(&service, &client, &request)["state"], "pending");
            let envelope = receiver.try_recv().unwrap();
            {
                let mut pending = service.pending.lock().unwrap();
                let work = pending.entries.get_mut(&envelope.submission_id.0).unwrap();
                if cancel {
                    work.cancelled.store(true, Ordering::Release);
                } else {
                    work.deadline = Instant::now();
                }
            }
            assert!(
                service
                    .admit(
                        envelope.submission_id,
                        &RunId("custody-run".into()),
                        ProductTurnId(1)
                    )
                    .is_err()
            );
            assert!(matches!(
                service.store().unwrap().lookup(&request, now_ms()),
                StoreDecision::Vacant
            ));
        }
    }

    #[test]
    fn admitted_but_unstarted_or_unclean_turns_keep_unknown_thread_occupancy() {
        for (salt, begin) in [(4, false), (5, true)] {
            let fixture = Fixture::new();
            let service = Arc::new(TurnStartService::new(
                fixture.0.clone(),
                TenantId("custody-tenant".into()),
            ));
            let _guard = service.runtime_custody();
            let (client, mut receiver) = client();
            let request = fixture_request(salt);
            assert_eq!(queued(&service, &client, &request)["state"], "pending");
            let envelope = receiver.try_recv().unwrap();
            let execution = service
                .admit(
                    envelope.submission_id,
                    &RunId("custody-run".into()),
                    ProductTurnId(1),
                )
                .unwrap()
                .unwrap();
            if begin {
                assert!(execution.begin());
            }
            assert!(!execution.finish(&Outcome::HarnessError, !begin));
            assert!(matches!(
                service.store().unwrap().lookup(&request, now_ms()),
                StoreDecision::Receipt(StoreReceipt {
                    state: StoreState::Unknown,
                    identity: Some(_),
                    ..
                })
            ));
            let next = fixture_request(salt + 10);
            assert!(matches!(
                service.store().unwrap().reserve(
                    &next,
                    &RunId("custody-run".into()),
                    false,
                    now_ms()
                ),
                StoreDecision::Refused(StoreRefusal {
                    reason: RefusalReason::TurnActive,
                    ..
                })
            ));
        }
    }

    #[test]
    fn transient_authority_open_failure_can_be_recovered_by_same_service() {
        let fixture = Fixture::new();
        let root = fixture.0.join("temporarily-unavailable");
        std::fs::write(&root, b"not a directory").unwrap();
        let service = TurnStartService::new(root.clone(), TenantId("custody-tenant".into()));
        assert!(service.store().is_err());
        std::fs::remove_file(&root).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert!(service.store().is_ok());
    }
}
