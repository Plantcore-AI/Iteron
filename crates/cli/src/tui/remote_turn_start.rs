//! One retained client request identity. Receipts observe admission; they never prove Applied.
use iteron_protocol::{RunId, SessionId, SubmissionId, product_contract::PRODUCT_CONTRACT_VERSION};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const OBSERVATION_WINDOW: Duration = Duration::from_secs(5);
const MAX_POLLS: u8 = 20;

pub(super) struct StartRequest {
    key: String,
    thread: SessionId,
    run: RunId,
    pub(super) draft: String,
    pub(super) revision: u64,
    deadline: Instant,
    poll_period: Duration,
    next_poll: Option<Instant>,
    polls: u8,
    definitely_refused: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StartReply {
    Accepted(SubmissionId),
    Pending,
    Unconfirmed,
    Refused,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Poll {
    Idle,
    Query,
    Expired,
}

impl StartRequest {
    pub(super) fn new(
        thread: SessionId,
        run: RunId,
        draft: String,
        revision: u64,
        now: Instant,
        poll_period: Duration,
    ) -> Result<Self, &'static str> {
        if thread.0.is_empty()
            || thread.0.len() > 256
            || draft.trim().is_empty()
            || draft.len() > 64 * 1024
        {
            return Err("turn-start input exceeds the client contract");
        }
        let draft = draft.into_boxed_str().into_string();
        let milliseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "turn-start clock unavailable")?
            .as_millis();
        if milliseconds >= 1u128 << 48 {
            return Err("turn-start clock exceeds UUIDv7 range");
        }
        let mut uuid = [0u8; 16];
        getrandom::fill(&mut uuid).map_err(|_| "turn-start identity entropy unavailable")?;
        uuid[..6].copy_from_slice(&(milliseconds as u64).to_be_bytes()[2..]);
        uuid[6] = (uuid[6] & 0x0f) | 0x70;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        let mut digest = Sha256::new();
        digest.update(uuid);
        digest.update((thread.0.len() as u64).to_be_bytes());
        digest.update(thread.0.as_bytes());
        digest.update((draft.len() as u64).to_be_bytes());
        digest.update(draft.as_bytes());
        let raw = hex::encode(uuid);
        let key = format!(
            "{}-{}-{}-{}-{}:{}",
            &raw[..8],
            &raw[8..12],
            &raw[12..16],
            &raw[16..20],
            &raw[20..],
            hex::encode(digest.finalize())
        );
        Ok(Self {
            key,
            thread,
            run,
            draft,
            revision,
            deadline: now + OBSERVATION_WINDOW,
            poll_period,
            next_poll: None,
            polls: 0,
            definitely_refused: false,
        })
    }

    pub(super) fn matches(&self, thread: &SessionId, run: &RunId, draft: &str) -> bool {
        &self.thread == thread && &self.run == run && self.draft == draft
    }

    pub(super) fn can_replace(&self) -> bool {
        self.definitely_refused
    }

    /// Only an explicit operator retry opens another bounded observation window. Identity and
    /// the original editor revision remain unchanged, even if the editor was subsequently edited.
    pub(super) fn retry(&mut self, now: Instant) {
        self.deadline = now + OBSERVATION_WINDOW;
        self.next_poll = None;
        self.polls = 0;
        self.definitely_refused = false;
    }

    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) fn command(&self) -> Value {
        json!({"type":"turn_start","thread_id":self.thread,"request_key":self.key,"text":self.draft})
    }

    pub(super) fn stop_observing(&mut self) {
        self.next_poll = None;
    }

    pub(super) fn poll(&mut self, now: Instant) -> Poll {
        let Some(due) = self.next_poll else {
            return Poll::Idle;
        };
        if now >= self.deadline || self.polls >= MAX_POLLS {
            self.next_poll = None;
            return Poll::Expired;
        }
        if now < due {
            return Poll::Idle;
        }
        self.polls += 1;
        self.next_poll = None;
        Poll::Query
    }

    pub(super) fn reply(
        &mut self,
        reply: &Value,
        now: Instant,
    ) -> Result<StartReply, &'static str> {
        if reply["contract_version"] != PRODUCT_CONTRACT_VERSION || reply["request_key"] != self.key
        {
            return Err("turn-start receipt version or request identity changed");
        }
        if reply["type"] == "turn_start_refused_v2" {
            let definite = reply["definitely_unregistered"]
                .as_bool()
                .ok_or("turn-start refusal registration truth unavailable")?;
            if !matches!(
                reply["reason_code"].as_str(),
                Some(
                    "request_conflict"
                        | "invalid_request_key"
                        | "request_key_expired"
                        | "request_key_in_future"
                        | "invalid_turn_text"
                        | "thread_unavailable"
                        | "turn_active"
                        | "capacity_full"
                        | "busy"
                        | "rate_limited"
                        | "runtime_disconnected"
                )
            ) {
                return Err("turn-start refusal reason unavailable");
            }
            self.next_poll = None;
            self.definitely_refused = definite;
            return Ok(StartReply::Refused);
        }
        if reply["type"] != "turn_start_receipt_v2" || reply["thread_id"] != self.thread.0 {
            return Err("turn-start receipt type or thread changed");
        }
        let closed = reply["window_closed"]
            .as_bool()
            .ok_or("turn-start window truth unavailable")?;
        let state = reply["state"]
            .as_str()
            .ok_or("turn-start state unavailable")?;
        if !matches!(
            state,
            "pending"
                | "admitted"
                | "running"
                | "completed"
                | "interrupted"
                | "drained"
                | "budget_exhausted"
                | "stuck"
                | "failed"
                | "unknown"
                | "admission_unknown"
        ) {
            return Err("turn-start state is unsupported");
        }
        let identity_absent = reply["submission_id"].is_null()
            && reply["run_id"].is_null()
            && reply["turn_id"].is_null();
        let id = if identity_absent {
            None
        } else {
            let id = reply["submission_id"]
                .as_u64()
                .filter(|id| *id > 0)
                .ok_or("turn-start submission identity unavailable")?;
            if reply["run_id"] != self.run.0 || reply["turn_id"].as_u64().is_none_or(|id| id == 0) {
                return Err("turn-start run or turn identity changed");
            }
            Some(SubmissionId(id))
        };
        self.next_poll = None;
        self.definitely_refused = false;
        if state == "admission_unknown" {
            if id.is_some() {
                return Err("unconfirmed admission carried an execution identity");
            }
            return Ok(StartReply::Unconfirmed);
        }
        if let Some(id) = id {
            return Ok(StartReply::Accepted(id));
        }
        if state != "pending" {
            return Err("admitted turn-start receipt has no execution identity");
        }
        if closed || now >= self.deadline || self.polls >= MAX_POLLS {
            return Ok(StartReply::Unconfirmed);
        }
        self.next_poll = Some(now + self.poll_period);
        Ok(StartReply::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const POLL_PERIOD: Duration = Duration::from_millis(250);
    fn sample_request(now: Instant) -> StartRequest {
        StartRequest::new(
            SessionId("thread".into()),
            RunId("run".into()),
            "  后续任务\n".into(),
            7,
            now,
            POLL_PERIOD,
        )
        .unwrap()
    }
    fn receipt(request: &StartRequest, state: &str) -> Value {
        json!({"type":"turn_start_receipt_v2","contract_version":PRODUCT_CONTRACT_VERSION,
            "request_key":request.key,"thread_id":request.thread,"state":state,
            "submission_id":null,"run_id":null,"turn_id":null,"window_closed":false})
    }
    #[test]
    fn exact_utf8_key_is_accepted_by_authority_and_explicit_retry_reuses_identity() {
        let now = Instant::now();
        let mut request = sample_request(now);
        let key = request.command()["request_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let prepared =
            iteron_record::turn_start_store::prepare(&key, &request.thread, &request.draft)
                .unwrap();
        assert_eq!(prepared.request_key(), key);
        assert!(
            iteron_record::turn_start_store::prepare(&key, &request.thread, request.draft.trim())
                .is_err()
        );
        assert!(
            iteron_record::turn_start_store::prepare(
                &key,
                &SessionId("other".into()),
                &request.draft
            )
            .is_err()
        );
        request.retry(now + Duration::from_secs(10));
        assert_eq!(request.command()["request_key"], key);
        assert_eq!(request.command()["text"], "  后续任务\n");
        assert_eq!(request.revision, 7);
        assert_ne!(sample_request(now).command()["request_key"], key);
    }
    #[test]
    fn pending_reobservation_is_same_key_and_stops_at_original_deadline() {
        let now = Instant::now();
        let mut request = sample_request(now);
        let wire = request.command();
        let pending = receipt(&request, "pending");
        assert_eq!(request.reply(&pending, now).unwrap(), StartReply::Pending);
        assert_eq!(request.poll(now + Duration::from_millis(249)), Poll::Idle);
        assert_eq!(request.poll(now + POLL_PERIOD), Poll::Query);
        assert_eq!(request.command(), wire);
        assert_eq!(
            request.reply(&pending, now + POLL_PERIOD).unwrap(),
            StartReply::Pending
        );
        assert_eq!(request.poll(now + OBSERVATION_WINDOW), Poll::Expired);
        assert_eq!(
            request.poll(now + OBSERVATION_WINDOW + POLL_PERIOD),
            Poll::Idle
        );
        let unknown = receipt(&request, "admission_unknown");
        assert_eq!(
            request.reply(&unknown, now).unwrap(),
            StartReply::Unconfirmed
        );
        assert_eq!(request.poll(now + POLL_PERIOD), Poll::Idle);

        let faster_period = Duration::from_millis(5);
        let mut faster = StartRequest::new(
            SessionId("thread".into()),
            RunId("run".into()),
            "next task".into(),
            8,
            now,
            faster_period,
        )
        .unwrap();
        let pending = receipt(&faster, "pending");
        assert_eq!(faster.reply(&pending, now).unwrap(), StartReply::Pending);
        assert_eq!(faster.poll(now + Duration::from_millis(4)), Poll::Idle);
        for count in 1..=20 {
            let at = now + faster_period * count;
            assert_eq!(faster.poll(at), Poll::Query);
            assert_eq!(
                faster.reply(&pending, at).unwrap(),
                if count == 20 {
                    StartReply::Unconfirmed
                } else {
                    StartReply::Pending
                }
            );
        }
        assert_eq!(faster.poll(now + Duration::from_millis(105)), Poll::Idle);
    }
    #[test]
    fn refusal_and_foreign_receipts_never_claim_admission_or_enable_automatic_retry() {
        let now = Instant::now();
        let mut request = sample_request(now);
        let mut admitted = receipt(&request, "running");
        admitted["submission_id"] = json!(9);
        admitted["run_id"] = json!("run");
        admitted["turn_id"] = json!(2);
        for (field, value) in [
            ("contract_version", json!(1)),
            ("request_key", json!("other")),
            ("thread_id", json!("other")),
            ("run_id", json!("other")),
            ("submission_id", json!(0)),
            ("turn_id", json!(0)),
        ] {
            let mut foreign = admitted.clone();
            foreign[field] = value;
            assert!(request.reply(&foreign, now).is_err(), "{field}");
        }
        let refused = json!({"type":"turn_start_refused_v2","contract_version":PRODUCT_CONTRACT_VERSION,
            "request_key":request.key,"reason_code":"turn_active","definitely_unregistered":true});
        assert_eq!(request.reply(&refused, now).unwrap(), StartReply::Refused);
        assert!(request.can_replace());
        assert_eq!(request.poll(now + POLL_PERIOD), Poll::Idle);
        assert_eq!(
            request.reply(&admitted, now).unwrap(),
            StartReply::Accepted(SubmissionId(9))
        );
    }
}
