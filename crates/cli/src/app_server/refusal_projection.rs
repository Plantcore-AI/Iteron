//! Bounded live provenance. Historical/opaque error strings never identify an authority.
use super::ControlReply;
use iteron_protocol::client_refusal::RefusalsReadV1;
use iteron_protocol::refusal::{HostRefusalV1, RefusalReasonV1};
use iteron_protocol::{RunId, SessionId, TenantId};
use serde_json::{Value, json};
use std::collections::VecDeque;
const MAX_REFUSALS: usize = 64;
const MAX_SUBJECT_BYTES: usize = 2048;
#[derive(Default)]
pub(super) struct RefusalReader {
    scope: Option<(SessionId, TenantId, RunId)>,
    rows: VecDeque<(u64, HostRefusalV1)>,
    omitted: u64,
}
impl RefusalReader {
    pub(super) fn bind(&mut self, thread: SessionId, tenant: TenantId, run: RunId) {
        if self
            .scope
            .as_ref()
            .is_some_and(|(t, a, b)| *t == thread && *a == tenant && *b == run)
        {
            return;
        }
        self.scope = Some((thread, tenant, run));
        self.rows.clear();
        self.omitted = 0;
    }
    pub(super) fn observe(&mut self, eq_sequence: u64, observation: &HostRefusalV1) -> bool {
        let Some((_, tenant, run)) = &self.scope else {
            return false;
        };
        if eq_sequence == 0
            || observation
                .tool
                .as_ref()
                .is_some_and(|v| v.len() > MAX_SUBJECT_BYTES)
            || observation
                .tool_use_id
                .as_ref()
                .is_some_and(|v| v.len() > MAX_SUBJECT_BYTES)
            || observation.source.as_ref().is_some_and(|source| {
                source.tenant != *tenant || source.run_id != *run || source.sequence.0 == 0
            })
        {
            return false;
        }
        if let Some((old, value)) = self.rows.back()
            && eq_sequence <= *old
        {
            return eq_sequence == *old && value == observation;
        }
        if self.rows.len() == MAX_REFUSALS {
            self.rows.pop_front();
            self.omitted = self.omitted.saturating_add(1);
        }
        self.rows.push_back((eq_sequence, observation.clone()));
        true
    }
    pub(super) fn read(&self, command: RefusalsReadV1) -> Value {
        if command.validate().is_err() {
            return json!({"type":"refusals_refused_v1","reason_code":"invalid_request"});
        }
        let Some((thread, _, run)) = &self.scope else {
            return json!({"type":"refusals_refused_v1","reason_code":"unavailable"});
        };
        if *thread != command.thread_id || *run != command.run_id {
            return json!({"type":"refusals_refused_v1","reason_code":"scope_mismatch"});
        }
        let rows=self.rows.iter().map(|(seq,value)|json!({"observation_sequence":seq,"origin":value.origin(),"summary":value.summary(),"refusal":value})).collect::<Vec<_>>();
        json!({"type":"refusals_snapshot_v1","thread_id":thread,"run_id":run,"observations":rows,"omitted":self.omitted,"source":"live_host_provenance","delivery":"bounded_snapshot_not_historical_error_reclassification"})
    }
}
impl ControlReply {
    pub(super) fn refused_by(error: &crate::runtime::KernelError) -> Self {
        Self::RefusedWithOrigin {
            message: error.public_summary(),
            refusal: Box::new(error.refusal_observation()),
        }
    }
}
pub(crate) fn reply_value(message: String, refusal: HostRefusalV1) -> Value {
    json!({"type":"refused","message":iteron_record::redact::scrub(&message),"origin":refusal.origin(),"refusal":refusal})
}
pub(crate) fn unknown_reply(message: String) -> Value {
    reply_value(message, HostRefusalV1::unscoped(RefusalReasonV1::Unknown))
}
pub(crate) fn heap_bytes(value: &HostRefusalV1) -> usize {
    512_usize
        .saturating_add(value.tool.as_ref().map_or(0, String::len))
        .saturating_add(value.tool_use_id.as_ref().map_or(0, String::len))
        .saturating_add(value.source.as_ref().map_or(0, |source| {
            source.tenant.0.len().saturating_add(source.run_id.0.len())
        }))
}
#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::refusal::{RefusalEffectStateV1, RefusalSourceV1};
    use iteron_protocol::{Seq, TurnId};
    #[test]
    fn exact_scope_receipt_and_opaque_text_remain_separate() {
        let mut reader = RefusalReader::default();
        reader.bind(
            SessionId("session-run".into()),
            TenantId::default(),
            RunId("run".into()),
        );
        let actual = HostRefusalV1 {
            reason: RefusalReasonV1::PermissionDenied,
            source: Some(RefusalSourceV1 {
                tenant: TenantId::default(),
                run_id: RunId("run".into()),
                turn: TurnId(0),
                sequence: Seq(9),
            }),
            tool: Some("write_file".into()),
            tool_use_id: Some("native-call".into()),
            effects: RefusalEffectStateV1::NotDispatched,
        };
        assert!(reader.observe(8, &actual));
        let mut foreign = actual.clone();
        foreign.source.as_mut().unwrap().run_id = RunId("foreign".into());
        assert!(!reader.observe(9, &foreign));
        let query = || RefusalsReadV1 {
            thread_id: SessionId("session-run".into()),
            run_id: RunId("run".into()),
        };
        assert_eq!(
            reader.read(query())["observations"][0]["origin"],
            "host_policy"
        );
        reader.bind(
            SessionId("session-run".into()),
            TenantId::default(),
            RunId("run".into()),
        );
        assert_eq!(
            reader.read(query())["observations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let opaque = unknown_reply("administrator denied / OS sandbox / user said no".into());
        assert_eq!(opaque["origin"], "unknown");
        assert!(opaque["refusal"]["source"].is_null());
        reader.bind(
            SessionId("session-other".into()),
            TenantId::default(),
            RunId("other".into()),
        );
        assert_eq!(reader.read(query())["reason_code"], "scope_mismatch");
    }

    #[test]
    fn bounded_live_reader_reports_omission_without_inventing_a_durable_cursor() {
        let mut reader = RefusalReader::default();
        reader.bind(
            SessionId("session-run".into()),
            TenantId::default(),
            RunId("run".into()),
        );
        let value = HostRefusalV1::unscoped(RefusalReasonV1::SandboxUnavailable);
        for sequence in 1..=65 {
            assert!(reader.observe(sequence, &value));
        }
        let query = RefusalsReadV1 {
            thread_id: SessionId("session-run".into()),
            run_id: RunId("run".into()),
        };
        let snapshot = reader.read(query);
        let rows = snapshot["observations"].as_array().unwrap();
        assert_eq!(rows.len(), 64);
        assert_eq!(snapshot["omitted"], 1);
        assert_eq!(rows[0]["observation_sequence"], 2);
        assert_eq!(rows[63]["observation_sequence"], 65);
        assert_eq!(rows[0]["refusal"]["effects"], "unavailable");
        assert!(rows[0]["refusal"]["source"].is_null());
        assert!(!reader.observe(64, &value));
        assert!(reader.observe(65, &value));
    }
}
