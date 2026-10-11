//! Session picker facts come from the same captured live Activity Center owners. Historical
//! records supply their recorded outcome; they cannot establish a live process or its creation run.
use super::picker::{PickAction, PickItem};
use iteron_protocol::{
    RunId,
    product_contract::{ThreadSnapshotV1, TurnStateV1},
};
use serde_json::Value;
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Observation {
    run: RunId,
    parent_running: bool,
    run_tasks: usize,
    resident_tasks: usize,
    unknown: usize,
    omitted: usize,
    changes: Option<super::session_changes::Summary>,
}
impl Observation {
    pub(super) fn capture(
        value: &Value,
        snapshot: &ThreadSnapshotV1,
    ) -> Result<Self, &'static str> {
        if value["type"] != "activity_center_v1"
            || value["thread_id"] != snapshot.thread_id.0
            || value["run_id"] != snapshot.run_id.0
        {
            return Err("live activity observation belongs to another scope");
        }
        let rows = value["data"]["activities"]
            .as_array()
            .filter(|rows| rows.len() <= 320)
            .ok_or("live owner activity unavailable")?;
        let mut observation = Self {
            run: snapshot.run_id.clone(),
            parent_running: snapshot
                .turn
                .as_ref()
                .is_some_and(|turn| turn.state == TurnStateV1::Running),
            run_tasks: 0,
            resident_tasks: 0,
            unknown: 0,
            omitted: value["data"]["omitted"]
                .as_u64()
                .and_then(|count| usize::try_from(count).ok())
                .ok_or("live omission count unavailable")?,
            changes: None,
        };
        for row in rows {
            let kind = row["target"]["kind"]
                .as_str()
                .ok_or("live activity kind unavailable")?;
            let resident = match kind {
                "process" | "workflow" | "mcp" => {
                    if row["owner_scope"]["kind"] != "resident_session"
                        || row["owner_scope"]["thread_id"] != snapshot.thread_id.0
                        || !row["owner_scope"]["creation_run_id"].is_null()
                    {
                        return Err("resident activity owner scope changed");
                    }
                    true
                }
                "persistent_agent" | "verifier" => {
                    if row["owner_scope"]["kind"] != "physical_run"
                        || row["owner_scope"]["run_id"] != snapshot.run_id.0
                    {
                        return Err("run activity owner scope changed");
                    }
                    false
                }
                _ => return Err("live activity kind is not understood"),
            };
            let active = match kind {
                "mcp" => row["details"]["busy"].as_bool(),
                "process" => closed_state(
                    row["state"]["kind"].as_str(),
                    &["running", "stopping"],
                    &[
                        "exited",
                        "stopped",
                        "timed_out",
                        "idle_stalled",
                        "output_limit_exceeded",
                        "io_failed",
                    ],
                ),
                "persistent_agent" => closed_state(
                    row["state"]["type"].as_str(),
                    &["running", "interrupting", "closing"],
                    &["idle", "closed"],
                ),
                "workflow" => closed_state(
                    row["state"].as_str(),
                    &["running", "cancelling"],
                    &["settled", "failed"],
                ),
                "verifier" => closed_state(
                    row["state"].as_str(),
                    &["admitted", "running"],
                    &["settled"],
                ),
                _ => None,
            };
            match active {
                Some(true) if resident => observation.resident_tasks += 1,
                Some(true) => observation.run_tasks += 1,
                Some(false) => {}
                None => observation.unknown += 1,
            };
        }
        Ok(observation)
    }
    pub(super) fn changes(&mut self, changes: Option<super::session_changes::Summary>) {
        self.changes = changes;
    }
    fn label(&self) -> String {
        format!(
            "live parent {} · run tasks {} · resident session tasks {} · unresolved states {} · omitted {} · {}",
            if self.parent_running {
                "running"
            } else {
                "idle"
            },
            self.run_tasks,
            self.resident_tasks,
            self.unknown,
            self.omitted,
            self.changes.map_or_else(
                || "retained changes unavailable".into(),
                |changes| changes.label()
            )
        )
    }
    pub(super) fn apply(&self, items: &mut [PickItem], run: &str, base: Option<&str>) {
        for item in items {
            if matches!(&item.action,PickAction::AdoptRun(id) if id==run) {
                item.hint = format!(
                    "{} · {}",
                    base.unwrap_or(&item.hint),
                    if self.run.0 == run {
                        self.label()
                    } else {
                        "live activity unavailable for this record".into()
                    }
                );
            }
        }
    }
}
fn closed_state(state: Option<&str>, active: &[&str], inactive: &[&str]) -> Option<bool> {
    match state {
        Some(state) if active.contains(&state) => Some(true),
        Some(state) if inactive.contains(&state) => Some(false),
        _ => None,
    }
}
pub(super) fn unavailable(items: &mut [PickItem], run: &str, base: Option<&str>) {
    for item in items {
        if matches!(&item.action,PickAction::AdoptRun(id) if id==run) {
            item.hint = format!("{} · live activity unavailable", base.unwrap_or(&item.hint));
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn snapshot() -> ThreadSnapshotV1 {
        ThreadSnapshotV1 {
            contract_version: 1,
            thread_id: iteron_protocol::SessionId("thread".into()),
            run_id: RunId("run".into()),
            source_event_seq: 7,
            turn: None,
            submissions: vec![],
            evicted_submissions: 0,
        }
    }
    #[test]
    fn current_run_and_resident_session_provenance_stay_distinct_from_recorded_outcomes() {
        let snapshot = snapshot();
        let mut value = json!({"type":"activity_center_v1","thread_id":"thread","run_id":"run","data":{"omitted":2,"activities":[
            {"target":{"kind":"persistent_agent"},"state":{"type":"running"},"owner_scope":{"kind":"physical_run","run_id":"run"}},
            {"target":{"kind":"process"},"state":{"kind":"cleanup_unknown"},"owner_scope":{"kind":"resident_session","thread_id":"thread","creation_run_id":null}},
            {"target":{"kind":"mcp"},"details":{"busy":true},"owner_scope":{"kind":"resident_session","thread_id":"thread","creation_run_id":null}}
        ]}});
        let observation = Observation::capture(&value, &snapshot).unwrap();
        assert_eq!(
            (
                observation.run_tasks,
                observation.resident_tasks,
                observation.unknown,
                observation.omitted
            ),
            (1, 1, 1, 2)
        );
        let mut rows = vec![
            PickItem::flat(
                "Current",
                "recorded done",
                true,
                PickAction::AdoptRun("run".into()),
            ),
            PickItem::flat(
                "Old",
                "recorded done",
                false,
                PickAction::AdoptRun("old".into()),
            ),
        ];
        observation.apply(&mut rows, "run", None);
        assert!(rows[0].hint.contains("recorded done"));
        assert!(rows[0].hint.contains("run tasks 1"));
        assert!(rows[0].hint.contains("resident session tasks 1"));
        assert_eq!(rows[1].hint, "recorded done");
        value["data"]["activities"][0]["owner_scope"]["run_id"] = json!("old");
        assert!(Observation::capture(&value, &snapshot).is_err());
        value["data"]["activities"][0]["owner_scope"]["run_id"] = json!("run");
        value["data"]["activities"][1]["owner_scope"]["creation_run_id"] = json!("run");
        assert!(Observation::capture(&value, &snapshot).is_err());
    }
}
