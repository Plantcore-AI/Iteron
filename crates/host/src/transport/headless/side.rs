//! Bounded public side-conversation observations. Physical records and provider execution remain
//! with the existing resident side owner; remote replies never disclose its record path.

use crate::runtime::{SideAnswer, SideStatus};
use iteron_protocol::Outcome;
use iteron_protocol::client_interaction::CLIENT_INTERACTION_VERSION;
use serde_json::{Value, json};

const MAX_ANSWER_BYTES: usize = 64 * 1024;

pub(super) fn status_value(status: Option<&SideStatus>, closed: bool) -> Value {
    json!({
        "type":"side_status_v1", "contract_version":CLIENT_INTERACTION_VERSION,
        "closed":closed, "status":status.map(status_fields),
        "source":"resident_side_owner",
    })
}

pub(super) fn answer_value(answer: &SideAnswer) -> Value {
    let safe = iteron_record::redact::scrub(&answer.text);
    let mut end = safe.len().min(MAX_ANSWER_BYTES);
    while !safe.is_char_boundary(end) {
        end -= 1;
    }
    let (outcome, budget_limit) = match &answer.outcome {
        Outcome::Done => ("done", None),
        Outcome::Interrupted => ("interrupted", None),
        Outcome::Drained => ("drained", None),
        Outcome::BudgetExhausted(limit) => ("budget_exhausted", Some(*limit)),
        Outcome::Stuck => ("stuck", None),
        Outcome::HarnessError => ("harness_error", None),
    };
    json!({
        "type":"side_answer_v1", "contract_version":CLIENT_INTERACTION_VERSION,
        "text":&safe[..end], "text_complete":end==safe.len(),
        "omitted_redacted_bytes":safe.len()-end,
        "outcome":outcome, "budget_limit":budget_limit,
        "status":status_fields(&answer.status), "source":"resident_side_owner",
    })
}

fn status_fields(status: &SideStatus) -> Value {
    json!({"side_run_id":status.run_id,"asks":status.asks,"turns":status.turns,"cost":status.cost})
}

#[cfg(test)]
mod tests {
    use super::{answer_value, status_value};
    use crate::runtime::{SideAnswer, SideStatus};
    use iteron_obs::CostState;
    use iteron_protocol::Outcome;

    fn status() -> SideStatus {
        SideStatus {
            run_id: "side-owned-run".into(),
            record_path: "/private/not-public/side.jsonl".into(),
            asks: 1,
            turns: 2,
            cost: CostState::Zero,
            ledger_summary: "private summary is not a public locator".into(),
        }
    }

    #[test]
    fn public_side_status_and_answer_preserve_owner_facts_without_a_file_locator() {
        let status = status();
        let view = status_value(Some(&status), true);
        assert_eq!(view["status"]["side_run_id"], status.run_id);
        assert_eq!(view["status"]["asks"], 1);
        assert_eq!(view["closed"], true);
        assert!(!view.to_string().contains("not-public"));
        assert!(!view.to_string().contains("ledger_summary"));
        assert!(status_value(None, false)["status"].is_null());
        let answer = answer_value(&SideAnswer {
            text: "the parser is unchanged".into(),
            outcome: Outcome::Interrupted,
            status,
        });
        assert_eq!(answer["outcome"], "interrupted");
        assert_eq!(answer["text_complete"], true);
        assert_eq!(answer["status"]["cost"]["status"], "zero");
    }

    #[test]
    fn public_side_answer_reports_redacted_byte_omission_without_splitting_unicode() {
        let answer = answer_value(&SideAnswer {
            text: "界".repeat(30_000),
            outcome: Outcome::Done,
            status: status(),
        });
        assert_eq!(answer["text_complete"], false);
        assert_eq!(answer["text"].as_str().unwrap().len(), 65_535);
        assert_eq!(answer["omitted_redacted_bytes"], 90_000 - 65_535);
        assert_eq!(answer["outcome"], "done");
    }
}
