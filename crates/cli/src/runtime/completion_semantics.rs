//! Completion rules that stay separate from provider wire stop reasons.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EmptyEndTurnDecision {
    Reject,
    RequireOracle,
    AcceptCandidateHandoff,
}

pub(super) const fn empty_end_turn_decision(
    has_oracle: bool,
    stable_candidate_handoff: bool,
) -> EmptyEndTurnDecision {
    if has_oracle {
        EmptyEndTurnDecision::RequireOracle
    } else if stable_candidate_handoff {
        EmptyEndTurnDecision::AcceptCandidateHandoff
    } else {
        EmptyEndTurnDecision::Reject
    }
}

/// Detect a provider end-turn that is prose about an immediate edit rather than a completed
/// handoff.  This is intentionally narrow: it needs both a first-person future marker and a
/// candidate-mutation word in the same sentence, and rejects explicit negation.  The runtime uses
/// it only once per automated run while mutation is still admissible and no candidate exists.
pub(super) fn commits_to_immediate_candidate_action(text: &str) -> bool {
    text.split(['.', '!', '?', '\n', '。', '！', '？'])
        .map(str::trim)
        .filter(|sentence| !sentence.is_empty())
        .any(|sentence| {
            let sentence = sentence.to_ascii_lowercase();
            let future = [
                "i will",
                "i'll",
                "next i will",
                "next, i will",
                "then i will",
                "next make",
                "then make",
            ]
            .iter()
            .any(|marker| sentence.contains(marker))
                || [
                    "我会",
                    "我将",
                    "接下来我",
                    "下一步我",
                    "现在我",
                    "随后做",
                    "接下来做",
                    "下一步做",
                    "现在做",
                ]
                .iter()
                .any(|marker| sentence.contains(marker));
            let candidate_action = [
                " edit",
                " modify",
                " apply",
                " implement",
                " patch",
                " change",
                " fix",
                "修改",
                "编辑",
                "应用补丁",
                "打补丁",
                "做最小补丁",
                "修复",
            ]
            .iter()
            .any(|marker| sentence.contains(marker));
            let negated_or_explanatory = [
                "will not",
                "won't",
                "cannot",
                "can't",
                "explain how",
                "describe how",
                "show how",
                "不会",
                "不再",
                "无法",
                "不能",
                "解释如何",
                "说明如何",
            ]
            .iter()
            .any(|marker| sentence.contains(marker));
            future && candidate_action && !negated_or_explanatory
        })
}

/// Future-action recovery must never turn an analysis/plan request into an implementation task.
pub(super) fn task_requests_candidate_action(task: &str) -> bool {
    let task = task.to_ascii_lowercase();
    let read_only = [
        "do not edit",
        "don't edit",
        "do not modify",
        "without changing",
        "read-only",
        "read only",
        "plan only",
        "analyze only",
        "analysis only",
        "不要修改",
        "不要改",
        "无需修改",
        "仅分析",
        "只分析",
        "只读",
        "先不要实现",
        "先不要 impl",
    ]
    .iter()
    .any(|marker| task.contains(marker));
    let implementation = [
        " fix ",
        " fix the",
        "implement",
        "modify",
        " edit ",
        "change the",
        "apply a patch",
        "修复",
        "修改",
        "实现",
        "改代码",
        "做最小必要修改",
    ]
    .iter()
    .any(|marker| task.contains(marker));
    implementation && !read_only
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_end_turn_accepts_only_oracle_or_stable_candidate_handoff() {
        assert_eq!(
            empty_end_turn_decision(false, false),
            EmptyEndTurnDecision::Reject
        );
        assert_eq!(
            empty_end_turn_decision(true, false),
            EmptyEndTurnDecision::RequireOracle
        );
        assert_eq!(
            empty_end_turn_decision(false, true),
            EmptyEndTurnDecision::AcceptCandidateHandoff
        );
        assert_eq!(
            empty_end_turn_decision(true, true),
            EmptyEndTurnDecision::RequireOracle,
            "a configured oracle remains authoritative over candidate handoff"
        );
    }

    #[test]
    fn immediate_candidate_commitment_is_distinct_from_a_terminal_report() {
        assert!(commits_to_immediate_candidate_action(
            "The evidence is closed, so I will make the minimal edit and verify."
        ));
        assert!(commits_to_immediate_candidate_action(
            "证据已经闭合，接下来我会修改 owner，然后验证。"
        ));
        assert!(commits_to_immediate_candidate_action(
            "结论与依据如下，随后做最小补丁并验证。"
        ));
        assert!(!commits_to_immediate_candidate_action(
            "I made the minimal edit and verified it."
        ));
        assert!(!commits_to_immediate_candidate_action(
            "I will not modify the workspace because the evidence is insufficient."
        ));
        assert!(!commits_to_immediate_candidate_action(
            "No code change is supported; verification remains external."
        ));
        assert!(!commits_to_immediate_candidate_action(
            "I will explain how to edit the file, but I will not change it."
        ));
        assert!(task_requests_candidate_action(
            "Locate and fix the bug with the smallest patch."
        ));
        assert!(task_requests_candidate_action(
            "请定位并修复问题，做最小必要修改。"
        ));
        assert!(!task_requests_candidate_action(
            "Analyze the bug and explain how to fix it; do not edit files."
        ));
        assert!(!task_requests_candidate_action(
            "先不要实现，只分析应该怎么修改。"
        ));
    }
}
