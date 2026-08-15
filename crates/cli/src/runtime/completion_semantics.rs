//! Completion rules that stay separate from provider wire stop reasons.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EmptyEndTurnDecision {
    Reject,
    RequireOracle,
}

pub(super) const fn empty_end_turn_decision(has_oracle: bool) -> EmptyEndTurnDecision {
    if has_oracle {
        EmptyEndTurnDecision::RequireOracle
    } else {
        EmptyEndTurnDecision::Reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_end_turn_never_succeeds_without_an_oracle() {
        assert_eq!(empty_end_turn_decision(false), EmptyEndTurnDecision::Reject);
        assert_eq!(
            empty_end_turn_decision(true),
            EmptyEndTurnDecision::RequireOracle
        );
    }
}
