//! Runtime-effective compaction controls beside the transcript planning algorithm.

use iteron_protocol::Effort;

const RATIO_SCALE: u32 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionHysteresis {
    pub cooldown_turns: u32,
    pub enter_ratio_ppm: u32,
    pub exit_ratio_ppm: u32,
}

impl Default for CompactionHysteresis {
    fn default() -> Self {
        Self {
            cooldown_turns: 1,
            enter_ratio_ppm: 750_000,
            exit_ratio_ppm: 500_000,
        }
    }
}

impl CompactionHysteresis {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.enter_ratio_ppm > RATIO_SCALE || self.exit_ratio_ppm > self.enter_ratio_ppm {
            return Err("compaction hysteresis requires exit <= enter <= 1");
        }
        Ok(self)
    }

    pub fn enter_threshold(self, trigger: usize) -> usize {
        trigger.saturating_mul(self.enter_ratio_ppm as usize) / RATIO_SCALE as usize
    }

    pub fn exit_threshold(self, trigger: usize) -> usize {
        trigger.saturating_mul(self.exit_ratio_ppm as usize) / RATIO_SCALE as usize
    }

    pub fn cooldown_allows(self, current_turn: u64, last_compaction_turn: Option<u64>) -> bool {
        last_compaction_turn
            .is_none_or(|last| current_turn.saturating_sub(last) >= u64::from(self.cooldown_turns))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryTopology {
    SingleStage,
    Hierarchical,
    MapReduce,
}

impl SummaryTopology {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "single_stage" => Some(Self::SingleStage),
            "hierarchical" => Some(Self::Hierarchical),
            "map_reduce" => Some(Self::MapReduce),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SummaryProfile {
    pub max_output_tokens: u32,
    pub effort: Effort,
    pub preserve_tool_evidence: bool,
}

impl Default for SummaryProfile {
    fn default() -> Self {
        Self {
            max_output_tokens: 2_048,
            effort: Effort::Low,
            preserve_tool_evidence: true,
        }
    }
}

impl SummaryProfile {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.max_output_tokens == 0 {
            return Err("summary output budget must be non-zero");
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteresis_has_distinct_entry_exit_and_bounded_cooldown() {
        let policy = CompactionHysteresis::default();
        assert_eq!(policy.enter_threshold(100_000), 75_000);
        assert_eq!(policy.exit_threshold(100_000), 50_000);
        assert!(!policy.cooldown_allows(10, Some(10)));
        assert!(policy.cooldown_allows(11, Some(10)));
    }
}
