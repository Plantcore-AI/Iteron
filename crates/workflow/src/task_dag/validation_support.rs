use super::DagError;
use super::types::{BudgetReservation, BudgetUsage, TaskBudget, TaskId};

pub(super) fn budget_fits(
    limit: TaskBudget,
    usage: BudgetUsage,
    reserved: BudgetReservation,
    requested: BudgetReservation,
) -> Result<(), DagError> {
    let reserved = reserved
        .checked_add(requested)
        .ok_or(DagError::Budget("budget reservation overflow"))?;
    let turns = usage
        .turns
        .checked_add(reserved.turns)
        .ok_or(DagError::Budget("turn usage overflow"))?;
    if turns > u64::from(limit.max_turns) {
        return Err(DagError::Budget(
            "turn reservation exceeds its parent ceiling",
        ));
    }
    let tokens = usage
        .tokens
        .checked_add(reserved.tokens)
        .ok_or(DagError::Budget("token usage overflow"))?;
    if tokens > limit.max_tokens {
        return Err(DagError::Budget(
            "token reservation exceeds its parent ceiling",
        ));
    }
    let cost = usage
        .cost_microusd
        .checked_add(reserved.cost_microusd)
        .ok_or(DagError::Budget("cost usage overflow"))?;
    if cost > limit.max_cost_microusd {
        return Err(DagError::Budget(
            "cost reservation exceeds its parent ceiling",
        ));
    }
    if usage.wall_ms > limit.max_wall_ms {
        return Err(DagError::Budget(
            "wall-clock usage exceeds its task ceiling",
        ));
    }
    Ok(())
}

pub(super) fn validate_visible(
    value: &str,
    max_bytes: usize,
    name: &'static str,
) -> Result<(), DagError> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(DagError::Invalid(match name {
            "cancel reason" => "cancel reason is empty or over its byte limit",
            "cancellation reason" => "cancellation reason is empty or over its byte limit",
            _ => "failure detail is over its byte limit",
        }));
    }
    if value.chars().any(|character| {
        (character.is_control() && !matches!(character, '\n' | '\t'))
            || matches!(character, '\u{202a}'..='\u{202e}')
    }) {
        return Err(DagError::Invalid(
            "task-DAG display text contains terminal-control or bidi-override characters",
        ));
    }
    Ok(())
}

pub(super) fn transition(task: TaskId, reason: &'static str) -> DagError {
    DagError::Transition {
        task: task.0,
        reason,
    }
}
