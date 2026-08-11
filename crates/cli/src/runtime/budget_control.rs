use super::*;

impl Agent {
    pub(super) fn run_time_remaining(&self) -> Option<Duration> {
        self.run_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// One absolute child deadline that can only tighten both the parent run bound and the
    /// child's writer-first wall allocation. Copying only the parent deadline would leave the
    /// child's advertised `Budget::max_wall_secs` unenforced.
    pub(super) fn child_run_deadline(&self, child_budget: &Budget) -> Instant {
        let now = Instant::now();
        let local = now
            .checked_add(Duration::from_secs(child_budget.max_wall_secs))
            .unwrap_or(now);
        self.run_deadline.map_or(local, |parent| parent.min(local))
    }

    pub(super) fn run_deadline_exhausted(&self) -> bool {
        self.run_time_remaining()
            .is_some_and(|remaining| remaining.is_zero())
    }

    pub(super) fn usd_budget_exhausted(&self) -> bool {
        self.usd_budget
            .as_ref()
            .is_some_and(|budget| budget.exhausted())
    }

    pub(super) fn token_budget_exhausted(&self) -> bool {
        self.budget.max_tokens.is_some_and(|ceiling| {
            // A dispatched response without authoritative usage cannot prove that any positive
            // remainder exists, so the optional hard ceiling fails closed.
            self.ledger.provider_attempts > self.ledger.turns
                || ledger_tokens(&self.ledger) >= ceiling
        })
    }

    pub(super) fn remaining_provider_tokens(&self) -> Option<u64> {
        self.budget.max_tokens.map(|ceiling| {
            if self.ledger.provider_attempts > self.ledger.turns {
                0
            } else {
                ceiling.saturating_sub(ledger_tokens(&self.ledger))
            }
        })
    }

    /// Deterministic precedence when multiple aggregate ceilings become true at one safe point.
    pub(super) fn completed_turn_budget_exhaustion(&self) -> Option<&'static str> {
        if self.token_budget_exhausted() {
            Some("max_tokens")
        } else if self.usd_budget_exhausted() {
            Some("max_usd")
        } else {
            None
        }
    }

    /// One admission predicate for every logical provider call owned by this agent. Child-agent
    /// attempts are merged into the ledger, so decomposition, compaction, fan workers, direct
    /// investigators, and writer turns consume the same operator ceiling.
    pub(super) fn inference_budget_exhaustion(
        &mut self,
    ) -> Result<Option<&'static str>, KernelError> {
        self.budget.validate().map_err(KernelError::InvalidBudget)?;
        self.synchronize_usd_budget()?;
        self.close_usd_budget_on_unknown_cost();
        if self.ledger.provider_attempts >= self.budget.max_turns {
            Ok(Some("max_turns"))
        } else if self.token_budget_exhausted() {
            Ok(Some("max_tokens"))
        } else if self.usd_budget_exhausted() {
            Ok(Some("max_usd"))
        } else if self.run_deadline_exhausted() {
            Ok(Some("max_wall_secs"))
        } else {
            Ok(None)
        }
    }

    pub(super) fn remaining_inference_turns(&self) -> u32 {
        self.budget
            .max_turns
            .saturating_sub(self.ledger.provider_attempts)
    }

    /// The turn ceiling and what has already been charged against it, read as one pair so a
    /// frontend can never print a ceiling from one instant beside a count from another.
    pub fn turn_budget(&self) -> TurnBudgetState {
        TurnBudgetState {
            max_turns: self.budget.max_turns,
            used: self.ledger.provider_attempts,
        }
    }

    /// Set the session turn ceiling in place, write-ahead.
    ///
    /// `max_turns` is the one ceiling an operator can saturate without having spent anything:
    /// `provider_attempts` only ever saturating-adds, subagent attempts are charged to the parent,
    /// and resume deliberately restores the count so it cannot be laundered by reconnecting. That
    /// is correct as an aggregate guarantee and unusable as a stop: before this existed, the
    /// ceiling was fixed at startup, so a long session that reached it ended every later
    /// submission immediately and the only exit was restarting the process.
    ///
    /// The escape hatch is explicit rather than automatic. Nothing here resets `provider_attempts`
    /// — the count keeps meaning "provider calls this session made" across resume — and the new
    /// ceiling is appended to the record BEFORE memory changes, so a reader of the log can always
    /// tell why more turns were admitted than the run started with. A failed append leaves the old
    /// ceiling in force.
    pub fn set_turn_ceiling(&mut self, max_turns: u32) -> Result<TurnBudgetState, KernelError> {
        if max_turns == 0 {
            return Err(KernelError::InvalidBudget(
                "max_turns must be >= 1 (0 would disable the turn budget)",
            ));
        }
        let previous = self.budget.max_turns;
        if max_turns != previous {
            let kind = EventKind::TurnCeilingChanged {
                version: RuntimePolicyEventVersion::V1,
                source: RuntimePolicySource::Operator,
                max_turns,
            };
            let sequence = self.emit_durable_seq(TurnId(self.seq_turn), kind.clone())?;
            self.budget.max_turns = max_turns;
            self.observe_runtime_policy_commit(
                &kind,
                sequence,
                RuntimePolicyObservation::LiveCommit,
            );
        }
        Ok(self.turn_budget())
    }

    /// Install the inbound approvals channel (the TUI's answer path). When set, an `Ask` verdict
    /// prompts the operator and blocks (interrupt-bounded) for the answer; without it, `Ask` denies.
    pub fn set_approvals(&mut self, rx: tokio::sync::mpsc::UnboundedReceiver<SqEnvelope>) {
        self.approvals_rx = Some(rx);
    }

    /// Install trusted provider credential-variable names without ever inspecting their values.
    /// Child agents and the strong verification oracle inherit this deny-list.
    pub fn set_sensitive_env_names(&mut self, mut names: Vec<String>) {
        names.sort();
        names.dedup();
        self.hooks.set_sensitive_env_names(names.clone());
        self.sensitive_env_names = names;
    }
}
