use super::provider_attempt_journal::ProviderLogicalUsageEvidence;
use super::*;

/// Wall-clock stamp reported when the host clock reads before the Unix epoch; accounting keeps an
/// unusable stamp rather than failing the caller.
const CLOCK_BEFORE_EPOCH_SECS: u64 = 0;

/// Byte ceiling on a provider notice surfaced into the transcript. Provider messages are
/// untrusted and unbounded; only enough of one to identify the condition is kept.
const PROVIDER_NOTICE_MAX_BYTES: usize = 512;

pub(super) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(iteron_tunables::param_integer(
            "cli.runtime.provider_accounting.clock_before_epoch_secs",
            CLOCK_BEFORE_EPOCH_SECS,
        ))
}

pub(super) fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

pub(super) fn bounded_provider_notice(
    label: &str,
    notice: &iteron_provider::ProviderNotice,
) -> String {
    let raw = format!("{label} [{}]: {}", notice.code, notice.message);
    iteron_protocol::text::head(
        &iteron_record::redact::scrub(&raw),
        iteron_tunables::param_integer(
            "cli.runtime.provider_accounting.provider_notice_max_bytes",
            PROVIDER_NOTICE_MAX_BYTES,
        ),
    )
}

pub(super) fn bounded_provider_run_notice(
    notice: &iteron_provider::ProviderNotice,
    key: &str,
) -> String {
    let raw = format!(
        "{PROVIDER_RUN_NOTICE_LABEL} [key={key}; code={}]: {}",
        notice.code, notice.message
    );
    iteron_protocol::text::head(
        &iteron_record::redact::scrub(&raw),
        iteron_tunables::param_integer(
            "cli.runtime.provider_accounting.provider_notice_max_bytes",
            PROVIDER_NOTICE_MAX_BYTES,
        ),
    )
}

pub(super) fn provider_run_notice_key_from_text(text: &str) -> Option<String> {
    let suffix = text.strip_prefix(PROVIDER_RUN_NOTICE_PREFIX)?;
    let body = suffix.as_bytes().get(
        ..iteron_tunables::param_integer(
            "cli.runtime.provider_run_notice_key_body_len",
            PROVIDER_RUN_NOTICE_KEY_BODY_LEN,
        ),
    )?;
    if !body.iter().enumerate().all(|(index, byte)| {
        if (index + 1) % 9 == 0 && index < 63 {
            *byte == b'-'
        } else {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
        }
    }) || !suffix
        .get(
            iteron_tunables::param_integer(
                "cli.runtime.provider_run_notice_key_body_len",
                PROVIDER_RUN_NOTICE_KEY_BODY_LEN,
            )..,
        )?
        .starts_with("; code=")
    {
        return None;
    }
    Some(format!("sha256:{}", std::str::from_utf8(body).ok()?))
}

impl Agent {
    #[cfg(test)]
    /// Publish the logical projection of an already sealed physical usage receipt.
    pub(super) fn complete_provider_turn(
        &mut self,
        turn: TurnId,
        usage: iteron_protocol::Usage,
        model_ms: u64,
        usage_evidence: &ProviderLogicalUsageEvidence,
        stream: StreamTiming,
        cache_creation_reported: bool,
    ) -> Result<(), KernelError> {
        self.provider_usage_journal(turn).complete(
            turn,
            usage,
            model_ms,
            usage_evidence,
            stream,
            cache_creation_reported,
        )
    }

    pub(super) fn record_provider_usage(
        &mut self,
        turn: TurnId,
        report: UsageReport,
        model_ms: u64,
        usage_evidence: &ProviderLogicalUsageEvidence,
        stream: StreamTiming,
    ) -> Result<Option<iteron_protocol::Usage>, KernelError> {
        self.provider_usage_journal(turn)
            .record(turn, report, model_ms, usage_evidence, stream)
    }

    pub(super) fn mark_usd_unknown(&self) {
        if let Some(budget) = &self.usd_budget {
            budget.mark_unknown();
        }
    }

    /// Reconcile the public execution budget with the monetary enforcement object. `None` never
    /// removes an already-established ceiling and a larger replacement never widens it. This keeps
    /// source compatibility for existing callers while making post-construction mutation safe.
    pub(super) fn synchronize_usd_budget(&mut self) -> Result<(), KernelError> {
        let turn = TurnId(self.seq_turn);
        self.invocation_funding().synchronize(turn)
    }

    /// Genesis stores the effective ceiling in `RunStart`; reconcile memory first, then mark it
    /// persisted only after that append succeeds.
    pub(super) fn reconcile_usd_budget_for_genesis(&mut self) {
        let Some(proposed) = self.budget.max_usd.map(usd_to_microusd_ceiling) else {
            return;
        };
        if let Some(shared) = &self.usd_budget {
            shared.tighten_microusd(proposed);
        } else {
            self.usd_budget = Some(std::sync::Arc::new(SharedUsdBudget::from_microusd(
                proposed,
            )));
        }
        self.budget.max_usd = self.effective_max_usd();
    }

    pub(super) fn effective_max_usd(&self) -> Option<f64> {
        self.usd_budget.as_ref().map(|budget| budget.ceiling_usd())
    }

    pub(super) fn close_usd_budget_on_unknown_cost(&self) {
        if self
            .usd_budget
            .as_ref()
            .is_some_and(|budget| budget.requires_pricing())
            && matches!(self.ledger.cost_state(), CostState::Unknown { .. })
        {
            self.mark_usd_unknown();
        }
    }
}

pub(super) const PROVIDER_RUN_NOTICE_LABEL: &str = "provider run notice";
pub(super) const PROVIDER_RUN_NOTICE_PREFIX: &str = "provider run notice [key=sha256:";
pub(super) const PROVIDER_RUN_NOTICE_KEY_BODY_LEN: usize = 71;
pub(super) const MAX_COMMITTED_PROVIDER_RUN_NOTICES: usize = 256;
