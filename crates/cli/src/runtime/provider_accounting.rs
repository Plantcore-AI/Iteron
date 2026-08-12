use super::*;

pub(super) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(super) fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

pub(super) fn bounded_provider_notice(
    label: &str,
    notice: &iteron_provider::ProviderNotice,
) -> String {
    let raw = format!("{label} [{}]: {}", notice.code, notice.message);
    iteron_protocol::text::head(&iteron_record::redact::scrub(&raw), 512)
}

pub(super) fn bounded_provider_run_notice(
    notice: &iteron_provider::ProviderNotice,
    key: &str,
) -> String {
    let raw = format!(
        "{PROVIDER_RUN_NOTICE_LABEL} [key={key}; code={}]: {}",
        notice.code, notice.message
    );
    iteron_protocol::text::head(&iteron_record::redact::scrub(&raw), 512)
}

pub(super) fn provider_run_notice_key_from_text(text: &str) -> Option<String> {
    let suffix = text.strip_prefix(PROVIDER_RUN_NOTICE_PREFIX)?;
    let body = suffix.as_bytes().get(..PROVIDER_RUN_NOTICE_KEY_BODY_LEN)?;
    if !body.iter().enumerate().all(|(index, byte)| {
        if (index + 1) % 9 == 0 && index < 63 {
            *byte == b'-'
        } else {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
        }
    }) || !suffix
        .get(PROVIDER_RUN_NOTICE_KEY_BODY_LEN..)?
        .starts_with("; code=")
    {
        return None;
    }
    Some(format!("sha256:{}", std::str::from_utf8(body).ok()?))
}

impl Agent {
    fn close_usd_if_physical_charge_is_unproved(&self, turn: TurnId) {
        let physical_charge_known = self.usd_budget.as_ref().is_some_and(|budget| {
            budget.has_known_provider_charge_for(self.rollout.tenant(), self.rollout.run_id(), turn)
        });
        if !physical_charge_known {
            self.mark_usd_unknown();
        }
    }

    /// Commit authoritative usage and its optional signed monetary projection before updating the
    /// in-memory ledger. The pricing strategy is pure and injected; this code performs no price
    /// lookup, filesystem read, network request, or extra provider call.
    pub(super) fn complete_provider_turn(
        &mut self,
        turn: TurnId,
        usage: iteron_protocol::Usage,
        model_ms: u64,
        projected_at_unix_secs: u64,
        stream: StreamTiming,
        cache_creation_reported: bool,
    ) -> Result<(), KernelError> {
        // A rate that is never charged cannot be misapplied, so an unreported cache-creation count
        // only makes the turn unpriceable when the bound card actually bills for cache writes.
        let unpriceable_cache_creation = !cache_creation_reported
            && self.pricing.as_ref().is_some_and(|signed| {
                signed.rate_card.rates.cache_creation_microusd_per_million > 0
            });
        let projection_identity = CostProjectionIdentity {
            tenant_id: self.rollout.tenant().0.clone(),
            run_id: self.rollout.run_id().0.clone(),
            turn_id: turn.0,
            provider_attempt: self.ledger.provider_attempts,
            attribution: self.projection_attribution.clone(),
        };
        let projection = match (&self.pricing_port, &self.pricing) {
            (Some(port), Some(rate_card)) if !unpriceable_cache_creation => Some(port.project(
                rate_card,
                projection_identity.clone(),
                usage,
                projected_at_unix_secs,
            )),
            _ => None,
        };
        if let Err(error) = self.emit_durable(
            turn,
            EventKind::TurnEnd {
                usage,
                ttft_ms: stream.ttft_ms,
                decode_ms: stream.decode_ms,
                stream_items: stream.stream_items,
            },
        ) {
            // The per-route terminal and exact charge are already durable/load-bearing. Losing
            // this logical turn projection is a record failure, not uncertainty about billing.
            self.close_usd_if_physical_charge_is_unproved(turn);
            return Err(error);
        }
        if unpriceable_cache_creation {
            // Say why, on the record, before the ledger reports an unpriced turn. A silent
            // downgrade to "unknown" is indistinguishable from a missing rate card.
            if let Err(error) = self.emit_durable(
                turn,
                EventKind::Notice {
                    text: UNPRICEABLE_CACHE_CREATION_NOTICE.into(),
                },
            ) {
                self.close_usd_if_physical_charge_is_unproved(turn);
                return Err(error);
            }
            self.ui(UiEvent::Notice(UNPRICEABLE_CACHE_CREATION_NOTICE.into()));
        }
        self.ledger.turn(&usage, model_ms);
        let projection = match projection.transpose() {
            Ok(projection) => projection,
            Err(error) => {
                self.close_usd_if_physical_charge_is_unproved(turn);
                return Err(error.into());
            }
        };
        if let Some(projection) = &projection {
            if let Err(error) = self.emit_durable(
                turn,
                EventKind::CostProjected {
                    projection: projection.clone(),
                },
            ) {
                self.close_usd_if_physical_charge_is_unproved(turn);
                return Err(error);
            }
            let Some(port) = &self.pricing_port else {
                self.close_usd_if_physical_charge_is_unproved(turn);
                return Err(KernelError::PricingLedger(
                    "signed projection lost its pricing authority",
                ));
            };
            let Some(rate_card) = &self.pricing else {
                self.close_usd_if_physical_charge_is_unproved(turn);
                return Err(KernelError::PricingLedger(
                    "signed projection lost its bound rate card",
                ));
            };
            match admit_verified_projection(
                port.as_ref(),
                rate_card,
                &projection_identity,
                projection,
                &mut self.ledger,
            ) {
                Ok(()) => {}
                Err(ProjectionAdmissionError::Pricing(error)) => {
                    self.close_usd_if_physical_charge_is_unproved(turn);
                    return Err(error.into());
                }
                Err(ProjectionAdmissionError::Ledger(reason)) => {
                    self.close_usd_if_physical_charge_is_unproved(turn);
                    return Err(KernelError::PricingLedger(reason));
                }
            }
            // The logical projection remains the operator-facing turn/accounting evidence, but
            // the shared hard ceiling was already charged by the physical route terminal before
            // this point. Charging the winner here would count it twice after retry/fallback.
        } else {
            self.close_usd_if_physical_charge_is_unproved(turn);
        }
        Ok(())
    }

    /// Record the billing evidence for one otherwise-successful provider response.
    ///
    /// A missing provider report is not a zero-token turn. Keep the durable `TurnStart`
    /// unmatched so replay reaches the same `BillingEvidenceMissing` state, and continue with the
    /// assistant transcript because the semantic response itself completed successfully.
    pub(super) fn record_provider_usage(
        &mut self,
        turn: TurnId,
        report: UsageReport,
        model_ms: u64,
        projected_at_unix_secs: u64,
        stream: StreamTiming,
    ) -> Result<Option<iteron_protocol::Usage>, KernelError> {
        match report {
            UsageReport::Complete(usage) | UsageReport::CacheCreationUnreported(usage) => {
                self.complete_provider_turn(
                    turn,
                    usage,
                    model_ms,
                    projected_at_unix_secs,
                    stream,
                    report.cache_creation_reported(),
                )?;
                Ok(Some(usage))
            }
            UsageReport::Incomplete { .. } => {
                if let Err(error) = self.emit_durable(
                    turn,
                    EventKind::Notice {
                        text: INCOMPLETE_USAGE_NOTICE.into(),
                    },
                ) {
                    self.mark_usd_unknown();
                    return Err(error);
                }
                self.ledger.turn_without_usage(model_ms);
                self.mark_usd_unknown();
                Ok(None)
            }
        }
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
        let proposed = self.budget.max_usd.map(usd_to_microusd_ceiling);
        let current = self
            .usd_budget
            .as_ref()
            .map(|budget| budget.ceiling_microusd());
        let target = match (current, proposed) {
            (None, None) => return Ok(()),
            (Some(current), None) => current,
            (None, Some(proposed)) => proposed,
            (Some(current), Some(proposed)) => current.min(proposed),
        };
        let persisted = self.usd_budget_persisted_microusd;
        if persisted.is_none_or(|ceiling| target < ceiling) {
            let source = if persisted.is_some() {
                RuntimePolicySource::Operator
            } else {
                RuntimePolicySource::Startup
            };
            let kind = EventKind::UsdCeilingChanged {
                version: RuntimePolicyEventVersion::V1,
                source,
                max_microusd: target,
            };
            let sequence = self.emit_durable_seq(TurnId(self.seq_turn), kind.clone())?;
            self.usd_budget_persisted_microusd = Some(target);
            self.observe_runtime_policy_commit(
                &kind,
                sequence,
                RuntimePolicyObservation::LiveCommit,
            );
        }
        let created = self.usd_budget.is_none();
        if let Some(shared) = &self.usd_budget {
            shared.tighten_microusd(target);
        } else {
            self.usd_budget = Some(std::sync::Arc::new(SharedUsdBudget::from_microusd(target)));
        }
        if created {
            let scoped = replay_scoped_rollout(self.rollout.path())?;
            self.restore_usd_budget_from_route_receipts(&scoped)?;
        }
        self.budget.max_usd = self.effective_max_usd();
        Ok(())
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

    pub(super) fn merge_child_ledger(&mut self, child: &Ledger) {
        let child_unknown = matches!(child.cost_state(), CostState::Unknown { .. });
        self.ledger.merge(child);
        if child_unknown || matches!(self.ledger.cost_state(), CostState::Unknown { .. }) {
            self.mark_usd_unknown();
        }
    }
}
