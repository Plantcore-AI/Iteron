use super::*;

/// How this process learned a runtime-policy value. The durable event source remains separate:
/// an operator-authored event replayed after restart is still operator-authored, but the frontend
/// should also say that the current process restored it rather than just committing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimePolicyObservation {
    Genesis,
    LiveCommit,
    ResumeReplay,
}

/// One live value joined to the exact durable event that made it effective.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct RuntimePolicyValue<T> {
    pub(crate) value: T,
    pub(crate) source: RuntimePolicySource,
    pub(crate) sequence: u64,
    pub(crate) observed_via: RuntimePolicyObservation,
}

/// Content-free live overlay projected beside the immutable tunables checkpoint.
///
/// Permission rules may contain operator-chosen tool names, so status transports expose only a
/// deterministic digest and count. `/permissions` remains the explicit surface for rule details.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct RuntimePolicyOverlaySnapshot {
    pub(crate) sequence: u64,
    pub(crate) effort: RuntimePolicyValue<Effort>,
    pub(crate) permission_mode: RuntimePolicyValue<PermissionMode>,
    pub(crate) permission_rule_count: usize,
    pub(crate) permission_rules_digest_sha256: String,
    pub(crate) max_turns: RuntimePolicyValue<u32>,
    pub(crate) max_usd_microusd: Option<RuntimePolicyValue<u64>>,
}

/// Cloneable read authority for `/status` while the resident `Agent` is exclusively borrowed by a
/// turn. Writers publish only after the corresponding WAL commit and in-memory owner update.
#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimePolicyOverlayHandle {
    current: std::sync::Arc<std::sync::RwLock<Option<RuntimePolicyOverlaySnapshot>>>,
}

impl RuntimePolicyOverlayHandle {
    fn publish(&self, snapshot: Option<RuntimePolicyOverlaySnapshot>) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot;
    }

    pub(crate) fn snapshot(&self) -> Option<RuntimePolicyOverlaySnapshot> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RuntimePolicyCommit {
    source: RuntimePolicySource,
    sequence: u64,
    observed_via: RuntimePolicyObservation,
}

impl RuntimePolicyCommit {
    fn value<T>(self, value: T) -> RuntimePolicyValue<T> {
        RuntimePolicyValue {
            value,
            source: self.source,
            sequence: self.sequence,
            observed_via: self.observed_via,
        }
    }
}

/// Metadata only: the effective values continue to have exactly one runtime owner (`Agent`).
/// Keeping provenance separate avoids a second mutable copy that could drift from enforcement.
#[derive(Debug, Clone, Default)]
pub(super) struct RuntimePolicyProvenance {
    effort: Option<RuntimePolicyCommit>,
    permission: Option<RuntimePolicyCommit>,
    max_turns: Option<RuntimePolicyCommit>,
    max_usd: Option<RuntimePolicyCommit>,
    max_usd_microusd: Option<u64>,
    live: RuntimePolicyOverlayHandle,
}

impl RuntimePolicyProvenance {
    pub(super) fn from_events(events: &[Event], observed_via: RuntimePolicyObservation) -> Self {
        let mut projection = Self::default();
        for event in events {
            projection.observe(&event.kind, event.seq, observed_via);
        }
        projection
    }

    /// Rebuild a run-local projection while retaining the process-owned publication handle held
    /// by status/control readers. Replacing the handle during an in-process adoption would leave
    /// those readers permanently attached to the run that was left.
    pub(super) fn replay_preserving_handle(
        &self,
        events: &[Event],
        observed_via: RuntimePolicyObservation,
    ) -> Self {
        let mut projection = Self::from_events(events, observed_via);
        projection.live = self.live.clone();
        projection
    }

    pub(super) fn observe(
        &mut self,
        kind: &EventKind,
        sequence: Seq,
        observed_via: RuntimePolicyObservation,
    ) {
        let commit = |source| RuntimePolicyCommit {
            source,
            sequence: sequence.0,
            observed_via,
        };
        match kind {
            EventKind::EffortChanged { source, .. } => {
                self.effort = Some(commit(*source));
            }
            EventKind::PolicyChanged { source, .. } => {
                self.permission = Some(commit(*source));
            }
            EventKind::TurnCeilingChanged {
                source, max_turns, ..
            } if *max_turns > 0 => {
                self.max_turns = Some(commit(*source));
            }
            EventKind::UsdCeilingChanged {
                source,
                max_microusd,
                ..
            } if self
                .max_usd_microusd
                .is_none_or(|current| *max_microusd <= current) =>
            {
                // The monetary owner is monotone. Equal fork snapshots deliberately select the
                // later physical event so provenance names the current branch, while a later
                // larger value can never make the overlay claim authority was widened.
                self.max_usd_microusd = Some(*max_microusd);
                self.max_usd = Some(commit(*source));
            }
            _ => {}
        }
    }
}

impl Agent {
    pub(super) fn observe_runtime_policy_commit(
        &mut self,
        kind: &EventKind,
        sequence: Seq,
        observed_via: RuntimePolicyObservation,
    ) {
        self.runtime_policy_provenance
            .observe(kind, sequence, observed_via);
        // Publishing here makes the clone held by OperatorStatusSources advance at the same
        // post-WAL point as the enforced fields, including USD tightening inside an active turn.
        let _ = self.runtime_policy_overlay();
    }

    /// Exact live values plus durable provenance. `None` is honest for an unsealed/legacy test
    /// agent: a caller must not label genesis defaults as a verified runtime overlay.
    pub(crate) fn runtime_policy_overlay(&self) -> Option<RuntimePolicyOverlaySnapshot> {
        let provenance = &self.runtime_policy_provenance;
        let snapshot = (|| {
            let effort = provenance.effort?.value(self.effort);
            let permission_mode = provenance.permission?.value(self.permission_mode);
            let max_turns = provenance.max_turns?.value(self.budget.max_turns);
            let max_usd_microusd = match (provenance.max_usd, provenance.max_usd_microusd) {
                (Some(commit), Some(value)) => Some(commit.value(value)),
                (None, None) => None,
                _ => return None,
            };
            let sequence = effort
                .sequence
                .max(permission_mode.sequence)
                .max(max_turns.sequence)
                .max(max_usd_microusd.as_ref().map_or(0, |value| value.sequence));
            Some(RuntimePolicyOverlaySnapshot {
                sequence,
                effort,
                permission_mode,
                permission_rule_count: self.permission_rules.describe().len(),
                permission_rules_digest_sha256: permission_rules_digest(&self.permission_rules),
                max_turns,
                max_usd_microusd,
            })
        })();
        provenance.live.publish(snapshot.clone());
        snapshot
    }

    pub(crate) fn runtime_policy_overlay_handle(&self) -> RuntimePolicyOverlayHandle {
        // Synchronize the initial/resumed projection before handing out the read authority. Later
        // successful transitions publish through `observe_runtime_policy_commit` above.
        let _ = self.runtime_policy_overlay();
        self.runtime_policy_provenance.live.clone()
    }
}

fn permission_rules_digest(rules: &PermissionRules) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"iteron.runtime-permission-rules.v1\0");
    for (capability, verdict) in rules.capability_rules() {
        hasher.update([0x01]);
        hasher.update(format!("{capability:?}").as_bytes());
        hasher.update([0x00]);
        hasher.update(format!("{verdict:?}").as_bytes());
        hasher.update([0x00]);
    }
    for (tool, verdict) in rules.tool_rules() {
        hasher.update([0x02]);
        hasher.update(u64::try_from(tool.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(tool.as_bytes());
        hasher.update(format!("{verdict:?}").as_bytes());
        hasher.update([0x00]);
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_projection_is_ordered_and_a_larger_usd_event_cannot_widen_it() {
        let mut rules = PermissionRules::new();
        rules.set_cap(Capability::CodeExecuting, Verdict::Deny);
        let events = vec![
            Event {
                seq: Seq(3),
                turn: TurnId(0),
                kind: EventKind::TurnCeilingChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Startup,
                    max_turns: 12,
                },
            },
            Event {
                seq: Seq(4),
                turn: TurnId(0),
                kind: EventKind::UsdCeilingChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Startup,
                    max_microusd: 2_000_000,
                },
            },
            Event {
                seq: Seq(5),
                turn: TurnId(0),
                kind: EventKind::EffortChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Startup,
                    effort: Effort::Medium,
                },
            },
            Event {
                seq: Seq(6),
                turn: TurnId(0),
                kind: EventKind::PolicyChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Startup,
                    mode: PermissionMode::Default,
                    rules,
                },
            },
            Event {
                seq: Seq(9),
                turn: TurnId(1),
                kind: EventKind::EffortChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Operator,
                    effort: Effort::High,
                },
            },
            Event {
                seq: Seq(10),
                turn: TurnId(1),
                kind: EventKind::UsdCeilingChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Operator,
                    max_microusd: 1_000_000,
                },
            },
            Event {
                seq: Seq(11),
                turn: TurnId(1),
                kind: EventKind::UsdCeilingChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Operator,
                    max_microusd: 9_000_000,
                },
            },
        ];
        let projected =
            RuntimePolicyProvenance::from_events(&events, RuntimePolicyObservation::ResumeReplay);
        assert_eq!(projected.effort.unwrap().sequence, 9);
        assert_eq!(projected.max_usd.unwrap().sequence, 10);
        assert_eq!(projected.max_usd_microusd, Some(1_000_000));
    }
}
