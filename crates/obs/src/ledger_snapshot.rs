//! Allocation admission for a frozen ledger clone, inspected before any evidence is copied.
use crate::Ledger;
use iteron_protocol::CostAttribution;

impl Ledger {
    /// Conservative retained allocation charge for an owned clone. Includes collection/entry
    /// overhead and every nested string. This is a bounded heap admission weight, not RSS.
    pub fn bounded_snapshot_bytes(&self, limit: usize) -> Option<usize> {
        let mut total = std::mem::size_of::<Self>().checked_add(8192)?;
        total = total.checked_add(
            self.cost_projections
                .len()
                .checked_mul(std::mem::size_of::<iteron_protocol::CostProjection>())?,
        )?;
        total = total.checked_add(self.rate_card_digests.len().checked_mul(256)?)?;
        if total > limit {
            return None;
        }
        let mut add = |text: &str| -> Option<()> {
            total = total.checked_add(text.len().checked_add(64)?)?;
            (total <= limit).then_some(())
        };
        for effect in &self.pending_child_accounting {
            add(&effect.0)?;
        }
        for digest in &self.rate_card_digests {
            add(digest)?;
        }
        for projection in &self.cost_projections {
            for text in [
                &projection.route.provider_id,
                &projection.route.model_id,
                &projection.route.catalog_digest,
                &projection.route.capability_digest,
                &projection.rate_card_digest,
                &projection.signer_id,
                &projection.projection_digest,
                &projection.signature,
            ] {
                add(text)?;
            }
            if let Some(identity) = &projection.identity {
                add(&identity.tenant_id)?;
                add(&identity.run_id)?;
                if let Some(attribution) = &identity.attribution {
                    match attribution {
                        CostAttribution::DirectSubagent {
                            parent_run_id,
                            sub_run,
                        } => {
                            add(parent_run_id)?;
                            add(sub_run)?;
                        }
                        CostAttribution::WorkflowChild {
                            parent_run_id,
                            workflow_id,
                            sub_run,
                            ..
                        } => {
                            add(parent_run_id)?;
                            add(workflow_id)?;
                            add(sub_run)?;
                        }
                    }
                }
            }
        }
        Some(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_counts_private_nested_projection_allocations_before_clone() {
        let mut ledger = Ledger::new();
        assert!(ledger.bounded_snapshot_bytes(1024).is_none());
        let initial = ledger.bounded_snapshot_bytes(1024 * 1024).unwrap();
        ledger.rate_card_digests.insert("x".repeat(1024 * 1024));
        assert!(ledger.bounded_snapshot_bytes(1024 * 1024).is_none());
        assert!(initial < 1024 * 1024);
    }
}
