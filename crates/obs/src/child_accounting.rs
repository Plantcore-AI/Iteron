//! Exact pending child accounting is separate from physical effect certainty and provider counts.
use crate::Ledger;
use iteron_protocol::EffectId;
impl Ledger {
    pub(crate) fn merge_child_accounting(&mut self, child: &Ledger) {
        self.child_accounting_evidence_lost |= child.child_accounting_evidence_lost;
        for effect in &child.pending_child_accounting {
            if self.pending_child_accounting.len() < 64
                || self.pending_child_accounting.contains(effect)
            {
                self.pending_child_accounting.insert(effect.clone());
            } else {
                self.child_accounting_evidence_lost = true;
            }
        }
    }
    pub fn child_accounting_complete(&self) -> bool {
        !self.child_accounting_evidence_lost
            && self.pending_child_accounting.is_empty()
            && self.unresolved_child_attributions == 0
    }
    pub fn begin_child_accounting(&mut self, effect: &EffectId) -> Result<(), &'static str> {
        if effect.0.is_empty() || effect.0.len() > 256 || effect.0.chars().any(char::is_control) {
            return Err("invalid child accounting identity");
        }
        if !self.pending_child_accounting.contains(effect)
            && self.pending_child_accounting.len() >= 64
        {
            self.child_accounting_evidence_lost = true;
            return Err("child accounting pending bound");
        }
        self.pending_child_accounting.insert(effect.clone());
        Ok(())
    }
    pub fn resolve_child_accounting(&mut self, effect: &EffectId) -> Result<(), &'static str> {
        if !self.pending_child_accounting.remove(effect) {
            return Err("child accounting resolution has no exact pending identity");
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_pair_is_idempotent_without_fabricating_provider_calls_or_resolving_old_child_admission()
     {
        let mut ledger = Ledger::default();
        let a = EffectId("actual-a".into());
        let b = EffectId("actual-b".into());
        ledger.admit_child_attribution();
        ledger.begin_child_accounting(&a).unwrap();
        ledger.begin_child_accounting(&a).unwrap();
        assert!(ledger.resolve_child_accounting(&b).is_err());
        assert_eq!(ledger.provider_attempts, 0);
        ledger.resolve_child_accounting(&a).unwrap();
        assert!(!ledger.child_accounting_complete());
        ledger.resolve_child_attribution();
        assert!(ledger.child_accounting_complete());
    }
}
