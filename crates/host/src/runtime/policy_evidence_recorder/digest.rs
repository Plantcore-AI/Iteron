use iteron_protocol::{PolicyOpportunityId, PolicyOpportunityJoinDigest};
use sha2::{Digest, Sha256};

const OPPORTUNITY_ID_DOMAIN: &[u8] = b"core-policy-opportunity-id-v1\0";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct OrderedOpportunityDigest(PolicyOpportunityJoinDigest);

impl OrderedOpportunityDigest {
    pub(super) fn append(&mut self, opportunity: &PolicyOpportunityId) {
        self.0
            .append(opportunity)
            .expect("the recorder enforces the same opportunity bound before append");
    }

    pub(super) fn count(&self) -> u32 {
        self.0.count()
    }

    pub(super) fn hex_digest(&self) -> String {
        self.0.digest_sha256()
    }
}

pub(super) fn opportunity_id(
    recorder_id: u64,
    sequence: u64,
    run_id: &str,
    tunables_digest: &str,
    slot: &str,
    bundle_digest: &str,
    policy_digest: &str,
) -> PolicyOpportunityId {
    let mut hasher = Sha256::new();
    hasher.update(OPPORTUNITY_ID_DOMAIN);
    hasher.update(recorder_id.to_le_bytes());
    hasher.update(sequence.to_le_bytes());
    update_bounded(&mut hasher, run_id);
    update_bounded(&mut hasher, tunables_digest);
    update_bounded(&mut hasher, slot);
    update_bounded(&mut hasher, bundle_digest);
    update_bounded(&mut hasher, policy_digest);
    PolicyOpportunityId(format!(
        "policy:{}:{sequence}",
        hex::encode(hasher.finalize())
    ))
}

fn update_bounded(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}
