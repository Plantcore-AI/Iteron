use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio_util::sync::CancellationToken;

use crate::EarlyStopQuorumPolicy;

struct Group {
    token: CancellationToken,
    evidence: usize,
    roles: BTreeSet<String>,
    vetoed: bool,
    quorum_reached: bool,
}

/// Per-run sibling-cancellation owner for opt-in quorum fans.
pub(super) struct QuorumGroups {
    policy: EarlyStopQuorumPolicy,
    next_id: AtomicU64,
    groups: Mutex<BTreeMap<u64, Group>>,
}

impl QuorumGroups {
    pub(super) fn new(policy: EarlyStopQuorumPolicy) -> Self {
        Self {
            policy,
            next_id: AtomicU64::new(1),
            groups: Mutex::new(BTreeMap::new()),
        }
    }

    pub(super) fn begin(&self, parent: &CancellationToken, members: usize) -> u64 {
        if members == 0 {
            return 0;
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.groups.lock().unwrap().insert(
            id,
            Group {
                token: parent.child_token(),
                evidence: 0,
                roles: BTreeSet::new(),
                vetoed: false,
                quorum_reached: false,
            },
        );
        id
    }

    pub(super) fn token(&self, group_id: Option<u64>) -> Option<CancellationToken> {
        let id = group_id.filter(|id| *id != 0)?;
        self.groups
            .lock()
            .unwrap()
            .get(&id)
            .map(|group| group.token.clone())
    }

    pub(super) fn observe(&self, group_id: Option<u64>, role: &str, evidence: bool) {
        let Some(id) = group_id.filter(|id| *id != 0) else {
            return;
        };
        let mut groups = self.groups.lock().unwrap();
        let Some(group) = groups.get_mut(&id) else {
            return;
        };
        if group.quorum_reached {
            return;
        }
        if evidence {
            group.evidence = group.evidence.saturating_add(1);
            group.roles.insert(role.to_owned());
        } else if self.policy.strong_veto() {
            group.vetoed = true;
        }
        if !group.vetoed
            && group.evidence >= self.policy.minimum_evidence()
            && group.roles.len() >= self.policy.required_roles()
        {
            group.quorum_reached = true;
            group.token.cancel();
        }
    }

    pub(super) fn end(&self, group_id: u64) {
        if group_id != 0 {
            self.groups.lock().unwrap().remove(&group_id);
        }
    }
}
