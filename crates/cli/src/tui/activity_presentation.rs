//! Bounded advisory activity and provider-wait observations. This owner cannot cancel work or
//! infer a durable terminal from an activity; actual owner ports retain those responsibilities.
use iteron_protocol::{ActivityDetailCode, ActivityEvent, ActivityOwner};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_ACTIVE: usize = 64;
const MAX_ACTIVE_BYTES: usize = 64 * 1024;
const MAX_RETIRED: usize = 256;

pub(super) struct PresentedActivity {
    event: ActivityEvent,
    observed_at: Instant,
}
impl PresentedActivity {
    pub(super) fn event(&self) -> &ActivityEvent {
        &self.event
    }
    pub(super) fn observed_at(&self) -> Instant {
        self.observed_at
    }
}
#[derive(Clone, Copy)]
pub(super) struct ProviderWait {
    pub(super) started: Instant,
    pub(super) accepted: bool,
}
pub(super) enum ActivityReaction {
    None,
    Status(&'static str),
    Invalid,
    Saturated,
}
#[derive(Default)]
pub(super) struct ActivityPresentation {
    active: BTreeMap<String, PresentedActivity>,
    retired: VecDeque<String>,
    active_bytes: usize,
    dropped_updates: u64,
    wait: Option<ProviderWait>,
}
impl ActivityPresentation {
    pub(super) fn observe(&mut self, event: ActivityEvent, running: bool) -> ActivityReaction {
        if event.validate().is_err() {
            return ActivityReaction::Invalid;
        }
        if self.retired.iter().any(|id| id == &event.id) {
            return ActivityReaction::None;
        }
        if event.state.is_terminal() {
            if let Some(previous) = self.active.remove(&event.id) {
                self.active_bytes = self.active_bytes.saturating_sub(charge(&previous.event));
            }
            let reaction = match event.detail_code {
                Some(ActivityDetailCode::AnswerComplete) if running => {
                    ActivityReaction::Status("answer complete · finalizing…")
                }
                Some(ActivityDetailCode::InputReady) if !running => {
                    ActivityReaction::Status("idle · input ready")
                }
                _ => ActivityReaction::None,
            };
            self.retire(&event.id);
            return reaction;
        }
        if !running
            && matches!(
                event.owner,
                ActivityOwner::Runtime
                    | ActivityOwner::Provider
                    | ActivityOwner::Tool
                    | ActivityOwner::Workflow
            )
        {
            return ActivityReaction::None;
        }
        let started = started_at(&event);
        match event.detail_code {
            Some(ActivityDetailCode::RequestSent) => self.observe_request_sent(started),
            Some(ActivityDetailCode::WaitingFirstToken) => self.observe_provider_response(started),
            _ => {}
        }
        let previous = self.active.get(&event.id);
        let previous_charge = previous.map_or(0, |previous| charge(&previous.event));
        let projected = self
            .active_bytes
            .saturating_sub(previous_charge)
            .saturating_add(charge(&event));
        if (previous.is_none() && self.active.len() >= MAX_ACTIVE) || projected > MAX_ACTIVE_BYTES {
            let first_gap = self.dropped_updates == 0;
            self.dropped_updates = self.dropped_updates.saturating_add(1);
            return if first_gap {
                ActivityReaction::Saturated
            } else {
                ActivityReaction::None
            };
        }
        let reaction = if event.detail_code == Some(ActivityDetailCode::Finalizing) {
            ActivityReaction::Status("answer complete · finalizing…")
        } else {
            ActivityReaction::None
        };
        let observed_at = previous.map_or(started, |previous| previous.observed_at);
        self.active_bytes = projected;
        self.active
            .insert(event.id.clone(), PresentedActivity { event, observed_at });
        reaction
    }
    pub(super) fn has_active(&self) -> bool {
        !self.active.is_empty()
    }
    pub(super) fn values(&self) -> impl Iterator<Item = &PresentedActivity> {
        self.active.values()
    }
    pub(super) fn has_presentation_gap(&self) -> bool {
        self.dropped_updates > 0
    }
    pub(super) fn provider_wait(&self) -> Option<ProviderWait> {
        self.wait
    }
    pub(super) fn observe_request_sent(&mut self, started: Instant) {
        self.wait = Some(ProviderWait {
            started,
            accepted: false,
        });
    }
    pub(super) fn observe_provider_response(&mut self, started: Instant) {
        let wait = self.wait.get_or_insert(ProviderWait {
            started,
            accepted: false,
        });
        wait.accepted = true;
    }
    pub(super) fn finish_provider_wait(&mut self) {
        self.wait = None;
    }
    /// Invoked from actual RunEnded/adoption presentation boundaries. Retirement prevents a late
    /// cosmetic update from reopening a spinner; it does not publish a task-success observation.
    pub(super) fn retire_run_observations(&mut self) {
        let active = std::mem::take(&mut self.active);
        for id in active.keys() {
            self.retire(id);
        }
        self.active_bytes = 0;
        self.wait = None;
        self.dropped_updates = 0;
    }
    fn retire(&mut self, id: &str) {
        if self.retired.iter().any(|retired| retired == id) {
            return;
        }
        self.retired.push_back(id.to_owned());
        while self.retired.len() > MAX_RETIRED {
            self.retired.pop_front();
        }
    }
    #[cfg(test)]
    pub(super) fn contains(&self, id: &str) -> bool {
        self.active.contains_key(id)
    }
}
fn charge(event: &ActivityEvent) -> usize {
    std::mem::size_of::<PresentedActivity>()
        .saturating_add(64)
        .saturating_add(event.id.capacity())
        .saturating_add(event.id.len())
        .saturating_add(event.parent_id.as_ref().map_or(0, String::capacity))
}
fn started_at(event: &ActivityEvent) -> Instant {
    let now = Instant::now();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok());
    let age = wall
        .map_or(Duration::ZERO, |wall| {
            Duration::from_millis(wall.saturating_sub(event.started_at_unix_ms))
        })
        .min(Duration::from_secs(24 * 60 * 60));
    now.checked_sub(age).unwrap_or(now)
}
#[cfg(test)]
mod tests;
