//! The registry's single session-local memoization authority.
//!
//! Pure tool calls are keyed by their logical name and bounded JSON input. Every completed
//! effecting attempt invalidates the whole generation. A pure result that started before that
//! invalidation carries an old generation token and cannot repopulate the cache afterward.
//! This protects registry-mediated writes; it is not a claim that ambient filesystem changes are
//! observable or that tool execution is hermetic.

use iteron_protocol::ToolResult;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_CAPACITY: usize = 256;
pub(crate) const DEFAULT_TTL_SECONDS: u64 = 60;
pub(crate) const MAX_TTL_SECONDS: u64 = 86_400;
const MAX_TOOL_NAME_BYTES: usize = 256;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_INPUT_DEPTH: usize = 32;
const MAX_INPUT_NODES: usize = 4_096;
const MAX_CONTAINER_ITEMS: usize = 4_096;

/// Exact fixed owner projection for the registry's physical pure-result cache. The projection is
/// read from the same `Memo` instance that performs lookup and invalidation, so composition cannot
/// drift from a separately copied set of defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PureMemoCachePolicy {
    pub max_entries: usize,
    pub max_key_bytes: usize,
    pub generation_scoped: bool,
}

impl PureMemoCachePolicy {
    /// Immutable production owner used by every non-test registry. Resume admission can sample
    /// this value without constructing a registry or reading the checkpoint it is validating.
    pub const fn production_owner() -> Self {
        Self {
            max_entries: DEFAULT_CAPACITY,
            max_key_bytes: MAX_INPUT_BYTES,
            generation_scoped: true,
        }
    }
}

struct BoundedDigestWriter<'a> {
    digest: &'a mut Sha256,
    written: usize,
}

impl Write for BoundedDigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(total) = self.written.checked_add(bytes.len()) else {
            return Err(io::Error::other("memo input byte count overflow"));
        };
        if total > MAX_INPUT_BYTES {
            return Err(io::Error::other("memo input exceeds byte ceiling"));
        }
        self.digest.update(bytes);
        self.written = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn input_is_keyable(value: &Value, depth: usize, remaining_nodes: &mut usize) -> bool {
    if depth > MAX_INPUT_DEPTH || *remaining_nodes == 0 {
        return false;
    }
    *remaining_nodes -= 1;
    match value {
        Value::Array(values) => {
            values.len() <= MAX_CONTAINER_ITEMS
                && values
                    .iter()
                    .all(|value| input_is_keyable(value, depth + 1, remaining_nodes))
        }
        Value::Object(values) => {
            values.len() <= MAX_CONTAINER_ITEMS
                && values.iter().all(|(key, value)| {
                    key.len() <= MAX_INPUT_BYTES
                        && input_is_keyable(value, depth + 1, remaining_nodes)
                })
        }
        Value::String(value) => value.len() <= MAX_INPUT_BYTES,
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct MemoKey([u8; 32]);

pub(crate) struct PendingInsert {
    generation: u64,
    key: MemoKey,
    enabled: bool,
}

pub(crate) enum Lookup {
    Hit(ToolResult),
    Miss(PendingInsert),
}

struct State {
    generation: u64,
    accepts_inserts: bool,
    cache: HashMap<MemoKey, MemoEntry>,
    insertion_order: VecDeque<MemoKey>,
    hits: u64,
    misses: u64,
    ttl: Duration,
    policy_installed: bool,
    activated: bool,
}

struct MemoEntry {
    result: ToolResult,
    inserted_at: Instant,
}

impl State {
    fn new(capacity: usize) -> Self {
        Self {
            generation: 0,
            accepts_inserts: true,
            cache: HashMap::with_capacity(capacity),
            insertion_order: VecDeque::with_capacity(capacity),
            hits: 0,
            misses: 0,
            ttl: Duration::from_secs(DEFAULT_TTL_SECONDS),
            policy_installed: false,
            activated: false,
        }
    }
}

pub(crate) struct Memo {
    state: Mutex<State>,
    capacity: usize,
}

impl Memo {
    pub(crate) fn policy(&self) -> PureMemoCachePolicy {
        PureMemoCachePolicy {
            max_entries: self.capacity,
            ..PureMemoCachePolicy::production_owner()
        }
    }

    pub(crate) fn key(tool_name: &str, input: &Value) -> Option<MemoKey> {
        if tool_name.len() > MAX_TOOL_NAME_BYTES {
            return None;
        }
        let mut remaining_nodes = MAX_INPUT_NODES;
        if !input_is_keyable(input, 0, &mut remaining_nodes) {
            return None;
        }

        let mut digest = Sha256::new();
        digest.update(b"iteron-tools-memo-v1\0");
        digest.update((tool_name.len() as u64).to_be_bytes());
        digest.update(tool_name.as_bytes());
        let mut writer = BoundedDigestWriter {
            digest: &mut digest,
            written: 0,
        };
        serde_json::to_writer(&mut writer, input).ok()?;
        Some(MemoKey(digest.finalize().into()))
    }

    pub(crate) fn lookup(&self, key: MemoKey) -> Lookup {
        self.lookup_at(key, Instant::now())
    }

    pub(crate) fn lookup_at(&self, key: MemoKey, now: Instant) -> Lookup {
        let mut state = self.state.lock().unwrap();
        state.activated = true;
        let ttl = state.ttl;
        let expired = state.cache.get(&key).is_some_and(|entry| {
            ttl.is_zero() || now.saturating_duration_since(entry.inserted_at) >= ttl
        });
        if expired {
            state.cache.remove(&key);
            state.insertion_order.retain(|candidate| candidate != &key);
        }
        if let Some(result) = state.cache.get(&key).map(|entry| entry.result.clone()) {
            state.hits = state.hits.saturating_add(1);
            Lookup::Hit(result)
        } else {
            state.misses = state.misses.saturating_add(1);
            Lookup::Miss(PendingInsert {
                generation: state.generation,
                key,
                enabled: state.accepts_inserts && !state.ttl.is_zero(),
            })
        }
    }

    /// Cache a successful pure result only when no effect completed after its lookup miss.
    pub(crate) fn complete(&self, pending: PendingInsert, result: &ToolResult) -> bool {
        self.complete_at(pending, result, Instant::now())
    }

    pub(crate) fn complete_at(
        &self,
        pending: PendingInsert,
        result: &ToolResult,
        now: Instant,
    ) -> bool {
        if result.is_error || !pending.enabled || self.capacity == 0 {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        if !state.accepts_inserts || state.generation != pending.generation {
            return false;
        }
        if let Some(existing) = state.cache.get_mut(&pending.key) {
            *existing = MemoEntry {
                result: result.clone(),
                inserted_at: now,
            };
            return true;
        }
        if state.cache.len() == self.capacity
            && let Some(oldest) = state.insertion_order.pop_front()
        {
            state.cache.remove(&oldest);
        }
        state.insertion_order.push_back(pending.key);
        state.cache.insert(
            pending.key,
            MemoEntry {
                result: result.clone(),
                inserted_at: now,
            },
        );
        true
    }

    pub(crate) fn install_ttl_seconds(&self, ttl_seconds: u64) -> Result<(), &'static str> {
        if ttl_seconds > MAX_TTL_SECONDS {
            return Err("tool-result cache TTL exceeds 86400 seconds");
        }
        let mut state = self.state.lock().unwrap();
        if state.policy_installed {
            return Err("tool-result cache TTL was already installed");
        }
        if state.activated {
            return Err("tool-result cache TTL must be installed before the first lookup");
        }
        state.ttl = Duration::from_secs(ttl_seconds);
        state.policy_installed = true;
        Ok(())
    }

    pub(crate) fn ttl_seconds(&self) -> u64 {
        self.state.lock().unwrap().ttl.as_secs()
    }

    /// Invalidate all reads after every completed effecting attempt, including error outcomes.
    pub(crate) fn invalidate(&self) {
        let mut state = self.state.lock().unwrap();
        state.cache.clear();
        state.insertion_order.clear();
        if let Some(next) = state.generation.checked_add(1) {
            state.generation = next;
        } else {
            // Never wrap to a generation that an ancient pending read could hold. At this
            // unreachable-in-practice boundary, memoization stays disabled for the session.
            state.accepts_inserts = false;
        }
    }

    pub(crate) fn stats(&self) -> (u64, u64) {
        let state = self.state.lock().unwrap();
        (state.hits, state.misses)
    }

    #[cfg(test)]
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State::new(capacity)),
            capacity,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state.lock().unwrap().cache.len()
    }
}

impl Default for Memo {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::new(DEFAULT_CAPACITY)),
            capacity: DEFAULT_CAPACITY,
        }
    }
}
