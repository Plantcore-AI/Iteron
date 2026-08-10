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

const DEFAULT_CAPACITY: usize = 256;
const MAX_TOOL_NAME_BYTES: usize = 256;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_INPUT_DEPTH: usize = 32;
const MAX_INPUT_NODES: usize = 4_096;
const MAX_CONTAINER_ITEMS: usize = 4_096;

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
    cache: HashMap<MemoKey, ToolResult>,
    insertion_order: VecDeque<MemoKey>,
    hits: u64,
    misses: u64,
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
        }
    }
}

pub(crate) struct Memo {
    state: Mutex<State>,
    capacity: usize,
}

impl Memo {
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
        let mut state = self.state.lock().unwrap();
        if let Some(result) = state.cache.get(&key).cloned() {
            state.hits = state.hits.saturating_add(1);
            Lookup::Hit(result)
        } else {
            state.misses = state.misses.saturating_add(1);
            Lookup::Miss(PendingInsert {
                generation: state.generation,
                key,
                enabled: state.accepts_inserts,
            })
        }
    }

    /// Cache a successful pure result only when no effect completed after its lookup miss.
    pub(crate) fn complete(&self, pending: PendingInsert, result: &ToolResult) -> bool {
        if result.is_error || !pending.enabled || self.capacity == 0 {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        if !state.accepts_inserts || state.generation != pending.generation {
            return false;
        }
        if let Some(existing) = state.cache.get_mut(&pending.key) {
            *existing = result.clone();
            return true;
        }
        if state.cache.len() == self.capacity
            && let Some(oldest) = state.insertion_order.pop_front()
        {
            state.cache.remove(&oldest);
        }
        state.insertion_order.push_back(pending.key);
        state.cache.insert(pending.key, result.clone());
        true
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
