//! Bounded metadata-only @file completion beneath the actual host workspace capability.
use super::workspace_storage::{NativeDirectory, leaf};
use crate::runtime::Agent;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};
const MAX_SCAN: usize = 4096;
const MAX_ROW_BYTES: usize = 255;
const MAX_ENTRY_BYTES: usize = 256 * 1024;
const MAX_CACHE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 32;

#[derive(Clone)]
pub(crate) struct CompletionSource {
    workspace: PathBuf,
    admitted: bool,
    #[cfg(test)]
    pause: Option<
        std::sync::Arc<
            std::sync::Mutex<(
                std::sync::mpsc::SyncSender<()>,
                std::sync::mpsc::Receiver<()>,
            )>,
        >,
    >,
}
impl CompletionSource {
    pub(crate) fn equivalent(&self, other: &Self) -> bool {
        self.workspace == other.workspace && self.admitted == other.admitted
    }
    pub(crate) fn capture(agent: &Agent) -> Self {
        let call = iteron_protocol::ToolUse {
            id: "operator-file-completion".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path":"."}),
        };
        Self {
            workspace: agent.workspace.clone(),
            admitted: agent.admit_operator_tool_call(&call),
            #[cfg(test)]
            pause: None,
        }
    }
    pub(crate) fn complete(
        &self,
        partial: &str,
        cache: &mut CompletionCache,
    ) -> Result<CompletionRows, &'static str> {
        if !self.admitted {
            return Err("file completion is denied by current host read authority");
        }
        #[cfg(test)]
        if let Some(pause) = &self.pause {
            let pause = pause.lock().unwrap();
            pause.0.send(()).unwrap();
            pause.1.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        let (directory, prefix) = parse(partial)?;
        let root = NativeDirectory::open(&self.workspace)
            .map_err(|_| "completion workspace unavailable")?;
        let mut child = None;
        for name in directory
            .trim_end_matches('/')
            .split('/')
            .filter(|name| !name.is_empty())
        {
            child = (child.as_ref().unwrap_or(&root))
                .child(name, false)
                .map_err(|_| "completion parent is unavailable or redirected")?;
            if child.is_none() {
                return Ok(CompletionRows {
                    items: Vec::new(),
                    incomplete: false,
                });
            }
        }
        let actual = child.as_ref().unwrap_or(&root);
        let identity = actual
            .cache_key()
            .map_err(|_| "completion namespace changed")?;
        let now = Instant::now();
        let ttl = iteron_tunables::param_duration(
            "cli.tui.driver_support.completion_directory_cache_ttl",
            Duration::from_secs(1),
        );
        cache.evict_expired(now, ttl);
        let entry = if let Some(index) = cache
            .entries
            .iter()
            .position(|entry| entry.directory == directory && entry.identity == identity)
        {
            cache.entries.remove(index).expect("present cache entry")
        } else {
            let (rows, mut incomplete) = actual
                .list(MAX_SCAN)
                .map_err(|_| "completion enumeration unavailable")?;
            let mut retained = Vec::with_capacity(rows.len().min(MAX_SCAN));
            let mut charge = directory.len()
                + retained.capacity() * std::mem::size_of::<(String, bool)>()
                + std::mem::size_of::<CacheEntry>();
            for (name, is_dir) in rows {
                if name.len() > MAX_ROW_BYTES || leaf(&name).is_err() {
                    incomplete = true;
                    continue;
                }
                if charge.saturating_add(name.capacity()) > MAX_ENTRY_BYTES {
                    incomplete = true;
                    continue;
                }
                charge += name.capacity();
                retained.push((name, is_dir));
            }
            retained.sort_by(|left, right| left.0.cmp(&right.0));
            CacheEntry {
                directory: directory.into(),
                identity,
                inserted: now,
                rows: retained,
                incomplete,
                charge,
            }
        };
        // Even a warm hit first opens the no-follow namespace and verifies its actual identity.
        if actual
            .cache_key()
            .map_err(|_| "completion namespace changed")?
            != identity
        {
            return Err("completion namespace changed");
        }
        let prefix = prefix.to_ascii_lowercase();
        let items = entry
            .rows
            .iter()
            .filter(|(name, _)| {
                (!name.starts_with('.') || prefix.starts_with('.'))
                    && !matches!(name.as_str(), "target" | "node_modules" | ".git")
                    && name.to_ascii_lowercase().starts_with(&prefix)
            })
            .take(8)
            .map(|(name, is_dir)| format!("{directory}{name}{}", if *is_dir { "/" } else { "" }))
            .collect();
        let result = CompletionRows {
            items,
            incomplete: entry.incomplete,
        };
        let limit = iteron_tunables::param_integer(
            "cli.tui.driver_support.completion_directory_cache_entries",
            MAX_ENTRIES,
        )
        .clamp(1, MAX_ENTRIES);
        while cache.entries.len() >= limit
            || cache.bytes().saturating_add(entry.charge) > MAX_CACHE_BYTES
        {
            cache.entries.pop_front();
        }
        cache.entries.push_back(entry);
        Ok(result)
    }
}
fn parse(partial: &str) -> Result<(&str, &str), &'static str> {
    if partial.len() > 1024
        || partial.starts_with('/')
        || partial.contains("..")
        || partial.contains(['\\', ':'])
        || partial.chars().any(char::is_control)
    {
        return Err("invalid bounded workspace completion path");
    }
    let (directory, prefix) = partial.rfind('/').map_or(("", partial), |index| {
        (&partial[..=index], &partial[index + 1..])
    });
    if directory.split('/').count() > 64
        || directory.trim_end_matches('/').split('/').any(|name| {
            (!directory.is_empty() && name.is_empty()) || name == "." || name.len() > 255
        })
    {
        return Err("invalid completion parent");
    }
    Ok((directory, prefix))
}
pub(crate) struct CompletionRows {
    pub(crate) items: Vec<String>,
    pub(crate) incomplete: bool,
}
#[derive(Default)]
pub(crate) struct CompletionCache {
    entries: VecDeque<CacheEntry>,
}
struct CacheEntry {
    directory: String,
    identity: [u64; 3],
    inserted: Instant,
    rows: Vec<(String, bool)>,
    incomplete: bool,
    charge: usize,
}
impl CompletionCache {
    fn bytes(&self) -> usize {
        // Reserve the bounded deque backing allocation as well as actual string/vector capacities.
        std::mem::size_of::<Self>()
            + MAX_ENTRIES * std::mem::size_of::<CacheEntry>()
            + self.entries.iter().map(|entry| entry.charge).sum::<usize>()
    }
    fn evict_expired(&mut self, now: Instant, ttl: Duration) {
        self.entries
            .retain(|entry| now.saturating_duration_since(entry.inserted) <= ttl);
    }
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}
#[cfg(test)]
pub(crate) fn fixture_complete(root: &std::path::Path, partial: &str) -> Vec<String> {
    let Ok(workspace) = root.canonicalize() else {
        return Vec::new();
    };
    CompletionSource {
        workspace,
        admitted: true,
        pause: None,
    }
    .complete(partial, &mut CompletionCache::default())
    .map(|rows| rows.items)
    .unwrap_or_default()
}
#[cfg(test)]
impl CompletionSource {
    pub(crate) fn pause(
        mut self,
        start: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Self {
        self.pause = Some(std::sync::Arc::new(std::sync::Mutex::new((start, release))));
        self
    }
}
#[cfg(test)]
mod tests;
