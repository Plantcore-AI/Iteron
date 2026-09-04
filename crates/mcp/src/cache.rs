//! Client-private, bounded cache for 2026 list responses.

use crate::McpError;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_CACHE_ENTRIES: usize = 64;
const MAX_TTL_MILLISECONDS: u64 = 5 * 60 * 1000;

struct Entry {
    expires: Instant,
    value: Value,
}

pub(crate) struct McpListCache {
    entries: Mutex<BTreeMap<[u8; 32], Entry>>,
}

impl McpListCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn get(&self, method: &str, params: &Value) -> Option<Value> {
        let cache_key = key(method, params).ok()?;
        let now = Instant::now();
        let mut entries = self.entries.lock().ok()?;
        entries.retain(|_, entry| entry.expires > now);
        entries.get(&cache_key).map(|entry| entry.value.clone())
    }

    pub(crate) fn put(&self, method: &str, params: &Value, value: &Value) -> Result<(), McpError> {
        let ttl = match value.get("ttlMs") {
            None => return Ok(()),
            Some(value) => value
                .as_u64()
                .ok_or_else(|| McpError::Protocol("MCP cache ttlMs must be non-negative".into()))?,
        };
        let scope = value
            .get("cacheScope")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::Protocol("MCP cacheScope is required with ttlMs".into()))?;
        if scope != "private" {
            return Err(McpError::Protocol("MCP cacheScope is not supported".into()));
        }
        if ttl == 0 {
            return Ok(());
        }
        let max_cache_entries =
            iteron_tunables::param_usize("mcp.cache.max_cache_entries", MAX_CACHE_ENTRIES);
        let max_ttl_milliseconds =
            iteron_tunables::param_u64("mcp.cache.max_ttl_milliseconds", MAX_TTL_MILLISECONDS);
        if max_cache_entries == 0 || max_ttl_milliseconds == 0 {
            return Ok(());
        }
        let cache_key = key(method, params)?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| McpError::Protocol("MCP list cache lock failed".into()))?;
        let now = Instant::now();
        entries.retain(|_, entry| entry.expires > now);
        if entries.len() >= max_cache_entries
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(key, _)| *key)
        {
            entries.remove(&oldest);
        }
        entries.insert(
            cache_key,
            Entry {
                expires: now + Duration::from_millis(ttl.min(max_ttl_milliseconds)),
                value: value.clone(),
            },
        );
        Ok(())
    }
}

fn key(method: &str, params: &Value) -> Result<[u8; 32], McpError> {
    let bytes = serde_json::to_vec(params)?;
    let mut digest = Sha256::new();
    digest.update(b"iteron-mcp-list-cache-v1\0");
    digest.update((method.len() as u64).to_be_bytes());
    digest.update(method.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cache_is_keyed_and_invalid_hints_fail_closed() {
        let cache = McpListCache::new();
        cache
            .put(
                "tools/list",
                &json!({}),
                &json!({"tools":[], "ttlMs":1000, "cacheScope":"private"}),
            )
            .unwrap();
        assert!(cache.get("tools/list", &json!({})).is_some());
        assert!(cache.get("prompts/list", &json!({})).is_none());
        assert!(cache.get("tools/list", &json!({"cursor":"x"})).is_none());
        assert!(
            cache
                .put(
                    "tools/list",
                    &json!({}),
                    &json!({"tools":[], "ttlMs":-1, "cacheScope":"private"})
                )
                .is_err()
        );
        assert!(
            cache
                .put(
                    "tools/list",
                    &json!({}),
                    &json!({"tools":[], "ttlMs":1, "cacheScope":"shared"})
                )
                .is_err()
        );
    }
}
