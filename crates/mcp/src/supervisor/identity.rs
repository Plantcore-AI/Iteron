use crate::{McpError, tool_filter::McpToolFilter};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

static NEXT_LINEAGE: AtomicU64 = AtomicU64::new(1);

/// Opaque identity for one owned supervisor lineage. It is stable across reconnects performed by
/// that instance and changes with its absolute launch configuration or exact tool filter. A fresh
/// supervisor receives a distinct lineage even for identical configuration.
///
/// This is not executable attestation: replacement of bytes at the same command path during the
/// lineage is not detected. Authorities requiring that guarantee must withhold continuity unless
/// they independently attest the executable. This identity does not itself authorize a tool.
#[derive(Clone, PartialEq, Eq)]
pub struct McpServerIdentity {
    name: String,
    binding: Arc<[u8]>,
}

impl McpServerIdentity {
    pub(super) fn new(
        name: String,
        config: Arc<[u8]>,
        filter: &McpToolFilter,
    ) -> Result<Self, McpError> {
        let lineage = NEXT_LINEAGE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| McpError::GenerationExhausted)?;
        Ok(Self {
            name,
            binding: supervisor_binding(config, filter, lineage),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn binding(&self) -> &Arc<[u8]> {
        &self.binding
    }
}

impl std::fmt::Debug for McpServerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpServerIdentity")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

fn supervisor_binding(config: Arc<[u8]>, filter: &McpToolFilter, lineage: u64) -> Arc<[u8]> {
    let mut binding = b"iteron-mcp-supervisor-binding-v2\0".to_vec();
    binding.extend_from_slice(&lineage.to_be_bytes());
    binding.extend_from_slice(&(config.len() as u64).to_be_bytes());
    binding.extend_from_slice(&config);
    let mut allow = filter.allow.clone();
    let mut deny = filter.deny.clone();
    allow.sort();
    deny.sort();
    append_names(&mut binding, &allow);
    append_names(&mut binding, &deny);
    binding.into()
}

fn append_names(binding: &mut Vec<u8>, names: &[String]) {
    binding.extend_from_slice(&(names.len() as u64).to_be_bytes());
    for name in names {
        binding.extend_from_slice(&(name.len() as u64).to_be_bytes());
        binding.extend_from_slice(name.as_bytes());
    }
}
