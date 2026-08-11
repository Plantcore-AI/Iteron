//! Content-free identity for the workflow graph runtime admitted by this binary.

use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Immutable identity consumed by tunables resolution and checked again before graph execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkflowGraphRuntimeIdentity {
    pub digest_sha256: String,
    pub entry_count: usize,
    pub canonical_bytes: usize,
}

/// Return the exact graph compiler/host catalog implemented by this build.
///
/// Dynamic scripts are content recorded by each workflow manifest. This identity instead binds
/// the executable graph semantics shared by every script: the deterministic prelude, host port
/// versions, schema retry ceiling, and durable task-DAG limits. A resumed run therefore refuses a
/// binary whose graph semantics no longer match its immutable tunables checkpoint.
pub fn workflow_graph_runtime_identity() -> WorkflowGraphRuntimeIdentity {
    #[derive(Serialize)]
    struct Descriptor {
        identity_version: &'static str,
        spawner_port_version: u32,
        progress_port_version: u32,
        schema_retry_max: usize,
        lifetime_cap: usize,
        dag_limits: crate::task_dag::Limits,
    }

    let descriptor = serde_json::to_vec(&Descriptor {
        identity_version: "iteron-workflow-graph-runtime-v1",
        spawner_port_version: crate::AGENT_SPAWNER_PORT_VERSION,
        progress_port_version: crate::PROGRESS_SINK_PORT_VERSION,
        schema_retry_max: usize::try_from(crate::schema::RETRY_MAX)
            .expect("schema retry ceiling fits usize"),
        lifetime_cap: crate::LIFETIME_CAP,
        dag_limits: crate::task_dag::Limits::default(),
    })
    .expect("fixed workflow runtime descriptor is serializable");
    let prelude = include_bytes!("prelude.js");
    let mut digest = Sha256::new();
    digest.update(b"iteron-workflow-graph-runtime-v1");
    for part in [descriptor.as_slice(), prelude.as_slice()] {
        digest.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(part);
    }
    WorkflowGraphRuntimeIdentity {
        digest_sha256: hex::encode(digest.finalize()),
        entry_count: 2,
        canonical_bytes: descriptor.len().saturating_add(prelude.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_runtime_identity_is_bounded_and_deterministic() {
        let first = workflow_graph_runtime_identity();
        let second = workflow_graph_runtime_identity();
        assert_eq!(first, second);
        assert_eq!(first.digest_sha256.len(), 64);
        assert!(
            first
                .digest_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_eq!(first.entry_count, 2);
        assert!(first.canonical_bytes > include_bytes!("prelude.js").len());
    }
}
