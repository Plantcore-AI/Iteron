//! Decode content-free runtime owner identities from the immutable tunables checkpoint.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use iteron_tunables::{ResolutionValue, RuntimeGetterId};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveContentIdentities {
    pub hooks: Option<crate::runtime::hooks::HookCatalogIdentity>,
    pub workflow_graph: iteron_workflow::WorkflowGraphRuntimeIdentity,
    pub agent_catalog: iteron_agents::AgentCatalogRuntimeIdentity,
    pub environment: iteron_protocol::EnvironmentSnapshotIdentity,
}

pub(crate) fn decode(
    view: &EffectiveTunablesView,
) -> Result<EffectiveContentIdentities, EffectiveContentError> {
    view.with_getter(RuntimeGetterId::EffectiveContent, || decode_inner(view))
}

fn decode_inner(
    view: &EffectiveTunablesView,
) -> Result<EffectiveContentIdentities, EffectiveContentError> {
    let hooks = view
        .optional_value("hooks_map")
        .map(|value| {
            let (digest_sha256, entry_count, canonical_bytes) =
                catalog(value, "hooks_map", HOOKS_CATALOG_ID)?;
            if entry_count > crate::runtime::hooks::MAX_HOOK_CATALOG_ENTRIES {
                return Err(EffectiveContentError::Range("hooks_map", "entry_count"));
            }
            Ok(crate::runtime::hooks::HookCatalogIdentity {
                digest_sha256,
                entry_count,
                canonical_bytes,
            })
        })
        .transpose()?;
    let (digest_sha256, entry_count, canonical_bytes) = catalog(
        view.value("workflow_graph")?,
        "workflow_graph",
        WORKFLOW_GRAPH_CATALOG_ID,
    )?;
    let (agent_digest_sha256, agent_entry_count, agent_canonical_bytes) = catalog(
        view.value("agent_catalog")?,
        "agent_catalog",
        AGENT_CATALOG_ID,
    )?;
    if agent_entry_count
        > iteron_tunables::param_integer(
            "cli.runtime_tunables.effective_content.max_agent_catalog_entries",
            MAX_AGENT_CATALOG_ENTRIES,
        )
    {
        return Err(EffectiveContentError::Range("agent_catalog", "entry_count"));
    }
    let environment = environment(view.object("environment_snapshot")?)?;
    Ok(EffectiveContentIdentities {
        hooks,
        workflow_graph: iteron_workflow::WorkflowGraphRuntimeIdentity {
            digest_sha256,
            entry_count,
            canonical_bytes,
        },
        agent_catalog: iteron_agents::AgentCatalogRuntimeIdentity {
            digest_sha256: agent_digest_sha256,
            entry_count: agent_entry_count,
            canonical_bytes: agent_canonical_bytes,
        },
        environment,
    })
}

const HOOKS_CATALOG_ID: &str = "iteron://tunables/catalogs/hooks_map-v1";
const WORKFLOW_GRAPH_CATALOG_ID: &str = "iteron://tunables/catalogs/workflow_graph-v1";
const AGENT_CATALOG_ID: &str = "iteron://tunables/catalogs/agent_catalog-v1";
const MAX_AGENT_CATALOG_ENTRIES: usize = 4_096;

fn catalog(
    value: &ResolutionValue,
    family: &'static str,
    expected_id: &'static str,
) -> Result<(String, usize, usize), EffectiveContentError> {
    let ResolutionValue::CatalogRef {
        catalog_id,
        digest_sha256,
        entry_count,
        canonical_bytes,
    } = value
    else {
        return Err(EffectiveContentError::WrongType(family));
    };
    if catalog_id != expected_id || !valid_sha256(digest_sha256) {
        return Err(EffectiveContentError::CatalogIdentity(family));
    }
    let entry_count = usize::try_from(*entry_count)
        .map_err(|_| EffectiveContentError::Range(family, "entry_count"))?;
    let canonical_bytes = usize::try_from(*canonical_bytes)
        .map_err(|_| EffectiveContentError::Range(family, "canonical_bytes"))?;
    Ok((digest_sha256.clone(), entry_count, canonical_bytes))
}

fn environment(
    fields: &BTreeMap<String, ResolutionValue>,
) -> Result<iteron_protocol::EnvironmentSnapshotIdentity, EffectiveContentError> {
    let present = boolean(fields, "present")?;
    let digest_sha256 = text(fields, "digest_sha256")?.to_owned();
    if !valid_sha256(&digest_sha256) {
        return Err(EffectiveContentError::CatalogIdentity(
            "environment_snapshot",
        ));
    }
    let canonical_bytes = usize::try_from(integer(fields, "canonical_bytes")?)
        .map_err(|_| EffectiveContentError::Range("environment_snapshot", "canonical_bytes"))?;
    let trust = match enumeration(fields, "trust")? {
        "untrusted" => iteron_protocol::Trust::Untrusted,
        "workspace" => iteron_protocol::Trust::Workspace,
        "trusted" => iteron_protocol::Trust::Trusted,
        _ => return Err(EffectiveContentError::UnknownTrust),
    };
    Ok(iteron_protocol::EnvironmentSnapshotIdentity {
        present,
        digest_sha256,
        canonical_bytes,
        trust,
    })
}

fn boolean(
    fields: &BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<bool, EffectiveContentError> {
    match fields.get(field) {
        Some(ResolutionValue::Boolean { value }) => Ok(*value),
        Some(_) => Err(EffectiveContentError::WrongField(field)),
        None => Err(EffectiveContentError::MissingField(field)),
    }
}

fn integer(
    fields: &BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<i64, EffectiveContentError> {
    match fields.get(field) {
        Some(ResolutionValue::Integer { value }) => Ok(*value),
        Some(_) => Err(EffectiveContentError::WrongField(field)),
        None => Err(EffectiveContentError::MissingField(field)),
    }
}

fn text<'a>(
    fields: &'a BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<&'a str, EffectiveContentError> {
    match fields.get(field) {
        Some(ResolutionValue::Text { value }) => Ok(value),
        Some(_) => Err(EffectiveContentError::WrongField(field)),
        None => Err(EffectiveContentError::MissingField(field)),
    }
}

fn enumeration<'a>(
    fields: &'a BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<&'a str, EffectiveContentError> {
    match fields.get(field) {
        Some(ResolutionValue::Enum { value }) => Ok(value),
        Some(_) => Err(EffectiveContentError::WrongField(field)),
        None => Err(EffectiveContentError::MissingField(field)),
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveContentError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error("effective tunable `{0}` must be a content-addressed catalog reference")]
    WrongType(&'static str),
    #[error("effective content catalog `{0}` has an invalid identity")]
    CatalogIdentity(&'static str),
    #[error("effective environment identity is missing `{0}`")]
    MissingField(&'static str),
    #[error("effective environment identity field `{0}` has the wrong type")]
    WrongField(&'static str),
    #[error("effective tunable `{0}` field `{1}` is outside the runtime range")]
    Range(&'static str, &'static str),
    #[error("effective environment identity has an unknown trust tier")]
    UnknownTrust,
}
