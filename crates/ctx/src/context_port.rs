//! Bounded materialization of a pure context plan.

use crate::context_strategy::MAX_CONTEXT_OUTLINE_DEPTH;
use crate::instructions::framed;
use crate::memory::{
    FileMemory, MemBudget, MemStore, MemTier, MemoryRecallAudit, MemoryRecallStrategy,
    MemoryStrategy,
};
use crate::{outline, skills};
use iteron_protocol::context::{
    ContextGrant, ContextSegment, ContextSelector, ContextSource, MAX_CONTEXT_SEGMENTS,
};
use iteron_protocol::{Trust, home, slot::StrategySlot};
use std::fmt;
use std::path::{Component, Path, PathBuf};

use crate::ContextPlan;

const SKILL_INDEX_BYTES: usize = 2_000;
const MAX_TRANSCRIPT_VALUES: usize = 1_024;

/// Already-gathered context bytes with their real provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextValue {
    pub text: String,
    pub trust: Trust,
}

/// World-facing inputs. Paths are supplied explicitly; the port never reads ambient `HOME`.
#[derive(Debug, Clone, Default)]
pub struct ContextPortInput {
    pub workspace: PathBuf,
    pub home_dir: Option<PathBuf>,
    pub active_dir: PathBuf,
    pub environment: Option<ContextValue>,
    pub transcript: Vec<ContextValue>,
    /// Exact verified plugin skill directories selected by runtime composition.
    pub dependency_skill_dirs: Vec<(PathBuf, PathBuf)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPortError(pub String);

impl fmt::Display for ContextPortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ContextPortError {}

/// Injected world port used by the kernel/driver after a pure context decision.
pub trait ContextPort: Send + Sync {
    fn resolve(
        &self,
        plan: &ContextPlan,
        input: &ContextPortInput,
    ) -> Result<ContextGrant, ContextPortError>;

    /// Resolve context with the exact `core/memory` policy pinned by the composition root.
    fn resolve_with_memory_strategy(
        &self,
        plan: &ContextPlan,
        input: &ContextPortInput,
        _memory_strategy: &dyn StrategySlot,
    ) -> Result<ContextGrant, ContextPortError> {
        self.resolve(plan, input)
    }

    /// Resolve plus an ephemeral explanation of the pinned memory decision. Replacement ports may
    /// decline the explanation by using this default; they may not fabricate one.
    fn resolve_with_memory_audit(
        &self,
        plan: &ContextPlan,
        input: &ContextPortInput,
        memory_strategy: &dyn StrategySlot,
    ) -> Result<(ContextGrant, Option<MemoryRecallAudit>), ContextPortError> {
        self.resolve_with_memory_strategy(plan, input, memory_strategy)
            .map(|grant| (grant, None))
    }
}

/// Filesystem-backed context adapter composed from the existing bounded ctx mechanisms.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultContextPort;

impl ContextPort for DefaultContextPort {
    fn resolve(
        &self,
        plan: &ContextPlan,
        input: &ContextPortInput,
    ) -> Result<ContextGrant, ContextPortError> {
        self.resolve_with_memory_strategy(plan, input, &MemoryRecallStrategy::default())
    }

    fn resolve_with_memory_strategy(
        &self,
        plan: &ContextPlan,
        input: &ContextPortInput,
        memory_strategy: &dyn StrategySlot,
    ) -> Result<ContextGrant, ContextPortError> {
        plan.request
            .validate()
            .map_err(|reason| ContextPortError(reason.into()))?;
        if input.transcript.len() > MAX_TRANSCRIPT_VALUES {
            return Err(ContextPortError(format!(
                "context transcript exceeds {MAX_TRANSCRIPT_VALUES} gathered values"
            )));
        }
        let workspace = explicit_workspace(input)?;
        let mut builder = GrantBuilder::new(&plan.request);
        let stores = memory_stores(&workspace, input.home_dir.as_deref());

        for selector in &plan.request.selectors {
            match selector {
                ContextSelector::RepoOutline { root, depth } => {
                    if *depth > MAX_CONTEXT_OUTLINE_DEPTH {
                        return Err(ContextPortError(format!(
                            "context outline depth exceeds {MAX_CONTEXT_OUTLINE_DEPTH}"
                        )));
                    }
                    let selected = confined_root(&workspace, root)?;
                    let text = outline::repo_outline_for_task_at_depth(
                        &selected,
                        *depth,
                        builder.remaining_bytes().saturating_div(3),
                        &plan.task,
                    );
                    builder.push(text, Trust::Workspace, ContextSource::RepoOutline);
                }
                ContextSelector::Instructions { scope } => {
                    let home_core = input.home_dir.as_deref().map(|home| home::path(home, ""));
                    let bundle = crate::instructions::discover_hierarchy_scope(
                        home_core.as_deref(),
                        &workspace,
                        if input.active_dir.as_os_str().is_empty() {
                            &workspace
                        } else {
                            &input.active_dir
                        },
                        *scope,
                    );
                    let mut rendered = String::new();
                    for source in bundle.sources() {
                        rendered.push_str(&framed(&source.source, &source.content));
                    }
                    builder.push(rendered, Trust::Untrusted, ContextSource::Instructions);
                }
                ContextSelector::MemoryKeys { keys } => {
                    for key in keys {
                        if let Ok(fact) = FileMemory.read_fact(&stores, key) {
                            builder.push(fact.framed(), fact.trust(), ContextSource::Memory);
                        }
                    }
                }
                ContextSelector::Transcript { last_n_turns } => {
                    let keep = usize::from(*last_n_turns).min(input.transcript.len());
                    for value in &input.transcript[input.transcript.len() - keep..] {
                        builder.push(value.text.clone(), value.trust, ContextSource::Transcript);
                    }
                }
                ContextSelector::EnvironmentFacts => {
                    if let Some(value) = &input.environment {
                        builder.push(value.text.clone(), value.trust, ContextSource::Environment);
                    }
                }
                ContextSelector::Unknown => {}
            }
        }

        if plan.recall_memory && builder.remaining_bytes() > 0 {
            let segment = FileMemory.recall_with_slot(
                &stores,
                &plan.task,
                &MemBudget::default(),
                memory_strategy,
            );
            if !segment.is_empty() {
                builder.push(
                    segment.render(),
                    segment.governing_trust(),
                    ContextSource::Memory,
                );
            }
        }

        if plan.include_skills && builder.remaining_bytes() > 0 {
            let catalog = skills::SkillCatalog::discover_for_operator_with_dependencies(
                input.home_dir.as_deref(),
                &workspace,
                &input.dependency_skill_dirs,
            );
            let active = skills::active_paths_from_text(&plan.task);
            let listing = catalog
                .listing_for_paths(SKILL_INDEX_BYTES.min(builder.remaining_bytes()), &active);
            if let Some(trust) = catalog.governing_trust() {
                builder.push(listing, trust, ContextSource::Skills);
            }
        }

        let grant = builder.finish();
        grant
            .validate_for(&plan.request)
            .map_err(|reason| ContextPortError(reason.into()))?;
        Ok(grant)
    }

    fn resolve_with_memory_audit(
        &self,
        plan: &ContextPlan,
        input: &ContextPortInput,
        memory_strategy: &dyn StrategySlot,
    ) -> Result<(ContextGrant, Option<MemoryRecallAudit>), ContextPortError> {
        let grant = self.resolve_with_memory_strategy(plan, input, memory_strategy)?;
        if !plan.recall_memory {
            return Ok((grant, None));
        }
        let workspace = explicit_workspace(input)?;
        let stores = memory_stores(&workspace, input.home_dir.as_deref());
        let audit = FileMemory::audit_recall_with_slot(
            &stores,
            &plan.task,
            &MemBudget::default(),
            memory_strategy,
        );
        Ok((grant, Some(audit)))
    }
}

/// Deterministic in-memory adapter used before the reducer's real port wiring lands.
#[derive(Debug, Clone, Default)]
pub struct PortStub {
    segments: Vec<ContextSegment>,
}

impl PortStub {
    pub fn new(segments: Vec<ContextSegment>) -> Self {
        Self { segments }
    }
}

impl ContextPort for PortStub {
    fn resolve(
        &self,
        plan: &ContextPlan,
        _input: &ContextPortInput,
    ) -> Result<ContextGrant, ContextPortError> {
        plan.request
            .validate()
            .map_err(|reason| ContextPortError(reason.into()))?;
        let mut builder = GrantBuilder::new(&plan.request);
        for segment in self.segments.iter().take(MAX_CONTEXT_SEGMENTS) {
            builder.push(segment.text.clone(), segment.trust, segment.source);
        }
        let grant = builder.finish();
        grant
            .validate_for(&plan.request)
            .map_err(|reason| ContextPortError(reason.into()))?;
        Ok(grant)
    }
}

struct GrantBuilder<'a> {
    request: &'a iteron_protocol::context::ContextRequest,
    segments: Vec<ContextSegment>,
    bytes: usize,
}

impl<'a> GrantBuilder<'a> {
    fn new(request: &'a iteron_protocol::context::ContextRequest) -> Self {
        Self {
            request,
            segments: Vec::new(),
            bytes: 0,
        }
    }

    fn remaining_bytes(&self) -> usize {
        (self.request.max_bytes as usize).saturating_sub(self.bytes)
    }

    fn push(&mut self, text: String, trust: Trust, source: ContextSource) {
        if text.is_empty()
            || self.segments.len() == MAX_CONTEXT_SEGMENTS
            || self.remaining_bytes() == 0
        {
            return;
        }
        let text = bounded_text(&text, self.remaining_bytes());
        if text.is_empty() {
            return;
        }
        self.bytes = self.bytes.saturating_add(text.len());
        self.segments.push(ContextSegment {
            text,
            trust: trust.min(self.request.trust_ceiling),
            source,
        });
    }

    fn finish(self) -> ContextGrant {
        ContextGrant {
            request_id: self.request.request_id,
            segments: self.segments,
            bytes: self.bytes as u32,
        }
    }
}

fn bounded_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    const MARKER: &str = "\n… (truncated)";
    if max_bytes <= MARKER.len() {
        return String::new();
    }
    let mut end = max_bytes - MARKER.len();
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut output = String::with_capacity(max_bytes);
    output.push_str(&text[..end]);
    output.push_str(MARKER);
    output
}

fn explicit_workspace(input: &ContextPortInput) -> Result<PathBuf, ContextPortError> {
    if input.workspace.as_os_str().is_empty() || !input.workspace.is_absolute() {
        return Err(ContextPortError(
            "context port requires an explicit absolute workspace".into(),
        ));
    }
    Ok(input.workspace.clone())
}

fn confined_root(workspace: &Path, root: &str) -> Result<PathBuf, ContextPortError> {
    let path = Path::new(root);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ContextPortError(
            "context selector root must stay workspace-relative".into(),
        ));
    }
    Ok(workspace.join(path))
}

fn memory_stores(workspace: &Path, home_dir: Option<&Path>) -> Vec<MemStore> {
    let mut stores = Vec::new();
    if let Some(home_dir) = home_dir {
        stores.push(MemStore::user(home_dir));
    }
    // Frontend instruction bytes have their own durable segment; do not attach instruction
    // discovery to this compatibility recall store or the same files would enter context twice.
    stores.push(MemStore::new(
        home::path(workspace, "memory"),
        MemTier::Project,
        true,
    ));
    stores
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContextSlotObservation, ContextStrategy};
    use iteron_protocol::Capability;
    use iteron_protocol::capability_set::CapabilitySet;
    use iteron_protocol::context::{ContextSource, RequestId};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_workspace() -> PathBuf {
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let workspace =
            std::env::temp_dir().join(format!("core-context-port-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        workspace
    }

    fn plan(max_bytes: u32) -> ContextPlan {
        let strategy = ContextStrategy::default();
        let mut input = ContextSlotObservation::baseline(RequestId(17), "src/lib.rs");
        input.max_bytes = max_bytes;
        input.instruction_scopes.clear();
        input.include_environment = false;
        input.recall_memory = false;
        input.include_skills = false;
        strategy
            .select(&input, CapabilitySet::only(Capability::ReadOnly))
            .unwrap()
    }

    #[test]
    fn port_stub_is_byte_deterministic_and_honors_every_sampled_ceiling() {
        let stub = PortStub::new(vec![ContextSegment {
            text: "写".repeat(256),
            trust: Trust::Workspace,
            source: ContextSource::RepoOutline,
        }]);
        for ceiling in (0..=1_024).chain([4_095, 4_096, 65_535, 131_072]) {
            let plan = plan(ceiling);
            let first = stub.resolve(&plan, &ContextPortInput::default()).unwrap();
            let second = stub.resolve(&plan, &ContextPortInput::default()).unwrap();
            assert_eq!(first, second);
            assert!(first.bytes <= ceiling);
            first.validate_for(&plan.request).unwrap();
        }
    }

    #[test]
    fn trust_is_only_narrowed() {
        let stub = PortStub::new(vec![ContextSegment {
            text: "operator bytes".into(),
            trust: Trust::Trusted,
            source: ContextSource::Environment,
        }]);
        let grant = stub
            .resolve(&plan(128), &ContextPortInput::default())
            .unwrap();
        assert_eq!(grant.segments[0].trust, Trust::Workspace);
    }

    #[test]
    fn filesystem_adapter_requires_an_explicit_workspace() {
        let error = DefaultContextPort
            .resolve(&plan(128), &ContextPortInput::default())
            .unwrap_err();
        assert!(error.0.contains("absolute workspace"));
    }

    #[test]
    fn filesystem_adapter_covers_every_frozen_selector_and_local_skills_source() {
        let workspace = temp_workspace();
        std::fs::create_dir_all(workspace.join("src")).unwrap();
        std::fs::write(workspace.join("src/lib.rs"), "pub fn selected() {}\n").unwrap();
        std::fs::write(workspace.join("AGENTS.md"), "project instructions\n").unwrap();
        std::fs::create_dir_all(home::path(&workspace, "memory")).unwrap();
        std::fs::write(
            home::path(&workspace, "memory").join("named-fact.md"),
            "# Named fact\nselector coverage\n",
        )
        .unwrap();
        let skill_dir = home::path(&workspace, "skills").join("coverage");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: coverage\ndescription: Selector coverage skill\n---\nbody\n",
        )
        .unwrap();

        let mut observation = ContextSlotObservation::baseline(RequestId(23), "src/lib.rs");
        observation.instruction_scopes = vec![iteron_protocol::context::InstructionScope::Project];
        observation.memory_keys = vec!["named-fact".into()];
        observation.transcript_turns = 1;
        observation.recall_memory = false;
        let plan = ContextStrategy::default()
            .select(&observation, CapabilitySet::only(Capability::ReadOnly))
            .unwrap();
        let grant = DefaultContextPort
            .resolve(
                &plan,
                &ContextPortInput {
                    workspace: workspace.clone(),
                    home_dir: None,
                    active_dir: workspace.clone(),
                    environment: Some(ContextValue {
                        text: "environment fact".into(),
                        trust: Trust::Workspace,
                    }),
                    transcript: vec![ContextValue {
                        text: "prior transcript".into(),
                        trust: Trust::Trusted,
                    }],
                    dependency_skill_dirs: Vec::new(),
                },
            )
            .unwrap();

        for source in [
            ContextSource::RepoOutline,
            ContextSource::Instructions,
            ContextSource::Memory,
            ContextSource::Transcript,
            ContextSource::Environment,
            ContextSource::Skills,
        ] {
            assert!(
                grant
                    .segments
                    .iter()
                    .any(|segment| segment.source == source),
                "missing {source:?}"
            );
        }
        grant.validate_for(&plan.request).unwrap();
        let _ = std::fs::remove_dir_all(workspace);
    }
}
