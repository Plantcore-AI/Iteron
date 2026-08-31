//! Private semantic roles used by controller strategy, separate from capability authority.

use crate::{Registry, ToolError, ToolOrigin, ToolResult, ToolSpec, ToolUse, boxfut};
use std::path::{Path, PathBuf};

/// Stable, tool-owned evidence classification. Runtime strategy consumes this typed result rather
/// than depending on a language-, framework-, or payload-specific grep annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceEvidenceOutcome {
    /// Replay-only compatibility variant. Current tools and parsers never produce it; positive
    /// repair evidence is represented by [`crate::RepairEvidenceReceipt`].
    Compared,
    Insufficient,
}

/// Closed reasons emitted by bounded native workspace-evidence tools. `Unknown` preserves a
/// fail-closed typed result when a newer tool reason reaches an older controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceEvidenceInsufficiencyReason {
    CausalContrastUnproven,
    CoverageIncomplete,
    NoFocusedContext,
    SingleContext,
    NoMatch,
    SourceAnchorsRequired,
    UndifferentiatedContexts,
    SingleFileOnly,
    Unknown,
}

/// Allocation-free controller classification of a successful native tool result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceEvidence {
    /// Replay-only compatibility variant. Current tools and parsers never produce it.
    Compared,
    Insufficient(WorkspaceEvidenceInsufficiencyReason),
}

/// Legacy wire prefix retained so older trace readers compile. It is deliberately not parsed:
/// lexical tool output is no longer positive repair evidence.
pub const WORKSPACE_EVIDENCE_COMPARED_MARKER: &str = "[workspace evidence: comparison complete;";
pub const WORKSPACE_EVIDENCE_INSUFFICIENT_MARKER: &str = "[workspace evidence: observation;";
const MAX_WORKSPACE_EVIDENCE_MARKER_LINE_BYTES: usize = 512;

fn max_workspace_evidence_marker_line_bytes() -> usize {
    iteron_tunables::param_usize(
        "tools.tool_purpose.max_workspace_evidence_marker_line_bytes",
        MAX_WORKSPACE_EVIDENCE_MARKER_LINE_BYTES,
    )
}

fn workspace_evidence_marker_line(content: &str) -> Option<&str> {
    let newline = content
        .as_bytes()
        .iter()
        .take(max_workspace_evidence_marker_line_bytes().saturating_add(1))
        .position(|byte| *byte == b'\n');
    let end = match newline {
        Some(end) => end,
        None if content.len() <= max_workspace_evidence_marker_line_bytes() => content.len(),
        None => return None,
    };
    content.get(..end)
}

fn insufficiency_reason(reason: &str) -> WorkspaceEvidenceInsufficiencyReason {
    match reason {
        "causal_contrast_unproven" => WorkspaceEvidenceInsufficiencyReason::CausalContrastUnproven,
        "coverage_incomplete" => WorkspaceEvidenceInsufficiencyReason::CoverageIncomplete,
        "no_focused_context" => WorkspaceEvidenceInsufficiencyReason::NoFocusedContext,
        "single_context" => WorkspaceEvidenceInsufficiencyReason::SingleContext,
        "no_match" => WorkspaceEvidenceInsufficiencyReason::NoMatch,
        "source_anchors_required" => WorkspaceEvidenceInsufficiencyReason::SourceAnchorsRequired,
        "undifferentiated_contexts" => {
            WorkspaceEvidenceInsufficiencyReason::UndifferentiatedContexts
        }
        // Retain typed replay compatibility with runs emitted before the causal-contrast gate.
        "single_file_only" => WorkspaceEvidenceInsufficiencyReason::SingleFileOnly,
        _ => WorkspaceEvidenceInsufficiencyReason::Unknown,
    }
}

/// Parse only the first, size-bounded tool-owned marker line. Repository content later in a tool
/// result cannot masquerade as controller evidence, and parsing allocates no memory proportional
/// to the result body.
pub fn workspace_evidence(content: &str) -> Option<WorkspaceEvidence> {
    let marker = workspace_evidence_marker_line(content)?;
    if marker.starts_with(WORKSPACE_EVIDENCE_COMPARED_MARKER) {
        return None;
    }
    let fields = marker.strip_prefix(WORKSPACE_EVIDENCE_INSUFFICIENT_MARKER)?;
    let reason = fields.strip_prefix(" reason=")?.split_once(';')?.0;
    Some(WorkspaceEvidence::Insufficient(insufficiency_reason(
        reason,
    )))
}

/// Typed evidence carried by one successful tool result. Failed results never advance or close a
/// controller evidence phase even if their diagnostic text happens to contain a marker.
pub fn tool_result_workspace_evidence(result: &ToolResult) -> Option<WorkspaceEvidence> {
    (!result.is_error)
        .then(|| workspace_evidence(&result.content))
        .flatten()
}

/// Classify only markers emitted by bounded native tools. Keeping parsing here makes the wire
/// text an implementation detail and gives older controllers one provider-independent coarse
/// predicate. New controllers should use [`tool_result_workspace_evidence`] to retain the typed
/// insufficiency reason.
pub fn workspace_evidence_outcome(content: &str) -> Option<WorkspaceEvidenceOutcome> {
    match workspace_evidence(content)? {
        WorkspaceEvidence::Compared => Some(WorkspaceEvidenceOutcome::Compared),
        WorkspaceEvidence::Insufficient(_) => Some(WorkspaceEvidenceOutcome::Insufficient),
    }
}

/// Capability answers what a tool may affect; purpose answers whether a successful call is an
/// actual candidate change. Keeping those questions separate prevents orchestration or shell
/// tools from masquerading as code progress merely because they carry broad authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ToolPurpose {
    General,
    TargetedObservation,
    CandidateChange,
}

impl Registry {
    /// Whether this exact registered tool is a controller-recognized candidate mutation. The
    /// answer comes from registration semantics, never from its name, provider, arguments, or
    /// capability class.
    pub fn is_candidate_change_tool(&self, name: &str) -> bool {
        self.tools
            .iter()
            .any(|tool| tool.spec.name == name && tool.purpose == ToolPurpose::CandidateChange)
    }

    /// Whether this registered tool belongs in the ordinary pre-mutation evidence surface.
    /// Candidate changes remain hidden until a source-anchored repair receipt selects an exact
    /// repair path; the ordinary authority gate still decides whether a retained observation is
    /// admissible.
    pub fn is_patch_trial_tool(&self, name: &str) -> bool {
        self.tools.iter().any(|tool| {
            tool.spec.name == name
                && (tool.spec.capability == iteron_protocol::Capability::ReadOnly
                    || tool.purpose == ToolPurpose::TargetedObservation)
        })
    }

    /// Whether this registered built-in belongs in the post-mutation review surface.
    ///
    /// This is intentionally narrower than patch trial: repository discovery and tool discovery
    /// cannot produce evidence that justifies an already-selected candidate. Exact source reads,
    /// reversible candidate revisions, diff inspection, and execution needed by a focused
    /// verifier remain available. Process continuation tools stay visible so a long-running build
    /// or test started by `bash` can still be polled or terminated cleanly.
    pub fn is_candidate_review_tool(&self, name: &str) -> bool {
        self.is_candidate_change_tool(name)
            || self.tools.iter().any(|tool| {
                tool.spec.name == name
                    && matches!(
                        tool.spec.name.as_str(),
                        "read_file"
                            | "git_diff"
                            | "bash"
                            | "process_poll"
                            | "process_write"
                            | "process_stop"
                            | "process_resize"
                    )
            })
    }

    /// Whether this exact call names only files in the candidate workspace.
    ///
    /// File tools intentionally retain host-path authority outside the workspace, but an external
    /// write is not progress on the candidate under repair. Strategy gates therefore use this
    /// stricter semantic predicate while ordinary admission remains unchanged. Existing absolute
    /// paths inside the workspace are accepted after canonical/symlink resolution.
    pub fn is_workspace_candidate_change(&self, call: &ToolUse, workspace: &Path) -> bool {
        self.workspace_candidate_paths(call, workspace)
            .is_some_and(|paths| !paths.is_empty())
    }

    /// Resolve the bounded file population named by a structured candidate change. The returned
    /// paths are canonical-root confined but may name a missing leaf that `write_file` is about to
    /// create. Runtime convergence fingerprints only this typed set, never the whole repository.
    pub fn workspace_candidate_paths(
        &self,
        call: &ToolUse,
        workspace: &Path,
    ) -> Option<Vec<PathBuf>> {
        if !self.is_candidate_change_tool(&call.name) {
            return None;
        }
        let paths = candidate_paths(call)?;
        let Ok(root) = workspace.canonicalize() else {
            return None;
        };
        paths
            .into_iter()
            .map(|path| {
                crate::resolve_from_canonical_root(&root, path)
                    .ok()
                    .filter(|resolved| resolved.starts_with(&root))
            })
            .collect()
    }

    /// Whether this exact call is a bounded native observation scoped to the candidate workspace.
    ///
    /// The convergence controller uses this narrower role to detect the transition from broad
    /// localization to bounded contract evidence. It deliberately excludes shell, traversal,
    /// network, and orchestration tools even when those tools could perform a read, because their
    /// arguments do not carry the same bounded semantic contract.
    pub fn is_workspace_targeted_observation(&self, call: &ToolUse, workspace: &Path) -> bool {
        if !self.tools.iter().any(|tool| {
            tool.spec.name == call.name && tool.purpose == ToolPurpose::TargetedObservation
        }) {
            return false;
        }
        if call.name == crate::SUBMIT_REPAIR_EVIDENCE {
            return self.is_repair_evidence_submission(call, workspace);
        }
        let Some(path) = bounded_targeted_observation_path(call) else {
            return false;
        };
        let Ok(root) = workspace.canonicalize() else {
            return false;
        };
        crate::resolve_from_canonical_root(&root, path).is_ok_and(|resolved| {
            if !resolved.starts_with(&root) {
                return false;
            }
            match call.name.as_str() {
                // A subtree name alone is still localization. Context makes a grep call a
                // bounded contract observation; an exact file is already a bounded target.
                "grep" => {
                    resolved.is_file()
                        || call
                            .input
                            .get("context_lines")
                            .and_then(serde_json::Value::as_u64)
                            .is_some_and(|lines| lines > 0)
                        || call
                            .input
                            .get("related_terms")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|terms| !terms.is_empty())
                }
                "read_file" => true,
                _ => false,
            }
        })
    }

    /// Whether this exact call is a native read-only localization observation confined to the
    /// candidate workspace.
    ///
    /// This role is deliberately broader than [`Self::is_workspace_targeted_observation`]: plain
    /// root grep plus native glob/listing are useful for measuring repeated discovery scopes, but
    /// they do not become bounded contract evidence. Runtime strategy advances localization only
    /// after the corresponding tool result succeeds.
    pub fn is_workspace_localization_observation(&self, call: &ToolUse, workspace: &Path) -> bool {
        if !matches!(
            call.name.as_str(),
            "grep" | "glob" | "list_dir" | "read_file"
        ) || !self.tools.iter().any(|tool| {
            tool.spec.name == call.name
                && tool.spec.purity == iteron_protocol::Purity::Pure
                && tool.spec.capability == iteron_protocol::Capability::ReadOnly
        }) {
            return false;
        }

        let path = match call.name.as_str() {
            "read_file" => call
                .input
                .get("path")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|path| !path.is_empty()),
            "grep" | "glob" | "list_dir" => Some(
                call.input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                    .unwrap_or("."),
            ),
            _ => None,
        };
        let (Some(path), Ok(root)) = (path, workspace.canonicalize()) else {
            return false;
        };
        crate::resolve_from_canonical_root(&root, path)
            .is_ok_and(|resolved| resolved.starts_with(&root))
    }

    /// Whether this call targets the registered source-anchored repair-evidence tool and every
    /// declared source/repair path resolves inside the candidate workspace. This is a cheap
    /// controller predicate only; the executor still performs no-follow traversal, exact line,
    /// graph, and repair-intent validation before it can issue a receipt.
    pub fn is_repair_evidence_submission(&self, call: &ToolUse, workspace: &Path) -> bool {
        if call.name != crate::SUBMIT_REPAIR_EVIDENCE
            || !self.tools.iter().any(|tool| {
                tool.spec.name == call.name && tool.purpose == ToolPurpose::TargetedObservation
            })
        {
            return false;
        }
        let Some(paths) = crate::repair_evidence::submission_paths(&call.input) else {
            return false;
        };
        let Ok(root) = workspace.canonicalize() else {
            return false;
        };
        paths.into_iter().all(|path| {
            crate::resolve_from_canonical_root(&root, path)
                .is_ok_and(|resolved| resolved.starts_with(&root))
        })
    }

    /// Compatibility predicate for controllers that classify a grep as a bounded evidence
    /// observation. It does not confer causal or repair authority; positive evidence now requires
    /// a [`crate::RepairEvidenceReceipt`].
    pub fn is_workspace_evidence_comparison(&self, call: &ToolUse, workspace: &Path) -> bool {
        if call.name != "grep"
            || !self.tools.iter().any(|tool| {
                tool.spec.name == call.name && tool.purpose == ToolPurpose::TargetedObservation
            })
        {
            return false;
        }
        let relative = call
            .input
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(".");
        let Ok(root) = workspace.canonicalize() else {
            return false;
        };
        crate::resolve_from_canonical_root(&root, relative)
            .is_ok_and(|resolved| resolved.starts_with(&root))
            && grep_call_requests_evidence(call)
    }

    /// Compatibility alias for controllers compiled against the earlier name.
    pub fn is_workspace_contract_comparison(&self, call: &ToolUse, workspace: &Path) -> bool {
        self.is_workspace_evidence_comparison(call, workspace)
    }

    /// Register a built-in native observation eligible for evidence-phase tracking. This is
    /// strategy metadata only; normal capability admission remains authoritative.
    pub(crate) fn push_targeted_observation_tool(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> boxfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        self.push_tool_with_origin_and_purpose(
            spec,
            run,
            ToolOrigin::BuiltIn,
            ToolPurpose::TargetedObservation,
        )
    }

    /// Register a built-in whose successful execution changes the candidate under repair. This
    /// metadata is private controller strategy, not authority: admission still uses the ToolSpec's
    /// capability and the normal effect broker.
    pub(crate) fn push_candidate_change_tool(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> boxfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        self.push_tool_with_origin_and_purpose(
            spec,
            run,
            ToolOrigin::BuiltIn,
            ToolPurpose::CandidateChange,
        )
    }
}

fn candidate_paths(call: &ToolUse) -> Option<Vec<&str>> {
    match call.name.as_str() {
        "edit" | "write_file" => call
            .input
            .get("path")
            .and_then(serde_json::Value::as_str)
            .map(|path| vec![path]),
        "apply_patch" => call
            .input
            .get("files")?
            .as_array()?
            .iter()
            .map(|file| file.get("path")?.as_str())
            .collect(),
        _ => None,
    }
}

fn bounded_targeted_observation_path(call: &ToolUse) -> Option<&str> {
    match call.name.as_str() {
        // The native reader is policy-bounded even when the caller omits a range. Once its path
        // resolves to an exact file, the controller has a concrete target; range quality remains
        // prompt/tool guidance rather than a false localization signal.
        "read_file" => call.input.get("path")?.as_str(),
        "grep" => call
            .input
            .get("path")
            .and_then(serde_json::Value::as_str)
            .filter(|path| !matches!(path.trim(), "" | "." | "./"))
            .or_else(|| {
                (call
                    .input
                    .get("context_lines")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|lines| lines > 0)
                    || call
                        .input
                        .get("related_terms")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|terms| !terms.is_empty()))
                .then_some(".")
            }),
        _ => None,
    }
}

fn grep_call_requests_evidence(call: &ToolUse) -> bool {
    call.input
        .get("path")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|path| !matches!(path.trim(), "" | "." | "./"))
        || call
            .input
            .get("pattern")
            .and_then(serde_json::Value::as_str)
            .is_some_and(crate::grep_tool::is_stable_evidence_anchor)
        || call
            .input
            .get("context_lines")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|lines| lines > 0)
        || call
            .input
            .get("related_terms")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|terms| !terms.is_empty())
}
