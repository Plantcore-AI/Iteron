//! Private semantic roles used by controller strategy, separate from capability authority.

use crate::{Registry, ToolError, ToolOrigin, ToolSpec, ToolUse, boxfut};
use std::path::PathBuf;

/// Capability answers what a tool may affect; purpose answers whether a successful call is an
/// actual candidate change. Keeping those questions separate prevents orchestration or shell
/// tools from masquerading as code progress merely because they carry broad authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ToolPurpose {
    General,
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
