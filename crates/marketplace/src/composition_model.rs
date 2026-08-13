//! The vocabulary of composition: what a plugin may contribute, where the contribution lands, and
//! what makes a manifest indefensible.
//!
//! This module holds only shapes and the per-manifest admission check. The merge itself is in
//! `composition`. The split is deliberate: admission must be decidable from **one manifest alone**,
//! with no reference to its neighbours, or a plugin's fate would depend on who else is installed --
//! which is exactly the coupling that makes one bad plugin able to take down the rest.

use iteron_protocol::capability_set::CapabilitySet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Longest slot key accepted. Keys are echoed into the operator's UI and into the model's prompt
/// (a skill name is a tool argument), so they are bounded and ASCII.
pub const MAX_SLOT_KEY_BYTES: usize = 64;

/// Longest detail string (a description, a hook action, a server command line) accepted.
pub const MAX_DETAIL_BYTES: usize = 4096;

/// Most contributions one plugin may declare.
///
/// The bound is **per plugin, never global**. A global cap on, say, hooks per event would make one
/// plugin's admission depend on how many hooks its neighbours declared and on who was evaluated
/// first -- reintroducing exactly the coupling this design exists to remove. A per-plugin bound
/// blames the manifest that is actually oversized, and bounds the total at plugins x this number.
pub const MAX_CONTRIBUTIONS_PER_PLUGIN: usize = 256;
pub const MAX_PLUGIN_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_PLUGIN_REQUIREMENTS: usize = 64;

/// The extension points a plugin may contribute to.
///
/// The distinction that matters is not what each one does at runtime but whether two plugins can
/// hold the same key at once. A skill name, an agent name and a language id each address exactly
/// one implementation -- the model asks for `review` and one thing must answer. A hook event
/// addresses a *chain*: every subscriber runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Skill,
    Agent,
    Hook,
    McpServer,
    LanguageServer,
}

impl Surface {
    /// The stable prefix used in slot addresses and in operator-facing text.
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Skill => "skill",
            Surface::Agent => "agent",
            Surface::Hook => "hook",
            Surface::McpServer => "mcp",
            Surface::LanguageServer => "lsp",
        }
    }

    /// Whether holding a key on this surface excludes every other holder.
    pub fn is_exclusive(self) -> bool {
        !matches!(self, Surface::Hook)
    }
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A composed address: the surface plus the key within it.
///
/// Carrying the surface in the address is what lets a skill and an agent both be called `review`
/// without contesting each other. Keying by bare name would silently merge two unrelated things.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Slot {
    pub surface: Surface,
    pub key: String,
}

impl Slot {
    pub fn new(surface: Surface, key: impl Into<String>) -> Self {
        Self {
            surface,
            key: key.into(),
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.surface.as_str(), self.key)
    }
}

/// One thing a plugin contributes.
///
/// The payload is deliberately thin: composition decides **who owns a slot**, not what the artifact
/// contains. The runtime loads the artifact from `(plugin, slot)` after composition has said which
/// plugin won. Keeping bodies out of here is what keeps composition a pure, cheap, re-runnable
/// function -- which is what quarantine needs (see `composition::Host`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Contribution {
    Skill { name: String, description: String },
    Agent { name: String, description: String },
    Hook { event: String, action: String },
    McpServer { name: String, binding: String },
    LanguageServer { language: String, command: String },
}

impl Contribution {
    pub fn surface(&self) -> Surface {
        match self {
            Contribution::Skill { .. } => Surface::Skill,
            Contribution::Agent { .. } => Surface::Agent,
            Contribution::Hook { .. } => Surface::Hook,
            Contribution::McpServer { .. } => Surface::McpServer,
            Contribution::LanguageServer { .. } => Surface::LanguageServer,
        }
    }

    /// The address this contribution claims.
    pub fn slot(&self) -> Slot {
        let key = match self {
            Contribution::Skill { name, .. } | Contribution::Agent { name, .. } => name,
            Contribution::Hook { event, .. } => event,
            Contribution::McpServer { name, .. } => name,
            Contribution::LanguageServer { language, .. } => language,
        };
        Slot::new(self.surface(), key.clone())
    }

    /// The operator-facing payload: a description, a hook action, or a server command line.
    pub fn detail(&self) -> &str {
        match self {
            Contribution::Skill { description, .. } | Contribution::Agent { description, .. } => {
                description
            }
            Contribution::Hook { action, .. } => action,
            Contribution::McpServer { binding, .. } => binding,
            Contribution::LanguageServer { command, .. } => command,
        }
    }
}

/// Where an installed plugin is visible. User plugins are globally available; workspace plugins
/// are admitted only while composing a workspace runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginScope {
    #[default]
    User,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    User,
    Workspace,
}

impl RuntimeScope {
    pub(crate) fn admits(self, plugin: PluginScope) -> bool {
        matches!(plugin, PluginScope::User)
            || matches!((self, plugin), (Self::Workspace, PluginScope::Workspace))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub plugin: String,
    pub minimum: crate::Version,
}

/// What one plugin declares.
///
/// `precedence` is the **operator's** ranking, not the plugin's own claim about its importance: a
/// plugin that could raise its own precedence would win every contest by asserting it should.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub plugin: String,
    #[serde(default)]
    pub version: crate::Version,
    #[serde(default)]
    pub scope: PluginScope,
    pub precedence: u32,
    #[serde(default)]
    pub requires: Vec<Requirement>,
    #[serde(default)]
    pub capabilities: CapabilitySet,
    pub contributions: Vec<Contribution>,
}

impl Manifest {
    pub fn new(plugin: impl Into<String>, precedence: u32) -> Self {
        Self {
            plugin: plugin.into(),
            version: crate::Version::default(),
            scope: PluginScope::default(),
            precedence,
            requires: Vec::new(),
            capabilities: CapabilitySet::none(),
            contributions: Vec::new(),
        }
    }

    pub fn parse_json(bytes: &[u8]) -> Result<Self, Defect> {
        if bytes.len()
            > iteron_tunables::param_integer(
                "marketplace.composition_model.max_plugin_manifest_bytes",
                MAX_PLUGIN_MANIFEST_BYTES,
            )
        {
            return Err(Defect::ManifestTooLarge { count: bytes.len() });
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|_| Defect::MalformedJson)?;
        inspect(&manifest)?;
        Ok(manifest)
    }

    #[must_use]
    pub fn at_version(mut self, version: crate::Version) -> Self {
        self.version = version;
        self
    }

    #[must_use]
    pub fn scoped(mut self, scope: PluginScope) -> Self {
        self.scope = scope;
        self
    }

    #[must_use]
    pub fn requiring(mut self, plugin: impl Into<String>, minimum: crate::Version) -> Self {
        self.requires.push(Requirement {
            plugin: plugin.into(),
            minimum,
        });
        self
    }

    #[must_use]
    pub fn with_capabilities(mut self, capabilities: CapabilitySet) -> Self {
        self.capabilities = capabilities;
        self
    }

    #[must_use]
    pub fn with(mut self, contribution: Contribution) -> Self {
        self.contributions.push(contribution);
        self
    }
}

/// Why a manifest cannot be admitted.
///
/// Every variant names the plugin's own manifest as the problem. Nothing here can be caused by a
/// neighbour, which is the property that makes refusal isolating rather than contagious.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Defect {
    #[error("plugin manifest is not valid bounded JSON")]
    MalformedJson,
    #[error("plugin manifest is {count} bytes; the limit is {MAX_PLUGIN_MANIFEST_BYTES}")]
    ManifestTooLarge { count: usize },
    #[error("plugin id {plugin:?} is not a valid identifier")]
    InvalidPluginId { plugin: String },
    #[error(
        "contribution #{index} ({surface}): key {key:?} is not a plain slug of 1..={MAX_SLOT_KEY_BYTES} bytes"
    )]
    InvalidSlotKey {
        index: usize,
        surface: Surface,
        key: String,
    },
    #[error(
        "contribution #{index} ({slot}): detail is {problem}, so the contribution cannot be described to the operator"
    )]
    UnusableDetail {
        index: usize,
        slot: Slot,
        problem: &'static str,
    },
    #[error(
        "contribution #{index} claims {slot} which contribution #{first} already claims; which one was meant cannot be known"
    )]
    DuplicateClaim {
        index: usize,
        first: usize,
        slot: Slot,
    },
    #[error("declares {count} contributions; the limit is {MAX_CONTRIBUTIONS_PER_PLUGIN}")]
    TooManyContributions { count: usize },
    #[error(
        "plugin id {plugin:?} is declared by {count} manifests; none of them can be trusted to be the one meant"
    )]
    DuplicatePluginId { plugin: String, count: usize },
    #[error("declares too many dependencies; the limit is {MAX_PLUGIN_REQUIREMENTS}")]
    TooManyRequirements,
    #[error("requires invalid plugin id {plugin:?}")]
    InvalidRequirement { plugin: String },
    #[error("requires {plugin}>={minimum}, which is not present in this runtime scope")]
    MissingDependency {
        plugin: String,
        minimum: crate::Version,
    },
    #[error("requires {plugin}>={minimum}, but only {actual} is installed")]
    DependencyTooOld {
        plugin: String,
        minimum: crate::Version,
        actual: crate::Version,
    },
}

/// A manifest that was not admitted, and why. Retained rather than dropped: a plugin that silently
/// contributes nothing is indistinguishable from one that was never installed, and the operator who
/// wonders why their skill is missing has no way to find out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub plugin: String,
    pub defect: Defect,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.plugin, self.defect)
    }
}

/// A key is a plain ASCII slug.
///
/// Stricter than [`crate::valid_name`], which admits `.` because a plugin id appears in paths.
/// Slot keys are echoed into the model's prompt and used as tool arguments, so they follow the
/// same rule the skill loader already enforces (`iteron-ctx` `skills.rs`: "not a plain slug").
fn valid_slot_key(key: &str) -> bool {
    !key.is_empty()
        && key.len()
            <= iteron_tunables::param_integer(
                "marketplace.composition_model.max_slot_key_bytes",
                MAX_SLOT_KEY_BYTES,
            )
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Why a detail string is unusable, or `None` if it is fine.
fn detail_problem(detail: &str) -> Option<&'static str> {
    if detail.trim().is_empty() {
        return Some("empty");
    }
    if detail.len()
        > iteron_tunables::param_integer(
            "marketplace.composition_model.max_detail_bytes",
            MAX_DETAIL_BYTES,
        )
    {
        return Some("longer than the declared limit");
    }
    if detail.chars().any(char::is_control) {
        // Details are rendered into a line-oriented operator UI; a control character there can
        // forge a second line that looks like it came from the host.
        return Some("carrying a control character");
    }
    None
}

/// Decide whether one manifest may be admitted, using nothing but the manifest.
///
/// The first defect found is reported rather than a list, and the order is identity first, then
/// size, then per-contribution shape: a manifest whose id is unusable has no defensible way to
/// report anything else about itself.
pub(crate) fn inspect(manifest: &Manifest) -> Result<(), Defect> {
    if !crate::valid_name(&manifest.plugin) {
        return Err(Defect::InvalidPluginId {
            plugin: manifest.plugin.clone(),
        });
    }
    if manifest.contributions.len()
        > iteron_tunables::param_integer(
            "marketplace.composition_model.max_contributions_per_plugin",
            MAX_CONTRIBUTIONS_PER_PLUGIN,
        )
    {
        return Err(Defect::TooManyContributions {
            count: manifest.contributions.len(),
        });
    }
    if manifest.requires.len()
        > iteron_tunables::param_integer(
            "marketplace.composition_model.max_plugin_requirements",
            MAX_PLUGIN_REQUIREMENTS,
        )
    {
        return Err(Defect::TooManyRequirements);
    }
    let mut requirements = BTreeSet::new();
    for requirement in &manifest.requires {
        if !crate::valid_name(&requirement.plugin)
            || requirement.plugin == manifest.plugin
            || !requirements.insert(requirement.plugin.as_str())
        {
            return Err(Defect::InvalidRequirement {
                plugin: requirement.plugin.clone(),
            });
        }
    }

    // `claim` is the slot for an exclusive surface, and the slot *plus the action* for a hook: a
    // plugin may subscribe twice to one event with different actions, but declaring the identical
    // action twice would run the side effect twice, which no author intends.
    let mut claimed: BTreeSet<(Slot, &str)> = BTreeSet::new();
    let mut first_claim: Vec<(Slot, &str, usize)> = Vec::new();
    for (index, contribution) in manifest.contributions.iter().enumerate() {
        let slot = contribution.slot();
        if !valid_slot_key(&slot.key) {
            return Err(Defect::InvalidSlotKey {
                index,
                surface: slot.surface,
                key: slot.key,
            });
        }
        let detail = contribution.detail();
        if let Some(problem) = detail_problem(detail) {
            return Err(Defect::UnusableDetail {
                index,
                slot,
                problem,
            });
        }
        let discriminator = if slot.surface.is_exclusive() {
            ""
        } else {
            detail
        };
        if !claimed.insert((slot.clone(), discriminator)) {
            let first = first_claim
                .iter()
                .find(|(s, d, _)| *s == slot && *d == discriminator)
                .map_or(index, |(_, _, i)| *i);
            return Err(Defect::DuplicateClaim { index, first, slot });
        }
        first_claim.push((slot, discriminator, index));
    }
    Ok(())
}
