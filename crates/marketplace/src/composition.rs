//! Composing independently-authored plugins into one runtime surface.
//!
//! Installation (see the crate root) decides *whether* third-party code may be present. Composition
//! decides *what actually runs* once several such plugins are present at the same time, each
//! written by someone who never saw the others.
//!
//! # The three questions, and this module's answers
//!
//! **How are contributions merged?** By slot. Every contribution claims an address --
//! `skill:review`, `agent:review`, `mcp:files`, `lsp:rust`, `hook:pre-tool-use` -- and the surface is part of the
//! address, so a skill and an agent may share a name without ever meeting. Exclusive surfaces
//! (skill, agent, language server) resolve to exactly one owner; the hook surface is a chain and
//! every subscriber survives.
//!
//! **How are conflicts resolved deterministically?** By a total order that is a pure function of
//! the contribution *set*: operator precedence first, then plugin id ascending. Neither install
//! order, discovery order, nor map iteration order appears in it, so composing the same plugins in
//! any sequence produces byte-identical wiring. Every contest is reported with its winner, its
//! losers, and **which rule decided it** -- because "the operator ranked A above B" and "the two were
//! ranked equally and the tie was broken by spelling" are the same outcome with completely
//! different standing, and only the second one means nobody has actually chosen yet. The existing
//! agent catalogue resolves a name collision by "keeping the earlier definition"
//! (`crates/agents/src/catalog.rs`), which is order-dependent: the same two plugins can produce
//! different agents on different machines. That is the failure this module is built not to have.
//!
//! **What happens to a malformed contribution?** Its manifest is refused, and nothing else changes.
//! The refusal is decidable from that manifest alone (`composition_model::inspect`), so it cannot be
//! provoked by a neighbour; the refused plugin is removed from the input and the merge simply runs
//! without it. The resulting wiring is *equal* to the wiring of the remaining plugins composed on
//! their own -- not similar, equal -- and a slot the malformed plugin would have won falls to the
//! neighbour it would have shadowed.
//!
//! # Blast radius: the plugin, not the contribution
//!
//! A malformed contribution costs its plugin **all** of its contributions, not just the bad one.
//! This is a deliberate choice against the softer alternative of dropping one entry and keeping the
//! rest. Loading half of a manifest runs the plugin in a configuration its author never wrote and
//! never tested -- a skill whose companion hook is missing is not a degraded plugin, it is an
//! untested one -- and the operator sees a plugin that is present and behaving strangely rather than
//! one that is absent for a stated reason. Refusal is at the manifest boundary because that is the
//! unit somebody authored, reviewed and signed.
//!
//! # What this is not: crash isolation
//!
//! Everything here is *static* isolation. It contains a plugin whose declaration is indefensible.
//! It does nothing about a perfectly well-formed contribution whose code panics, blocks forever,
//! exhausts memory, or corrupts shared state at runtime -- in one address space, that still takes the
//! host down, and no amount of merge discipline changes it.
//!
//! What this module does provide is the half of crash isolation that must be pure: composition is a
//! cheap total function of the admitted set, so a member can be *dropped and the surface re-derived*
//! rather than patched in place ([`Host::quarantine`]). Dropping the owner of a slot promotes the
//! neighbour that was shadowed, deterministically, with no rebuild from a different input.
//!
//! Process-level isolation still needs, and this round does not build:
//!
//! - **A separate execution context per plugin** (subprocess or wasm instance), so a fault has a
//!   boundary to stop at. The `PluginId` this module already assigns is the identity that boundary
//!   would be keyed by.
//! - **A deadline and a cancellation path on every call**, since a hang is the failure mode a
//!   crash boundary does not catch, and a hook that never returns is indistinguishable from a hook
//!   that denied the operation.
//! - **Capability-scoped handles**, so a plugin that dies mid-call cannot leave a half-written file
//!   or a held lock that outlives it.
//! - **A supervision policy with a failure budget** -- N faults in a window means quarantine, and
//!   quarantine means exactly [`Host::quarantine`]: recompose without it and tell the operator what
//!   was lost. Restart-forever is how a crash loop becomes an outage.
//! - **A record of the fault** on the same bounded, redacted diagnostic path the rest of the system
//!   uses, so "the plugin is gone" is explainable rather than mysterious.

use std::collections::{BTreeMap, BTreeSet};

use iteron_protocol::{Capability, capability_set::CapabilitySet};

use crate::composition_model::{Defect, Manifest, Refusal, RuntimeScope, Slot, Surface, inspect};

/// One resolved ownership fact: this plugin holds this slot, with this payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub slot: Slot,
    pub plugin: String,
    pub precedence: u32,
    pub detail: String,
    /// Manifest request intersected with the host ceiling. A binding can never carry a class the
    /// host did not already admit.
    pub capabilities: CapabilitySet,
}

/// Which rule decided a contest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arbitration {
    /// The operator ranked one contender above the rest. The outcome carries their intent.
    Precedence,
    /// The top contenders were ranked equally, so the tie was broken by plugin id. The outcome is
    /// deterministic but **arbitrary**: nobody has chosen yet, and the operator should be asked.
    TieBrokenByPluginId,
}

impl Arbitration {
    pub fn is_operator_intent(self) -> bool {
        matches!(self, Arbitration::Precedence)
    }
}

/// An exclusive slot that more than one admitted plugin claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contest {
    pub slot: Slot,
    pub winner: String,
    /// The plugins that lost, ascending. Named, never merely counted: an operator who cannot see
    /// which plugin was shadowed cannot tell a working install from a hijacked name.
    pub shadowed: Vec<String>,
    pub arbitration: Arbitration,
}

/// The merged runtime surface: everything that will actually run.
///
/// Equality is the load-bearing property. Two compositions are equal exactly when the runtime they
/// describe is indistinguishable, which is what lets "a refused plugin changed nothing" and
/// "quarantine equals composing without it" be *assertions* rather than descriptions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Wiring {
    exclusive: BTreeMap<Slot, Binding>,
    chains: BTreeMap<String, Vec<Binding>>,
}

impl Wiring {
    pub fn skill(&self, name: &str) -> Option<&Binding> {
        self.exclusive.get(&Slot::new(Surface::Skill, name))
    }

    /// Candidate selected for a public module seam. Resolution and activation remain host-owned.
    pub fn implementation(&self, module: iteron_tunables::ModuleId) -> Option<&Binding> {
        self.exclusive
            .get(&Slot::new(Surface::Implementation, module.as_str()))
    }

    pub fn agent(&self, name: &str) -> Option<&Binding> {
        self.exclusive.get(&Slot::new(Surface::Agent, name))
    }

    pub fn language_server(&self, language: &str) -> Option<&Binding> {
        self.exclusive
            .get(&Slot::new(Surface::LanguageServer, language))
    }

    pub fn mcp_server(&self, name: &str) -> Option<&Binding> {
        self.exclusive.get(&Slot::new(Surface::McpServer, name))
    }

    /// The subscribers to one event, in the order they must run.
    pub fn hooks(&self, event: &str) -> &[Binding] {
        self.chains.get(event).map_or(&[], Vec::as_slice)
    }

    pub fn owner(&self, slot: &Slot) -> Option<&str> {
        self.exclusive.get(slot).map(|b| b.plugin.as_str())
    }

    /// Every exclusive slot that has an owner, in address order.
    pub fn slots(&self) -> Vec<&Slot> {
        self.exclusive.keys().collect()
    }

    /// Every event with at least one subscriber, in address order.
    pub fn events(&self) -> Vec<&str> {
        self.chains.keys().map(String::as_str).collect()
    }

    /// The plugins that hold at least one binding, ascending and deduplicated.
    pub fn contributors(&self) -> Vec<&str> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for binding in self.exclusive.values() {
            seen.insert(binding.plugin.as_str());
        }
        for chain in self.chains.values() {
            for binding in chain {
                seen.insert(binding.plugin.as_str());
            }
        }
        seen.into_iter().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.exclusive.is_empty() && self.chains.is_empty()
    }
}

/// What composition had to decide or refuse along the way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    contests: Vec<Contest>,
    refusals: Vec<Refusal>,
}

impl Report {
    pub fn contests(&self) -> &[Contest] {
        &self.contests
    }

    pub fn refusals(&self) -> &[Refusal] {
        &self.refusals
    }

    pub fn refusal_for(&self, plugin: &str) -> Option<&Defect> {
        self.refusals
            .iter()
            .find(|r| r.plugin == plugin)
            .map(|r| &r.defect)
    }

    pub fn contest_for(&self, slot: &Slot) -> Option<&Contest> {
        self.contests.iter().find(|c| &c.slot == slot)
    }

    /// Contests the operator has not actually decided: deterministic, but decided by spelling.
    pub fn unarbitrated(&self) -> Vec<&Contest> {
        self.contests
            .iter()
            .filter(|c| !c.arbitration.is_operator_intent())
            .collect()
    }

    pub fn is_clean(&self) -> bool {
        self.refusals.is_empty() && self.contests.is_empty()
    }
}

/// The result of composing a set of manifests: the surface, and the account of how it was reached.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Composition {
    pub wiring: Wiring,
    pub report: Report,
}

/// A candidate for a slot, carrying exactly the keys the total order needs.
struct Candidate<'a> {
    plugin: &'a str,
    precedence: u32,
    /// Declaration index inside its own manifest, so an author's ordering of two hooks on one event
    /// survives the merge. It is a *within-plugin* index, so it cannot vary with input order.
    index: usize,
    detail: &'a str,
    capabilities: CapabilitySet,
}

impl Candidate<'_> {
    /// Highest precedence first, then plugin id ascending, then declaration order.
    ///
    /// No term of this key can change when the input is permuted, which is the whole point.
    fn order_key(&self) -> (std::cmp::Reverse<u32>, &str, usize) {
        (std::cmp::Reverse(self.precedence), self.plugin, self.index)
    }

    fn bind(&self, slot: Slot) -> Binding {
        Binding {
            slot,
            plugin: self.plugin.to_owned(),
            precedence: self.precedence,
            detail: self.detail.to_owned(),
            capabilities: self.capabilities,
        }
    }
}

/// Merge independently-authored manifests into one runtime surface.
///
/// Total: there is no failure mode for the *set*. A manifest that cannot be admitted is reported
/// and left out; every other manifest composes exactly as it would have without it.
pub fn compose(manifests: &[Manifest]) -> Composition {
    compose_governed(manifests, RuntimeScope::Workspace, all_capabilities())
}

/// Compose for one runtime scope under an authority ceiling. Dependencies are evaluated only
/// among manifests that are valid and visible in that scope; a dependent can never make a broken
/// dependency look present.
pub fn compose_governed(
    manifests: &[Manifest],
    runtime_scope: RuntimeScope,
    host_ceiling: CapabilitySet,
) -> Composition {
    let mut refusals: Vec<Refusal> = Vec::new();

    // A repeated plugin id is refused before anything else, and *every* copy is refused. Keeping
    // one of them would mean choosing between two things claiming the same identity, which is the
    // question the id was supposed to answer.
    let mut declared: BTreeMap<&str, usize> = BTreeMap::new();
    for manifest in manifests {
        *declared.entry(manifest.plugin.as_str()).or_insert(0) += 1;
    }

    let mut admitted: Vec<&Manifest> = Vec::new();
    for manifest in manifests {
        let count = declared
            .get(manifest.plugin.as_str())
            .copied()
            .unwrap_or_default();
        if count > 1 {
            refusals.push(Refusal {
                plugin: manifest.plugin.clone(),
                defect: Defect::DuplicatePluginId {
                    plugin: manifest.plugin.clone(),
                    count,
                },
            });
            continue;
        }
        match inspect(manifest) {
            Ok(()) if runtime_scope.admits(manifest.scope) => admitted.push(manifest),
            // Scope exclusion is not a defect: the plugin remains installed and simply does not
            // participate in this composition.
            Ok(()) => {}
            Err(defect) => refusals.push(Refusal {
                plugin: manifest.plugin.clone(),
                defect,
            }),
        }
    }

    // Dependency refusal is transitive and deterministic. Re-run until stable so a plugin whose
    // dependency was itself refused cannot survive by referring to its dead manifest.
    loop {
        let versions: BTreeMap<&str, crate::Version> = admitted
            .iter()
            .map(|manifest| (manifest.plugin.as_str(), manifest.version))
            .collect();
        let mut newly_refused: Vec<(&Manifest, Defect)> = Vec::new();
        for manifest in &admitted {
            for requirement in &manifest.requires {
                match versions.get(requirement.plugin.as_str()) {
                    None => {
                        newly_refused.push((
                            manifest,
                            Defect::MissingDependency {
                                plugin: requirement.plugin.clone(),
                                minimum: requirement.minimum,
                            },
                        ));
                        break;
                    }
                    Some(actual) if *actual < requirement.minimum => {
                        newly_refused.push((
                            manifest,
                            Defect::DependencyTooOld {
                                plugin: requirement.plugin.clone(),
                                minimum: requirement.minimum,
                                actual: *actual,
                            },
                        ));
                        break;
                    }
                    Some(_) => {}
                }
            }
        }
        if newly_refused.is_empty() {
            break;
        }
        let names: BTreeSet<&str> = newly_refused
            .iter()
            .map(|(manifest, _)| manifest.plugin.as_str())
            .collect();
        for (manifest, defect) in newly_refused {
            refusals.push(Refusal {
                plugin: manifest.plugin.clone(),
                defect,
            });
        }
        admitted.retain(|manifest| !names.contains(manifest.plugin.as_str()));
    }

    let mut exclusive_claims: BTreeMap<Slot, Vec<Candidate<'_>>> = BTreeMap::new();
    let mut chain_claims: BTreeMap<String, Vec<Candidate<'_>>> = BTreeMap::new();
    for manifest in &admitted {
        for (index, contribution) in manifest.contributions.iter().enumerate() {
            let slot = contribution.slot();
            let candidate = Candidate {
                plugin: manifest.plugin.as_str(),
                precedence: manifest.precedence,
                index,
                detail: contribution.detail(),
                capabilities: manifest.capabilities.intersect(host_ceiling),
            };
            if slot.surface.is_exclusive() {
                exclusive_claims.entry(slot).or_default().push(candidate);
            } else {
                chain_claims.entry(slot.key).or_default().push(candidate);
            }
        }
    }

    let mut wiring = Wiring::default();
    let mut contests: Vec<Contest> = Vec::new();
    for (slot, mut claims) in exclusive_claims {
        claims.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
        let winner = &claims[0];
        if claims.len() > 1 {
            let arbitration = if claims[1].precedence == winner.precedence {
                Arbitration::TieBrokenByPluginId
            } else {
                Arbitration::Precedence
            };
            let mut shadowed: Vec<String> =
                claims[1..].iter().map(|c| c.plugin.to_owned()).collect();
            shadowed.sort();
            contests.push(Contest {
                slot: slot.clone(),
                winner: winner.plugin.to_owned(),
                shadowed,
                arbitration,
            });
        }
        wiring.exclusive.insert(slot.clone(), winner.bind(slot));
    }

    for (event, mut claims) in chain_claims {
        claims.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
        let slot = Slot::new(Surface::Hook, event.clone());
        let chain = claims.iter().map(|c| c.bind(slot.clone())).collect();
        wiring.chains.insert(event, chain);
    }

    // Refusals are sorted by plugin id so the report, like the wiring, does not remember the order
    // the manifests arrived in.
    refusals.sort_by(|a, b| a.plugin.cmp(&b.plugin));

    Composition {
        wiring,
        report: Report { contests, refusals },
    }
}

fn all_capabilities() -> CapabilitySet {
    CapabilitySet::from_iter_capabilities([
        Capability::ReadOnly,
        Capability::ReversibleLocal,
        Capability::CodeExecuting,
        Capability::TrustMutating,
        Capability::IrreversibleExternal,
    ])
}

/// The set of installed plugins, plus the ones a supervisor has taken out of service.
///
/// This is the pure half of crash isolation. A supervisor that observes a fault it cannot attribute
/// to a bad manifest -- a panic, a hang, a repeated failure -- calls [`Host::quarantine`], and the
/// surface is re-derived from the surviving members. Because [`compose`] is a total function of the
/// set, the result is exactly what would have been composed had the quarantined plugin never been
/// installed: a shadowed neighbour is promoted, its chains close up, and nothing else moves.
#[derive(Debug, Clone)]
pub struct Host {
    manifests: Vec<Manifest>,
    quarantined: BTreeMap<String, String>,
    composition: Composition,
    runtime_scope: RuntimeScope,
    host_ceiling: CapabilitySet,
}

impl Host {
    pub fn new(manifests: Vec<Manifest>) -> Self {
        Self::governed(manifests, RuntimeScope::Workspace, all_capabilities())
    }

    pub fn governed(
        manifests: Vec<Manifest>,
        runtime_scope: RuntimeScope,
        host_ceiling: CapabilitySet,
    ) -> Self {
        let composition = compose_governed(&manifests, runtime_scope, host_ceiling);
        Self {
            manifests,
            quarantined: BTreeMap::new(),
            composition,
            runtime_scope,
            host_ceiling,
        }
    }

    pub fn composition(&self) -> &Composition {
        &self.composition
    }

    pub fn wiring(&self) -> &Wiring {
        &self.composition.wiring
    }

    pub fn report(&self) -> &Report {
        &self.composition.report
    }

    /// Take a plugin out of service and re-derive the surface.
    ///
    /// Returns whether this changed the quarantine set. Naming a plugin that is not installed is
    /// recorded and changes nothing: a supervisor reporting a fault must never have to handle a
    /// "could not quarantine" branch, because the alternative to quarantining is leaving faulty
    /// code running.
    pub fn quarantine(&mut self, plugin: &str, reason: impl Into<String>) -> bool {
        if self.quarantined.contains_key(plugin) {
            return false;
        }
        self.quarantined.insert(plugin.to_owned(), reason.into());
        self.recompose();
        true
    }

    /// Return a quarantined plugin to service, re-deriving the surface.
    pub fn release(&mut self, plugin: &str) -> bool {
        if self.quarantined.remove(plugin).is_none() {
            return false;
        }
        self.recompose();
        true
    }

    /// The quarantined plugins and the reasons given, ascending by id.
    pub fn quarantined(&self) -> Vec<(&str, &str)> {
        self.quarantined
            .iter()
            .map(|(plugin, reason)| (plugin.as_str(), reason.as_str()))
            .collect()
    }

    /// The manifests currently in service.
    pub fn in_service(&self) -> Vec<&Manifest> {
        self.manifests
            .iter()
            .filter(|m| !self.quarantined.contains_key(&m.plugin))
            .collect()
    }

    fn recompose(&mut self) {
        let surviving: Vec<Manifest> = self
            .manifests
            .iter()
            .filter(|m| !self.quarantined.contains_key(&m.plugin))
            .cloned()
            .collect();
        self.composition = compose_governed(&surviving, self.runtime_scope, self.host_ceiling);
    }
}

#[cfg(test)]
#[path = "composition_tests.rs"]
mod tests;
