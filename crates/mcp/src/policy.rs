//! Per-server and per-tool authority policy for an installed MCP server.
//!
//! [`McpToolFilter`](crate::McpToolFilter) already answers *which names* a server may expose. It
//! says nothing about *what authority* those names carry, and that is the half an installed server
//! is motivated to argue with. A server declares its own tools; if the declaration were allowed to
//! participate in the authority decision, installing a server would be indistinguishable from
//! granting it whatever it asked for.
//!
//! So authority here is only ever removed. The effective ceiling for one tool is
//!
//! ```text
//! host ∩ server ∩ tool
//! ```
//!
//! computed with [`CapabilitySet::intersect`], which is the only combining operation the type
//! offers — there is no union, no `max`, and no `Ord`. Widening is not expressible, so this module
//! cannot grow a widening path by accident later.
//!
//! Three consequences worth stating, because each one is a defect if it goes the other way.
//!
//! **An absent ceiling inherits; it does not grant.** A server with no policy is bounded by the
//! host ceiling alone, because the identity element for intersection is the host ceiling itself.
//! The alternative — treating "unset" as "everything" — would make a policy field that silently
//! widened whatever the host had already narrowed.
//!
//! **A per-tool entry is applied on top of the server ceiling, never instead of it.** Entries are
//! intersected, so naming a class the server ceiling already withheld does not restore it. A
//! per-tool policy can only ever be stricter than the server it belongs to; the tempting reading,
//! "this tool is an exception, let it through", is exactly the widening this refuses.
//!
//! **Denial excludes the tool before its untrusted material is retained.** A tool whose demanded
//! class does not survive the intersection is dropped at the same point as a name-filtered tool,
//! so a refused tool cannot spend the catalog's description or schema budget, and cannot reach the
//! model at all.
//!
//! This is not a second spelling of [`McpToolFilter`](crate::McpToolFilter), and the difference is
//! the reason both exist. A deny list binds *names the operator already knows*: a server that
//! publishes a new tool after installation is admitted by an empty allow list, because a name that
//! did not exist at configuration time could not have been written down. A server ceiling binds
//! *the server*, so it covers the tools it has not published yet. The two gates therefore fail in
//! opposite directions and neither can stand in for the other.

use crate::{McpError, tool_filter::validate_bare_tool_name};
use iteron_protocol::{Capability, capability_set::CapabilitySet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum number of per-tool ceilings in one server's policy.
pub const MAX_MCP_TOOL_POLICY_ENTRIES: usize = 256;

/// The authority an installed server's tools may carry, expressed only as narrowing.
///
/// `capabilities` is the ceiling for every tool the server exposes; `tools` narrows individual
/// tools further. Both are optional in the sense that absent means "inherit", never "allow": see
/// the module documentation for why that distinction is the whole point of the type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpServerPolicy {
    /// Ceiling applied to every tool of this server. `None` inherits the host ceiling unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<CapabilitySet>,
    /// Per-tool ceilings, keyed by bare (un-namespaced) tool name. Each is intersected on top of
    /// the server ceiling, so an entry can only ever remove classes.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, CapabilitySet>,
}

impl McpServerPolicy {
    /// A policy that narrows nothing. Every tool is bounded by the host ceiling alone.
    pub fn inherit() -> Self {
        Self::default()
    }

    /// True when this policy narrows nothing, so callers can skip storing it.
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_none() && self.tools.is_empty()
    }

    /// Validate fixed collection and name-shape bounds without reflecting an entry's contents.
    ///
    /// Tool names come from operator configuration but are shaped like the untrusted names they
    /// must match, so they are validated with the same rule and never echoed into a diagnostic.
    pub fn validate(&self) -> Result<(), McpError> {
        if self.tools.len()
            > iteron_tunables::param_integer(
                "mcp.policy.max_mcp_tool_policy_entries",
                MAX_MCP_TOOL_POLICY_ENTRIES,
            )
        {
            return Err(McpError::InvalidToolPolicy {
                limit: iteron_tunables::param_integer(
                    "mcp.policy.max_mcp_tool_policy_entries",
                    MAX_MCP_TOOL_POLICY_ENTRIES,
                ),
            });
        }
        for name in self.tools.keys() {
            validate_bare_tool_name(name).map_err(|_| McpError::InvalidToolPolicy {
                limit: iteron_tunables::param_integer(
                    "mcp.policy.max_mcp_tool_policy_entries",
                    MAX_MCP_TOOL_POLICY_ENTRIES,
                ),
            })?;
        }
        Ok(())
    }

    /// The classes one tool may carry: `host ∩ server ∩ tool`.
    ///
    /// Every step is an intersection, so the result is a subset of `host`, of the server ceiling,
    /// and of any per-tool entry. There is no ordering in which a caller can reach a wider set
    /// than the one it passed in.
    pub fn effective_ceiling(&self, host: CapabilitySet, bare_name: &str) -> CapabilitySet {
        let mut effective = host;
        if let Some(server) = self.capabilities {
            effective = effective.intersect(server);
        }
        if let Some(tool) = self.tools.get(bare_name) {
            effective = effective.intersect(*tool);
        }
        effective
    }

    /// Whether a tool demanding `demanded` survives `host ∩ server ∩ tool`.
    ///
    /// MCP tools are registered at the untrusted default (`Capability::IrreversibleExternal`), so
    /// in practice this asks whether the host still permits external effect for this server and
    /// this name. A server that declares otherwise does not participate in the answer.
    pub fn admits(&self, host: CapabilitySet, bare_name: &str, demanded: Capability) -> bool {
        self.effective_ceiling(host, bare_name).contains(demanded)
    }
}

/// The host ceiling an MCP server is admitted under when the composition root has not narrowed it.
///
/// This is the authority an MCP tool is *registered* with today (ADR-007 R16: untrusted, effecting,
/// external), not a grant to execute — the kernel gate still intersects it again per call. Naming
/// it here keeps the discovery path from open-coding the same constant in two places.
pub fn default_host_ceiling() -> CapabilitySet {
    CapabilitySet::only(Capability::IrreversibleExternal)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_CLASS: [Capability; 5] = [
        Capability::ReadOnly,
        Capability::ReversibleLocal,
        Capability::CodeExecuting,
        Capability::TrustMutating,
        Capability::IrreversibleExternal,
    ];

    fn set(classes: impl IntoIterator<Item = Capability>) -> CapabilitySet {
        CapabilitySet::from_iter_capabilities(classes)
    }

    #[test]
    fn an_absent_policy_inherits_the_host_ceiling_and_grants_nothing_extra() {
        // The defect this prevents: treating "unset" as "unrestricted", which would make adding a
        // policy field silently re-widen a host ceiling that had already been narrowed.
        let policy = McpServerPolicy::inherit();
        policy.validate().unwrap();
        assert!(policy.is_empty());

        for host in [
            CapabilitySet::none(),
            set([Capability::ReadOnly]),
            set(EVERY_CLASS),
        ] {
            assert_eq!(policy.effective_ceiling(host, "anything"), host);
        }
    }

    #[test]
    fn an_installed_server_cannot_widen_what_the_host_allows() {
        // The property under test, stated adversarially: the server asks for everything, and for
        // one tool asks again more loudly. The host permits read-only. Nothing else survives.
        let greedy = McpServerPolicy {
            capabilities: Some(set(EVERY_CLASS)),
            tools: BTreeMap::from([("escalate".into(), set(EVERY_CLASS))]),
        };
        greedy.validate().unwrap();

        let host = set([Capability::ReadOnly]);
        for name in ["escalate", "ordinary"] {
            let effective = greedy.effective_ceiling(host, name);
            assert_eq!(effective, host, "a server may not add a class to the host");
            assert!(effective.is_subset_of(host));
            for class in EVERY_CLASS {
                if class != Capability::ReadOnly {
                    assert!(!effective.contains(class));
                }
            }
        }

        // And an empty host ceiling admits nothing at all, however the server is configured.
        for name in ["escalate", "ordinary"] {
            assert!(
                greedy
                    .effective_ceiling(CapabilitySet::none(), name)
                    .is_empty()
            );
            assert!(!greedy.admits(
                CapabilitySet::none(),
                name,
                Capability::IrreversibleExternal
            ));
        }
    }

    #[test]
    fn a_per_tool_entry_narrows_on_top_of_the_server_ceiling_and_never_restores_a_class() {
        // The tempting misreading is "this tool is an exception, let it through". Entries are
        // intersected, so an entry naming a class the server ceiling withheld changes nothing.
        let policy = McpServerPolicy {
            capabilities: Some(set([Capability::ReadOnly, Capability::ReversibleLocal])),
            tools: BTreeMap::from([
                // Asks for a class the server ceiling does not have.
                ("exception".into(), set([Capability::IrreversibleExternal])),
                // Legitimately stricter than its server.
                ("audited".into(), set([Capability::ReadOnly])),
            ]),
        };
        policy.validate().unwrap();
        let host = set(EVERY_CLASS);

        assert!(
            policy.effective_ceiling(host, "exception").is_empty(),
            "an entry disjoint from its server ceiling admits nothing, it does not re-open"
        );
        assert!(
            !policy.admits(host, "exception", Capability::IrreversibleExternal),
            "a per-tool entry must not restore what the server ceiling removed"
        );

        assert_eq!(
            policy.effective_ceiling(host, "audited"),
            set([Capability::ReadOnly])
        );
        assert_eq!(
            policy.effective_ceiling(host, "unlisted"),
            set([Capability::ReadOnly, Capability::ReversibleLocal]),
            "a tool with no entry inherits the server ceiling, not the host ceiling"
        );
    }

    #[test]
    fn the_effective_ceiling_is_a_subset_of_every_input_for_every_combination() {
        // Exhaustive over the whole lattice: 32 host sets by 32 server sets by 32 tool sets. If
        // any ordering or any pair could produce a class none of the three held, this finds it.
        let all_sets: Vec<CapabilitySet> = (0u8..32)
            .map(|bits| {
                set(EVERY_CLASS
                    .into_iter()
                    .enumerate()
                    .filter(|(index, _)| bits & (1 << index) != 0)
                    .map(|(_, class)| class))
            })
            .collect();

        for &host in &all_sets {
            for &server in &all_sets {
                for &tool in &all_sets {
                    let policy = McpServerPolicy {
                        capabilities: Some(server),
                        tools: BTreeMap::from([("t".into(), tool)]),
                    };
                    let effective = policy.effective_ceiling(host, "t");
                    assert!(effective.is_subset_of(host));
                    assert!(effective.is_subset_of(server));
                    assert!(effective.is_subset_of(tool));
                    for class in EVERY_CLASS {
                        assert_eq!(
                            effective.contains(class),
                            host.contains(class) && server.contains(class) && tool.contains(class),
                            "the effective ceiling is exactly the intersection, never more"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_server_ceiling_bounds_a_tool_name_no_operator_could_have_written_down() {
        // Why this type is not a second deny list. The operator configured the server when it
        // published `known`; the server later publishes `added-after-install`. A name-based gate
        // has nothing to match on and admits it. The server ceiling covers it because it was never
        // about names.
        let named_gate_would_admit = McpServerPolicy::inherit();
        let host = set([Capability::IrreversibleExternal]);
        assert!(named_gate_would_admit.admits(
            host,
            "added-after-install",
            Capability::IrreversibleExternal
        ));

        let server_ceiling = McpServerPolicy {
            capabilities: Some(CapabilitySet::none()),
            tools: BTreeMap::from([("known".into(), set(EVERY_CLASS))]),
        };
        server_ceiling.validate().unwrap();
        for name in ["known", "added-after-install", "and-the-one-after-that"] {
            assert!(
                !server_ceiling.admits(host, name, Capability::IrreversibleExternal),
                "a server ceiling binds the server, not a list of known names"
            );
        }
    }

    #[test]
    fn narrowing_is_idempotent_so_re_applying_a_policy_cannot_drift() {
        let policy = McpServerPolicy {
            capabilities: Some(set([Capability::ReadOnly, Capability::CodeExecuting])),
            tools: BTreeMap::new(),
        };
        let host = set(EVERY_CLASS);
        let once = policy.effective_ceiling(host, "t");
        let twice = policy.effective_ceiling(once, "t");
        assert_eq!(once, twice);
    }

    #[test]
    fn the_default_host_ceiling_is_the_untrusted_registration_class_and_nothing_below_it() {
        // `Capability` derives Ord for BTreeSet storage; the classes that sort below
        // `IrreversibleExternal` must not be dragged in. This is the same defect
        // `CapabilitySet` exists to prevent, asserted at the seam that names the constant.
        let host = default_host_ceiling();
        assert!(host.contains(Capability::IrreversibleExternal));
        assert!(!host.contains(Capability::CodeExecuting));
        assert!(!host.contains(Capability::TrustMutating));

        let policy = McpServerPolicy::inherit();
        assert!(policy.admits(host, "t", Capability::IrreversibleExternal));
        assert!(!policy.admits(host, "t", Capability::CodeExecuting));
    }

    #[test]
    fn policy_bounds_fail_closed_without_reflecting_an_entry_name() {
        let secret_shaped = "secret/path?token=opaque";
        let unsafe_name = McpServerPolicy {
            capabilities: None,
            tools: BTreeMap::from([(secret_shaped.into(), CapabilitySet::none())]),
        };
        let diagnostic = unsafe_name.validate().unwrap_err().to_string();
        assert!(!diagnostic.contains(secret_shaped));
        assert!(!diagnostic.contains("secret"));

        let oversized = McpServerPolicy {
            capabilities: None,
            tools: (0..=MAX_MCP_TOOL_POLICY_ENTRIES)
                .map(|index| (format!("tool-{index}"), CapabilitySet::none()))
                .collect(),
        };
        assert!(matches!(
            oversized.validate(),
            Err(McpError::InvalidToolPolicy {
                limit: MAX_MCP_TOOL_POLICY_ENTRIES
            })
        ));
    }

    #[test]
    fn the_wire_form_omits_an_inherited_policy_and_round_trips_a_narrowed_one() {
        let inherited = McpServerPolicy::inherit();
        assert_eq!(serde_json::to_string(&inherited).unwrap(), "{}");

        let narrowed = McpServerPolicy {
            capabilities: Some(set([Capability::ReadOnly])),
            tools: BTreeMap::from([("audited".into(), CapabilitySet::none())]),
        };
        let json = serde_json::to_string(&narrowed).unwrap();
        assert_eq!(
            json,
            r#"{"capabilities":["read_only"],"tools":{"audited":[]}}"#
        );
        let back: McpServerPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, narrowed);

        // An unknown field is a rejection, not a silently ignored intent to restrict.
        assert!(
            serde_json::from_str::<McpServerPolicy>(r#"{"capability":["read_only"]}"#).is_err()
        );
    }
}
