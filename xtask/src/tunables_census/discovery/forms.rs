use super::{CallerInputProofKind, CensusCandidateKind, InvariantKind};

#[derive(Debug, Clone, Copy)]
pub(super) struct SourceInvariantDisposition {
    pub(super) kind: InvariantKind,
    pub(super) rationale: &'static str,
}

pub(super) fn is_public(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Public(_))
}

pub(super) fn parameter_name(pattern: &syn::Pat, index: usize) -> String {
    if let syn::Pat::Ident(ident) = pattern {
        ident.ident.to_string()
    } else {
        format!("argument_{index}")
    }
}

/// Only source-owned values are candidates. Paths, calls, field accesses, and other expressions
/// consume already-declared settings and therefore remain observations rather than new rows.
pub(super) fn is_inline_quality_value(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::Lit(_) => true,
        syn::Expr::Path(path) => {
            path.path.segments.len() > 1
                && path
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .is_some_and(|name| {
                        name.chars().next().is_some_and(char::is_uppercase)
                            && !name
                                .chars()
                                .all(|character| character.is_ascii_uppercase() || character == '_')
                    })
        }
        syn::Expr::Unary(unary) => is_inline_quality_value(&unary.expr),
        syn::Expr::Array(array) => array.elems.iter().all(is_inline_quality_value),
        syn::Expr::Tuple(tuple) => tuple.elems.iter().all(is_inline_quality_value),
        syn::Expr::Paren(paren) => is_inline_quality_value(&paren.expr),
        syn::Expr::Group(group) => is_inline_quality_value(&group.expr),
        syn::Expr::Repeat(repeat) => {
            is_inline_quality_value(&repeat.expr) && is_inline_quality_value(&repeat.len)
        }
        _ => false,
    }
}

pub(super) fn is_closed_policy_fallback_value(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::Lit(literal) => !matches!(literal.lit, syn::Lit::Str(_) | syn::Lit::ByteStr(_)),
        syn::Expr::Unary(unary) => is_closed_policy_fallback_value(&unary.expr),
        syn::Expr::Paren(paren) => is_closed_policy_fallback_value(&paren.expr),
        syn::Expr::Group(group) => is_closed_policy_fallback_value(&group.expr),
        syn::Expr::Reference(reference) => is_closed_policy_fallback_value(&reference.expr),
        syn::Expr::Array(array) => array
            .elems
            .iter()
            .all(|element| matches!(element, syn::Expr::Path(_))),
        _ => false,
    }
}

pub(super) fn is_quality_constructor(target: &str, owner: &str, relative: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    if [
        "set_color_output",
        "set_extension",
        "with_extension",
        "with_file_name",
    ]
    .iter()
    .any(|method| lower.ends_with(method))
    {
        return false;
    }
    let leaf_owner = lower
        .rsplit("::")
        .nth(1)
        .unwrap_or_default()
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_');
    if leaf_owner.ends_with("error")
        || leaf_owner.ends_with("id")
        || leaf_owner.ends_with("identifier")
        || leaf_owner.contains("identity")
    {
        return false;
    }
    if [
        "arc",
        "box",
        "btree_map",
        "btreemap",
        "btree_set",
        "btreeset",
        "error",
        "hash_map",
        "hashmap",
        "hash_set",
        "hashset",
        "line",
        "openoptions",
        "option",
        "pathbuf",
        "rc",
        "result",
        "string",
        "style",
        "vec",
        "vecdeque",
    ]
    .contains(&leaf_owner)
    {
        return false;
    }
    // A struct/call expression is a candidate declaration only when its constructed type is
    // itself a policy container. Merely occurring inside policy-related runtime code is not
    // enough: result, evidence, observation, state, UI projection, and protocol envelope literals
    // record facts and must never become trainer-controlled values.
    let type_context = if lower == "self" || lower.starts_with("self::") {
        owner.to_ascii_lowercase()
    } else if leaf_owner.is_empty() {
        lower.clone()
    } else {
        leaf_owner.to_owned()
    };
    let is_exact_type = |name: &str| type_context.split("::").any(|segment| segment == name);
    // These are exact accumulator/result containers. Their literals initialize factual runtime
    // state while the independently counted surrounding builder/default form remains observable.
    // In particular, zero counters are not optimization defaults merely because their owner also
    // contains words such as `policy`, `routing`, `limits`, or `builder`.
    if [
        "imageattachments",
        "policyharnesserrorjoindigest",
        "policyopportunityjoindigest",
        "policyrunaggregate",
        "replayring",
        "toolcatalogbuilder",
    ]
    .iter()
    .any(|name| is_exact_type(name))
        || (relative.ends_with("cli/src/tui/hyperlink.rs")
            && type_context.ends_with("policy::disabled"))
    {
        return false;
    }
    if [
        "artifact",
        "card",
        "decision",
        "entry",
        "envelope",
        "event",
        "evidence",
        "identity",
        "manifest",
        "observation",
        "outcome",
        "receipt",
        "result",
        "snapshot",
        "spec",
        "state",
        "status",
        "terminaloptions",
        "usage",
        "version",
    ]
    .iter()
    .any(|marker| type_context.contains(marker))
    {
        return false;
    }
    [
        "admission",
        "backoff",
        "budget",
        "config",
        "limits",
        "options",
        "policy",
        "quorum",
        "retry",
        "router",
        "routing",
        "sampling",
        "timeout",
    ]
    .iter()
    .any(|marker| type_context.contains(marker))
}

/// Exact source-owned invariants. These rules intentionally key on the declaring function/type,
/// never on generic words such as `policy`, `default`, or `limit`: genuine optimization defaults
/// remain binding-required until a production owner exposes them.
pub(super) fn source_invariant_disposition(
    identity: &str,
    value: &str,
) -> Option<SourceInvariantDisposition> {
    let identity = identity.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    let invariant = |kind, rationale| SourceInvariantDisposition { kind, rationale };

    if identity.contains("subagent_budget_ceiling")
        || (identity.contains("ultracode_planner")
            && (identity.contains("max_consecutive_tool_errors")
                || identity.contains("max.consecutive.tool.errors")))
        || identity.contains("executionruntimepolicy::fail_closed")
        || identity.contains("executionruntimepolicy.fail.closed")
        || identity.contains("governed_workflow_limits")
        || ((identity.contains("control_policy") || identity.contains("control.policy"))
            && identity.contains("stagelimits"))
    {
        return Some(invariant(
            InvariantKind::HardBudget,
            "the declaration is an owner-named hard ceiling or deny-by-default fallback",
        ));
    }
    if identity.contains("routerroute::direct") || identity.contains("routerroute.direct") {
        return Some(invariant(
            InvariantKind::HardBudget,
            "the direct route reserves zero fan-out leaves as its fail-closed breadth ceiling",
        ));
    }
    if (identity.contains("contextmaterializationpolicy::default")
        || identity.contains("contextmaterializationpolicy.default"))
        && (identity.contains("skill_listing_bytes") || identity.contains("skill.listing.bytes"))
    {
        return Some(invariant(
            InvariantKind::HardBudget,
            "the materialized skill listing is bounded by an owner-fixed context ceiling",
        ));
    }
    if identity.contains("turnlimits::default") || identity.contains("turnlimits.default") {
        return Some(invariant(
            InvariantKind::HardBudget,
            "the kernel turn owner fixes fail-closed execution and verification ceilings",
        ));
    }
    if (identity.contains("crates/protocol/src/lib.rs")
        || identity.contains("protocol.lib.budget.default"))
        && (identity.contains("budget::default") || identity.contains("budget.default"))
    {
        return Some(invariant(
            InvariantKind::HardBudget,
            "the protocol budget fixes the maximum admitted turns, wall time, and consecutive tool failures",
        ));
    }
    if identity.contains("join_reduce_policy") || identity.contains("join.reduce.policy") {
        return Some(if identity.contains("order") {
            invariant(
                InvariantKind::Replay,
                "reduction order is fixed for deterministic evidence replay",
            )
        } else {
            invariant(
                InvariantKind::EffectLedger,
                "join completion and failed-evidence handling fix effect-ledger adoption semantics",
            )
        });
    }
    if (identity.contains("effecting_tool_admission_policy")
        || identity.contains("effecting.tool.admission.policy"))
        && identity.contains("overlap")
    {
        return Some(invariant(
            InvariantKind::EffectLedger,
            "overlapping effecting writes are fixed by effect-ledger conflict semantics",
        ));
    }
    if ((identity.contains("effecting_tool_admission_policy")
        || identity.contains("effecting.tool.admission.policy"))
        && !identity.contains("overlap"))
        || (identity.contains("verificationrestorepolicy")
            && (identity.contains("require_operator_confirmation")
                || identity.contains("require.operator.confirmation")))
    {
        return Some(invariant(
            InvariantKind::Authority,
            "the value fixes effect admission or operator authority and is not trainer-controlled",
        ));
    }
    if identity.contains("processlaunchpolicy::owner")
        || identity.contains("processlaunchpolicy.owner")
        || identity.contains("childprocessenvironmentpolicy")
        || identity.contains("processcwdpolicy")
    {
        return Some(invariant(
            InvariantKind::Authority,
            "the value fixes the admitted child-process capability boundary",
        ));
    }
    if ((identity.contains("per_agent_memory") || identity.contains("per.agent.memory"))
        && value.contains("childmemorypolicy")
        && value.contains("isolated"))
        || (identity.contains("childadmissionpolicy")
            && (identity.contains("require_capability_subset")
                || identity.contains("require.capability.subset")))
    {
        return Some(invariant(
            InvariantKind::Security,
            "the value fixes child isolation or capability narrowing at an enforced security boundary",
        ));
    }
    if identity.contains("prunepolicy")
        && (identity.contains("dry_run") || identity.contains("dry.run"))
    {
        return Some(invariant(
            InvariantKind::Security,
            "retention preflight and destructive phases are fixed security semantics",
        ));
    }
    if identity.contains("providerconfig")
        && (identity.contains("field::catalog")
            || identity.contains("field.catalog")
            || identity.contains("field::enabled")
            || identity.contains("field.enabled"))
    {
        return Some(invariant(
            InvariantKind::Authority,
            "provider catalog and enablement are composition authority, not trainer inputs",
        ));
    }
    if (identity.contains("memoryretrievalpolicy::default")
        || identity.contains("memoryretrievalpolicy.default"))
        && (identity.contains("reranker_weight_ppm")
            || identity.contains("reranker.weight.ppm")
            || identity.contains("vector_weight_ppm")
            || identity.contains("vector.weight.ppm"))
    {
        return Some(invariant(
            InvariantKind::Authority,
            "unattested vector and reranker feature owners remain disabled at the retrieval authority boundary",
        ));
    }
    if identity.contains("runtimehttpclient::default_reconfigurable")
        || identity.contains("runtimehttpclient.default.reconfigurable")
    {
        return Some(invariant(
            InvariantKind::Authority,
            "the flag identifies the host-owned default transport as reconfigurable without widening injected transport authority",
        ));
    }
    if identity.contains("mcpoauthlifecyclepolicy::disabled")
        || identity.contains("mcpoauthlifecyclepolicy.disabled")
        || ((identity.contains("mcpoauthlifecyclepolicy::from_counts")
            || identity.contains("mcpoauthlifecyclepolicy.from.counts"))
            && (identity.contains("revoke_access_after_forbidden")
                || identity.contains("revoke.access.after.forbidden")))
    {
        return Some(invariant(
            InvariantKind::Security,
            "the closed OAuth owner disables absent credential capabilities and always revokes forbidden access",
        ));
    }
    if (identity.contains("verificationrestorepolicy::default")
        || identity.contains("verificationrestorepolicy.default"))
        && (identity.contains("field::mode") || identity.contains("field.mode"))
    {
        return Some(invariant(
            InvariantKind::Authority,
            "rollback is disabled unless an explicit restore authority is installed",
        ));
    }
    if (identity.contains("verificationretrypolicy::default")
        || identity.contains("verificationretrypolicy.default"))
        && (identity.contains("field::unknown") || identity.contains("field.unknown"))
    {
        return Some(invariant(
            InvariantKind::Security,
            "an unknown verification outcome stops rather than granting retry authority",
        ));
    }
    if (identity.contains("hedgepolicy::default") || identity.contains("hedgepolicy.default"))
        && (identity.contains("idempotent_only") || identity.contains("idempotent.only"))
    {
        return Some(invariant(
            InvariantKind::EffectLedger,
            "hedged duplicate execution is restricted to idempotent requests so effects cannot be duplicated",
        ));
    }
    if (identity.contains("taskretrypolicy::default")
        || identity.contains("taskretrypolicy.default"))
        && (identity.contains("argument_2") || identity.contains("argument.2"))
    {
        return Some(invariant(
            InvariantKind::Durability,
            "retry reassignment must preserve prior evidence across the durable workflow ledger",
        ));
    }
    if (identity.contains("appserverqueuepolicy::owner")
        || identity.contains("appserverqueuepolicy.owner"))
        && value.contains("authoritativeoverflow")
    {
        return Some(invariant(
            InvariantKind::Durability,
            "authoritative queue entries must wait rather than be dropped or rewritten",
        ));
    }
    if (identity.contains("appserverqueuepolicy::owner")
        || identity.contains("appserverqueuepolicy.owner"))
        && value.contains("cosmeticoverflow")
    {
        return Some(invariant(
            InvariantKind::NonValueStructural,
            "cosmetic overflow handling is a fixed projection behavior, not agent direction",
        ));
    }
    if identity.contains("verificationcheckpointpolicy")
        && (identity.contains("before_drain") || identity.contains("before.drain"))
    {
        return Some(invariant(
            InvariantKind::Durability,
            "drain must checkpoint before completion as a lifecycle durability guarantee",
        ));
    }
    if identity.contains("tooloutputspillpolicy::default")
        || identity.contains("tooloutputspillpolicy.default")
    {
        return Some(invariant(
            InvariantKind::Durability,
            "spill retention is fixed through run end so durable tool output is not lost early",
        ));
    }
    if identity.contains("schemavalidator::compile") || identity.contains("schemavalidator.compile")
    {
        return Some(invariant(
            InvariantKind::WireCompatibility,
            "the JSON Schema draft is pinned by the documented structured-output wire contract",
        ));
    }
    if identity.contains("replaydivergencedetectionpolicy::owner")
        || identity.contains("replaydivergencedetectionpolicy.owner")
    {
        return Some(invariant(
            InvariantKind::Replay,
            "the record reader fixes hash, identity, effect-terminal, and fail-closed divergence checks for every replay",
        ));
    }
    if identity.contains("purememocachepolicy::production_owner")
        || identity.contains("purememocachepolicy.production.owner")
    {
        return Some(invariant(
            InvariantKind::Replay,
            "generation scoping prevents a pre-invalidation result from repopulating a later replay generation",
        ));
    }
    if identity.contains("taskpriorityschedulingpolicy::owner")
        || identity.contains("taskpriorityschedulingpolicy.owner")
    {
        return Some(
            if identity.contains("dependency_ready_only")
                || identity.contains("dependency.ready.only")
            {
                invariant(
                    InvariantKind::EffectLedger,
                    "only dependency-ready tasks may enter the reducer's effect-admission queue",
                )
            } else {
                invariant(
                    InvariantKind::Replay,
                    "one FIFO priority level preserves durable declaration order during ready-queue replay",
                )
            },
        );
    }
    if identity.contains("writermergepolicy::isolated_writer")
        || identity.contains("writermergepolicy.isolated.writer")
        || identity.contains("writermergepolicy::parent_only")
        || identity.contains("writermergepolicy.parent.only")
    {
        return Some(
            if identity.contains("on_clean") || identity.contains("on.clean") {
                invariant(
                    InvariantKind::Durability,
                    "clean writer output enters the parent only through the serialized durable merge controller",
                )
            } else if identity.contains("on_conflict") || identity.contains("on.conflict") {
                invariant(
                    InvariantKind::EffectLedger,
                    "conflicting writer effects are rejected rather than silently adopted",
                )
            } else if identity.contains("writer_worktree_isolation")
                || identity.contains("writer.worktree.isolation")
            {
                invariant(
                    InvariantKind::Security,
                    "writer capability is paired exactly with a host-owned isolated worktree",
                )
            } else {
                invariant(
                    InvariantKind::Authority,
                    "writer adoption remains gated by host verification authority",
                )
            },
        );
    }
    if identity.contains("effectiveconfigdocument") {
        return Some(
            if identity.contains("field::kind") || identity.contains("field.kind") {
                invariant(
                    InvariantKind::Identity,
                    "the literal is the stable document-kind identity of a factual projection",
                )
            } else {
                invariant(
                    InvariantKind::Identity,
                    "the literal identifies the document as a runtime-bound effective projection",
                )
            },
        );
    }
    if identity.contains("routeview::unresolved")
        || identity.contains("routeview.unresolved")
        || identity.contains("contextbudgetviolation")
        || identity.contains("admissiondeferred")
        || identity.contains("admission::deferred")
        || identity.contains("admission.deferred")
        || identity.contains("ignorebudget")
    {
        return Some(invariant(
            InvariantKind::NonValueStructural,
            "the literal initializes or reports factual runtime state rather than selecting policy",
        ));
    }
    if identity.contains("harnessconfig") {
        return Some(invariant(
            InvariantKind::Identity,
            "the literal identifies one fixed evaluation arm and does not control production behavior",
        ));
    }
    None
}

pub(super) fn public_proof_kind(
    attrs: &[syn::Attribute],
    name: &str,
    owner: &str,
    fallback: CallerInputProofKind,
) -> CallerInputProofKind {
    if attrs.iter().any(|attr| attr.path().is_ident("serde")) {
        CallerInputProofKind::SerdeEnvelope
    } else if attrs
        .iter()
        .any(|attr| attr.path().is_ident("arg") || attr.path().is_ident("clap"))
    {
        CallerInputProofKind::ClapEnvelope
    } else if [name, owner]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains("protocol"))
    {
        CallerInputProofKind::ProtocolEnvelope
    } else {
        fallback
    }
}

pub(super) fn is_builder_name(name: &str) -> bool {
    matches!(name, "new" | "builder" | "build")
        || name.starts_with("build_")
        || name.starts_with("with_")
        || name.starts_with("set_")
}

pub(super) fn manifest_kind(name: &str) -> Option<CensusCandidateKind> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("implementation") && lower.contains("manifest") {
        Some(CensusCandidateKind::DynamicImplementationManifest)
    } else if lower.contains("plugin") && lower.contains("manifest") {
        Some(CensusCandidateKind::DynamicPluginManifest)
    } else {
        None
    }
}

pub(super) fn stable_id(krate: &str, relative: &str, symbol: &str) -> String {
    let module = relative
        .rsplit_once("/src/")
        .map(|(_, tail)| tail)
        .unwrap_or(relative)
        .trim_end_matches(".rs");
    format!("{krate}.{module}.{symbol}")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>()
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

pub(super) fn is_policy_context(context: &str) -> bool {
    [
        "policy",
        "config",
        "options",
        "limits",
        "budget",
        "retry",
        "timeout",
        "cache",
        "routing",
        "router",
        "model",
        "provider",
        "workflow",
        "verifier",
        "context",
        "memory",
        "compact",
        "prompt",
        "tool",
        "sandbox",
        "admission",
        "sampling",
        "reasoning",
        "queue",
        "concurrency",
        "turnstate",
        "implementation",
        "plugin",
        "manifest",
    ]
    .iter()
    .any(|marker| context.contains(marker))
}
