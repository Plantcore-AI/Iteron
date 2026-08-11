use anyhow::{Context, Result, bail};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::context::{ContextSelector, InstructionScope, RequestId};
use iteron_protocol::slot::StrategySlot;
use iteron_protocol::{Capability, ToolUse, Trust};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use syn::visit::{self, Visit};

const RUNTIME_SOURCE: &str = "crates/cli/src/runtime/workflow_collect.rs";
const KERNEL_MANIFEST: &str = "crates/kernel/Cargo.toml";
const KERNEL_SOURCE_DIR: &str = "crates/kernel/src";
const MAX_RUNTIME_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_KERNEL_FILE_BYTES: u64 = 512 * 1024;
const MAX_EVIDENCE_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_READ_ONLY_TOOLS: usize = 256;
const MAX_POLICY_TOOLS: usize = 256;
const MAX_W1_PLACEMENT_ROWS: usize = 16;
const SPAWN_SIGNATURE: &str = "    pub(super) async fn spawn_subagent(";
const BUDGET_BINDING: &str = "let Some(budget) = iteron_agents::subagent_budget(";
const REQUIRED_KERNEL_PATH_DEPENDENCIES: [&str; 3] = ["iteron-obs", "iteron-protocol", "iteron-record"];
const FORBIDDEN_WORLD_CRATES: [&str; 8] = [
    "iteron_agents",
    "iteron_ctx",
    "iteron_provider",
    "iteron_sandbox",
    "iteron_sched",
    "iteron_tools",
    "iteron_verify",
    "iteron_workflow",
];
const FORBIDDEN_WORLD_PATHS: [&str; 15] = [
    "std::env",
    "std::fs",
    "std::process",
    "crossterm",
    "ratatui",
    "ProviderClient",
    "PromptAssembler",
    "PromptBuilder",
    "activate_policy",
    "assemble_prompt",
    "build_prompt",
    "decode_tool_call",
    "parse_tool_call",
    "train_policy",
    "PolicyTrainer",
];
const W1_FREEZE_COMMIT: &str = "304027e";
const TCB_FREEZE_FIXTURES: [&str; 7] = [
    "governance/schema-compat/fixtures/abi/task-envelope-v1.json",
    "governance/schema-compat/fixtures/abi/context-request-v1.json",
    "governance/schema-compat/fixtures/abi/tool-intent-v1.json",
    "governance/schema-compat/fixtures/abi/effect-proposal-v1.json",
    "governance/schema-compat/fixtures/abi/artifact-ref-v1.json",
    "crates/evolve/tests/fixtures/policy-manifest-v1.json",
    "crates/evolve/tests/fixtures/policy-manifest-v2.json",
];

#[derive(Clone, Copy)]
struct MatrixRow {
    group: &'static str,
    id: &'static str,
    path: &'static str,
    test: &'static str,
}

const KERNEL_MATRIX: [MatrixRow; 23] = [
    MatrixRow {
        group: "component",
        id: "K1 identity-trust",
        path: "crates/kernel/src/admission.rs",
        test: "complete_capability_trust_mode_and_rule_truth_table_is_executable",
    },
    MatrixRow {
        group: "component",
        id: "K2 capability-admission",
        path: "crates/kernel/src/admission.rs",
        test: "task_and_candidate_policy_intersection_can_only_narrow",
    },
    MatrixRow {
        group: "component",
        id: "K3 effect-broker",
        path: "crates/kernel/src/effect_boundary_tests.rs",
        test: "every_effect_class_crosses_intent_then_executor_then_exactly_one_terminal",
    },
    MatrixRow {
        group: "component",
        id: "K4 deterministic-reducer",
        path: "crates/kernel/src/reducer_tests.rs",
        test: "replaying_a_command_stream_produces_a_byte_identical_action_sequence",
    },
    MatrixRow {
        group: "component",
        id: "K5 canonical-record",
        path: "crates/kernel/src/effect_boundary_tests.rs",
        test: "fsynced_intent_crash_reconciles_unknown_without_replay_then_forks_a_divergent_chain",
    },
    MatrixRow {
        group: "component",
        id: "K6 bounded-cancellation",
        path: "crates/cli/src/runtime.rs",
        test: "max_tokens_is_a_hard_recorded_terminal_at_the_safe_turn_boundary",
    },
    MatrixRow {
        group: "component",
        id: "K7 version-registry",
        path: "crates/protocol/tests/abi_freeze.rs",
        test: "the_declared_ceilings_are_part_of_the_frozen_contract",
    },
    MatrixRow {
        group: "component",
        id: "K8 kill-rollback",
        path: "crates/evolve/src/promotion_tests.rs",
        test: "d14_13_g3_rollback_and_reopen_restore_exact_prior_bundle_bytes_and_identity",
    },
    MatrixRow {
        group: "component",
        id: "K9 bounded-driver",
        path: "crates/kernel/src/driver_tests.rs",
        test: "the_driver_runs_a_whole_turn_against_stubbed_ports",
    },
    MatrixRow {
        group: "invariant",
        id: "Bounded",
        path: "crates/kernel/src/driver_tests.rs",
        test: "a_full_submission_queue_blocks_a_producer_rather_than_growing",
    },
    MatrixRow {
        group: "invariant",
        id: "Recoverable",
        path: "crates/kernel/src/effect_boundary_tests.rs",
        test: "fsynced_intent_crash_reconciles_unknown_without_replay_then_forks_a_divergent_chain",
    },
    MatrixRow {
        group: "invariant",
        id: "Reproducible",
        path: "crates/kernel/src/reducer_tests.rs",
        test: "replay_is_stable_across_an_independent_fold_order_of_the_same_stream",
    },
    MatrixRow {
        group: "invariant",
        id: "Observable",
        path: "crates/kernel/src/effect_boundary_tests.rs",
        test: "no_effect_producing_call_site_bypasses_the_boundary",
    },
    MatrixRow {
        group: "invariant",
        id: "Security-bounded",
        path: "crates/kernel/src/admission.rs",
        test: "exact_allow_and_operator_bypass_cannot_clear_tainted_egress",
    },
    MatrixRow {
        group: "negative",
        id: "N1 no-file-or-env",
        path: "xtask/src/conformance.rs",
        test: "negative_n1_file_and_environment_access_turn_red",
    },
    MatrixRow {
        group: "negative",
        id: "N2 no-provider",
        path: "xtask/src/conformance.rs",
        test: "negative_n2_provider_access_turns_red",
    },
    MatrixRow {
        group: "negative",
        id: "N3 no-prompt-building",
        path: "xtask/src/conformance.rs",
        test: "negative_n3_prompt_building_turns_red",
    },
    MatrixRow {
        group: "negative",
        id: "N4 no-context-selection",
        path: "xtask/src/conformance.rs",
        test: "negative_n4_context_selection_turns_red",
    },
    MatrixRow {
        group: "negative",
        id: "N5 no-process-spawn",
        path: "xtask/src/conformance.rs",
        test: "negative_n5_process_spawn_turns_red",
    },
    MatrixRow {
        group: "negative",
        id: "N6 no-mcp-parsing",
        path: "xtask/src/conformance.rs",
        test: "negative_n6_mcp_parsing_turns_red",
    },
    MatrixRow {
        group: "negative",
        id: "N7 no-ui-rendering",
        path: "xtask/src/conformance.rs",
        test: "negative_n7_ui_rendering_turns_red",
    },
    MatrixRow {
        group: "negative",
        id: "N8 no-policy-training-or-activation",
        path: "xtask/src/conformance.rs",
        test: "negative_n8_policy_training_and_activation_turn_red",
    },
    MatrixRow {
        group: "measurement",
        id: "kernel-tax",
        path: "crates/eval/src/main.rs",
        test: "kernel_tax_is_a_real_separate_eval_output_line",
    },
];

/// Validate cross-crate contracts that intentionally do not belong in the runtime dependency
/// graph. This is the single build-plane conformance entry point used both directly and by every
/// boundaries command.
pub fn validate(root: &Path) -> Result<()> {
    validate_read_only_registry(root)?;
    validate_tool_policy_registry(root)?;
    // Bootstrap fixtures and older trusted bases predate this W1 seam. The direct iteron-ctx build
    // dependency is the activation bit: once the registry declares it, every new checkout must
    // satisfy the placement and negative-space checks below.
    if w1_context_contract_enabled(root)? {
        validate_w1_placement_matrix(root)?;
        validate_kernel_context_facade(root)?;
    }
    validate_kernel_negative_space(root)?;
    let runtime = read_bounded_utf8(root, RUNTIME_SOURCE, MAX_RUNTIME_SOURCE_BYTES)?;
    validate_runtime_budget_binding(&runtime)
}

/// Emit the Sept-1 conformance matrix after proving every row has executable evidence and the
/// frozen TCB contract has no breaking diff from the W1 freeze.
pub fn kernel(root: &Path) -> Result<()> {
    validate(root)?;
    validate_tcb_freeze(root).context("TCB breaking-diff proof against W1 freeze failed")?;
    validate_matrix_evidence(root)?;
    run_matrix_tests(root)?;

    println!("group\trow\tstatus\tevidence");
    for row in KERNEL_MATRIX {
        println!(
            "{}\t{}\tPASS\ttest:{}::{}",
            row.group, row.id, row.path, row.test
        );
    }
    println!(
        "snapshot\tW1 frozen TCB\tPASS\tfive ABI fixtures + StrategySlot + PROTOCOL_VERSION + PolicyManifest @ {W1_FREEZE_COMMIT}"
    );
    Ok(())
}

fn validate_tcb_freeze(root: &Path) -> Result<()> {
    // First prove the candidate's full compatibility corpus agrees with its Rust shapes. The
    // against-W1 comparison below is deliberately TCB-scoped: unrelated versioned product/eval
    // surfaces are allowed to advance without invalidating a microkernel freeze proof.
    crate::schema_compat::validate_current(root)?;

    for relative in TCB_FREEZE_FIXTURES {
        let current = crate::schema_compat::read_candidate_file_bounded(
            root,
            relative,
            MAX_EVIDENCE_SOURCE_BYTES,
        )?;
        let frozen = crate::schema_compat::read_revision_file_bounded(
            root,
            W1_FREEZE_COMMIT,
            relative,
            MAX_EVIDENCE_SOURCE_BYTES,
        )?
        .with_context(|| format!("W1 freeze lacks `{relative}`"))?;
        require_identical_snapshot(relative, &frozen, &current)?;
    }

    for (relative, kind, name) in [
        (
            "crates/protocol/src/slot.rs",
            SnapshotItemKind::Trait,
            "StrategySlot",
        ),
        (
            "crates/evolve/src/lib.rs",
            SnapshotItemKind::Struct,
            "PolicyManifest",
        ),
    ] {
        let current = crate::schema_compat::read_candidate_file_bounded(
            root,
            relative,
            MAX_EVIDENCE_SOURCE_BYTES,
        )?;
        let frozen = crate::schema_compat::read_revision_file_bounded(
            root,
            W1_FREEZE_COMMIT,
            relative,
            MAX_EVIDENCE_SOURCE_BYTES,
        )?
        .with_context(|| format!("W1 freeze lacks `{relative}`"))?;
        require_identical_snapshot(
            &format!("{relative}::{name}"),
            normalized_item(&frozen, kind, name)?.as_bytes(),
            normalized_item(&current, kind, name)?.as_bytes(),
        )?;
    }

    let wire = crate::validate::PROTOCOL_VERSION_SOURCE;
    let current =
        crate::schema_compat::read_candidate_file_bounded(root, wire, MAX_EVIDENCE_SOURCE_BYTES)?;
    let frozen = crate::schema_compat::read_revision_file_bounded(
        root,
        W1_FREEZE_COMMIT,
        wire,
        MAX_EVIDENCE_SOURCE_BYTES,
    )?
    .with_context(|| format!("W1 freeze lacks `{wire}`"))?;
    let current_version = crate::validate::protocol_version_from_source(&current)?;
    let frozen_version = crate::validate::protocol_version_from_source(&frozen)?;
    require_monotone_protocol_version(frozen_version, current_version)
}

/// The W1 pin on `PROTOCOL_VERSION`, as a comparison rather than as a step inside a function that
/// can only run against real git revisions -- so the direction it enforces is testable.
///
/// Monotone, not equal. Equality made two of this repository's own rules unsatisfiable at the same
/// time: `sqeq-version-lockstep` (`validate_protocol_version_bump`) *requires* a bump once a
/// published surface moves, and `docs/spec/abi.md` §4.3(c) says the same, while pinning the constant
/// here forbade one. Adding an event kind moves the `record.event-envelope` and `record.rollout`
/// corpora -- `crates/record/tests/d13_14_event_schema.rs` requires a new kind to appear in both --
/// so under equality no event kind could ever be added again.
///
/// What #14 criterion 7 asks for is a breaking-diff proof, and an advance is not a breaking diff: it
/// is the declared mechanism for handling one, and a peer that meets an unfamiliar stamp is refused
/// by `require_current` rather than left to mis-read the payload. A *decrease* is the break -- it
/// would let a shape change be reverted on the wire while producers that already emitted the newer
/// form stayed in the field -- so that stays refused, as does the rest of the frozen snapshot, which
/// is still compared byte for byte.
fn require_monotone_protocol_version(frozen: u32, current: u32) -> Result<()> {
    if current < frozen {
        bail!(
            "PROTOCOL_VERSION regressed from W1 value {frozen} to {current}; it may advance but never go backwards"
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SnapshotItemKind {
    Trait,
    Struct,
}

fn normalized_item(source: &[u8], kind: SnapshotItemKind, name: &str) -> Result<String> {
    let source = std::str::from_utf8(source)
        .with_context(|| format!("snapshot source for `{name}` is not UTF-8"))?;
    let file = syn::parse_file(source)
        .with_context(|| format!("snapshot source containing `{name}` is invalid Rust"))?;
    file.items
        .into_iter()
        .find_map(|item| match (kind, item) {
            (SnapshotItemKind::Trait, syn::Item::Trait(item)) if item.ident == name => {
                Some(item.to_token_stream().to_string())
            }
            (SnapshotItemKind::Struct, syn::Item::Struct(item)) if item.ident == name => {
                Some(item.to_token_stream().to_string())
            }
            _ => None,
        })
        .with_context(|| format!("snapshot source lacks `{name}`"))
}

fn require_identical_snapshot(label: &str, frozen: &[u8], current: &[u8]) -> Result<()> {
    if frozen != current {
        bail!("W1 TCB snapshot `{label}` has a breaking diff");
    }
    Ok(())
}

fn run_matrix_tests(root: &Path) -> Result<()> {
    const TEST_COMMANDS: &[&[&str]] = &[
        &["test", "--locked", "-p", "iteron-kernel"],
        &[
            "test",
            "--locked",
            "-p",
            "iteron-cli",
            "max_tokens_is_a_hard_recorded_terminal_at_the_safe_turn_boundary",
        ],
        &[
            "test",
            "--locked",
            "-p",
            "iteron-cli",
            "max_tokens_fails_closed_when_provider_usage_is_missing",
        ],
        &[
            "test",
            "--locked",
            "-p",
            "iteron-cli",
            "readme_prompt_injection_cannot_push_through_the_effect_boundary",
        ],
        &[
            "test",
            "--locked",
            "-p",
            "iteron-protocol",
            "--test",
            "abi_freeze",
        ],
        &[
            "test",
            "--locked",
            "-p",
            "iteron-evolve",
            "d14_13_g3_rollback_and_reopen_restore_exact_prior_bundle_bytes_and_identity",
        ],
        &[
            "test",
            "--locked",
            "-p",
            "iteron-evolve",
            "d14_13_g4_candidate_cannot_self_authorize_change_policy_or_relax_safety_budgets",
        ],
        &[
            "test",
            "--locked",
            "-p",
            "iteron-eval",
            "kernel_tax_is_a_real_separate_eval_output_line",
        ],
        &["test", "--locked", "-p", "iteron-xtask", "negative_n"],
    ];

    for arguments in TEST_COMMANDS {
        let rendered = format!("cargo {}", arguments.join(" "));
        let status = Command::new("cargo")
            .args(*arguments)
            .current_dir(root)
            .status()
            .with_context(|| format!("cannot execute conformance evidence `{rendered}`"))?;
        if !status.success() {
            bail!("conformance evidence failed: `{rendered}`");
        }
    }
    Ok(())
}

fn validate_matrix_evidence(root: &Path) -> Result<()> {
    let mut cached = BTreeMap::new();
    for row in KERNEL_MATRIX {
        let source = match cached.get(row.path) {
            Some(source) => source,
            None => {
                let source = read_bounded_utf8(root, row.path, MAX_EVIDENCE_SOURCE_BYTES)?;
                cached.insert(row.path, source);
                cached
                    .get(row.path)
                    .expect("matrix evidence was just inserted")
            }
        };
        let ordinary = format!("fn {}(", row.test);
        let asynchronous = format!("async fn {}(", row.test);
        if !source.contains(&ordinary) && !source.contains(&asynchronous) {
            bail!(
                "unbacked conformance row `{}`: test `{}` is absent from {}",
                row.id,
                row.test,
                row.path
            );
        }
    }
    Ok(())
}

fn w1_context_contract_enabled(root: &Path) -> Result<bool> {
    let registry: serde_json::Value = serde_json::from_str(&read_bounded_utf8(
        root,
        "governance/boundaries.json",
        2 * 1024 * 1024,
    )?)
    .context("governance/boundaries.json is not valid JSON")?;
    Ok(registry["cargo_policy"]["packages"]["iteron-xtask"]["normal"]
        .as_array()
        .is_some_and(|dependencies| {
            dependencies
                .iter()
                .any(|dependency| dependency.as_str() == Some("iteron-ctx"))
        }))
}

struct PlacementRow {
    capability: &'static str,
    authority_boundaries: &'static [&'static str],
    strategy_slots: &'static [&'static str],
    world_modules: &'static [&'static str],
}

const W1_PLACEMENT_ROWS: &[PlacementRow] = &[
    PlacementRow {
        capability: "read/list/glob",
        authority_boundaries: &["kernel-runtime", "kernel-effects"],
        strategy_slots: &["core/context", "core/tool_policy"],
        world_modules: &[
            "crates/ctx/src/context_port.rs",
            "crates/tools/src/fs_tools.rs",
        ],
    },
    PlacementRow {
        capability: "skills",
        authority_boundaries: &["kernel-runtime"],
        strategy_slots: &["core/context"],
        world_modules: &["crates/ctx/src/skills.rs"],
    },
];

fn validate_w1_placement_matrix(root: &Path) -> Result<()> {
    if W1_PLACEMENT_ROWS.len() > MAX_W1_PLACEMENT_ROWS {
        bail!("W1 placement matrix exceeds its {MAX_W1_PLACEMENT_ROWS}-row limit");
    }
    let available_slots = [
        iteron_ctx::ContextStrategy::default()
            .slot()
            .as_persisted_str()
            .to_owned(),
        iteron_tools::ToolPolicy::default()
            .slot()
            .as_persisted_str()
            .to_owned(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let registry: serde_json::Value = serde_json::from_str(&read_bounded_utf8(
        root,
        "governance/boundaries.json",
        2 * 1024 * 1024,
    )?)
    .context("governance/boundaries.json is not valid JSON")?;
    let boundary_ids = registry["boundaries"]
        .as_array()
        .context("boundary registry lacks a boundaries array")?
        .iter()
        .filter_map(|boundary| boundary["id"].as_str())
        .collect::<BTreeSet<_>>();

    let mut capabilities = BTreeSet::new();
    for row in W1_PLACEMENT_ROWS {
        if !capabilities.insert(row.capability) {
            bail!("W1 placement matrix repeats `{}`", row.capability);
        }
        for boundary in row.authority_boundaries {
            if !boundary_ids.contains(boundary) {
                bail!(
                    "W1 placement `{}` names unknown authority boundary `{boundary}`",
                    row.capability
                );
            }
        }
        for slot in row.strategy_slots {
            if !available_slots.contains(*slot) {
                bail!(
                    "W1 placement `{}` names unavailable strategy slot `{slot}`",
                    row.capability
                );
            }
        }
        for module in row.world_modules {
            if !root.join(module).is_file() {
                bail!(
                    "W1 placement `{}` names missing world module `{module}`",
                    row.capability
                );
            }
        }
    }

    validate_context_selector_projection()
}

fn validate_context_selector_projection() -> Result<()> {
    let mut observation =
        iteron_ctx::ContextSlotObservation::baseline(RequestId(1), "xtask conformance");
    observation.instruction_scopes = vec![
        InstructionScope::User,
        InstructionScope::Project,
        InstructionScope::Directory,
    ];
    observation.memory_keys = vec!["named".into()];
    observation.transcript_turns = 1;
    let plan = iteron_ctx::ContextStrategy::default()
        .select(&observation, CapabilitySet::only(Capability::ReadOnly))
        .map_err(|reason| {
            anyhow::anyhow!("context strategy rejected conformance input: {reason}")
        })?;
    let actual = plan
        .request
        .selectors
        .iter()
        .map(|selector| match selector {
            ContextSelector::RepoOutline { .. } => "repo_outline",
            ContextSelector::Instructions { .. } => "instructions",
            ContextSelector::MemoryKeys { .. } => "memory_keys",
            ContextSelector::Transcript { .. } => "transcript",
            ContextSelector::EnvironmentFacts => "environment_facts",
            ContextSelector::Unknown => "unknown",
        })
        .collect::<BTreeSet<_>>();
    let expected = [
        "repo_outline",
        "instructions",
        "memory_keys",
        "transcript",
        "environment_facts",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if actual != expected || !plan.include_skills {
        bail!("context strategy no longer projects every frozen selector plus local skills policy");
    }
    Ok(())
}

fn validate_kernel_context_facade(root: &Path) -> Result<()> {
    const KERNEL_CONTEXT_INTERNALS: &[&str] = &[
        "iteron_ctx::memory::",
        "iteron_ctx::skills::",
        "iteron_ctx::outline::",
        "iteron_ctx::instructions::",
        "FileMemory",
        "SkillCatalog",
        "MemoryStrategy",
        "repo_outline_for_task",
        "discover_hierarchy",
    ];
    let source_dir = root.join(KERNEL_SOURCE_DIR);
    let mut files = std::fs::read_dir(&source_dir)
        .with_context(|| format!("cannot inspect {}", source_dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .collect::<Vec<_>>();
    files.sort();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .expect("kernel source is below repository root")
            .to_string_lossy()
            .replace('\\', "/");
        let text = read_bounded_utf8(root, &relative, MAX_KERNEL_FILE_BYTES)?;
        if let Some(forbidden) = KERNEL_CONTEXT_INTERNALS
            .iter()
            .find(|forbidden| text.contains(**forbidden))
        {
            bail!("kernel source `{relative}` reaches into ctx internal `{forbidden}`");
        }
    }
    Ok(())
}

fn validate_tool_policy_registry(root: &Path) -> Result<()> {
    let registry = iteron_tools::Registry::coding_agent(root).map_err(|error| {
        anyhow::anyhow!("cannot construct iteron-tools coding-agent registry: {error}")
    })?;
    let specs = registry.specs();
    if specs.len() > MAX_POLICY_TOOLS {
        bail!("tool-policy conformance exceeds the {MAX_POLICY_TOOLS}-tool build-plane limit");
    }
    let ceiling = CapabilitySet::from_iter_capabilities([
        Capability::ReadOnly,
        Capability::ReversibleLocal,
        Capability::CodeExecuting,
        Capability::TrustMutating,
        Capability::IrreversibleExternal,
    ]);
    let policy = iteron_tools::ToolPolicy::default();
    for spec in specs {
        let proposal = registry
            .propose_intent(
                &policy,
                ToolUse {
                    id: "xtask-conformance".into(),
                    name: spec.name.clone(),
                    input: serde_json::json!({}),
                },
                Trust::Workspace,
                ceiling,
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "tool-policy rejected registered tool `{}`: {error}",
                    spec.name
                )
            })?;
        validate_tool_policy_projection(&spec.name, spec.purity, spec.capability, &proposal)?;
    }
    Ok(())
}

fn validate_tool_policy_projection(
    name: &str,
    purity: iteron_protocol::Purity,
    capability: Capability,
    proposal: &iteron_tools::ToolPolicyProposal,
) -> Result<()> {
    if proposal.intent.call.name != name
        || proposal.intent.purity != purity
        || proposal.eligible != CapabilitySet::only(capability)
        || !proposal.intent.admitted.is_empty()
    {
        bail!(
            "tool-policy projection for `{name}` does not exactly preserve registry purity/capability and deny-by-default admission"
        );
    }
    Ok(())
}

fn validate_read_only_registry(root: &Path) -> Result<()> {
    let registry = iteron_tools::Registry::read_only(root).map_err(|error| {
        anyhow::anyhow!("cannot construct iteron-tools read-only registry: {error}")
    })?;
    let actual = registry
        .specs()
        .into_iter()
        .map(|spec| spec.name)
        .collect::<Vec<_>>();
    validate_read_only_names(iteron_agents::READ_ONLY_TOOLS, &actual)
}

fn validate_read_only_names(expected: &[&str], actual: &[String]) -> Result<()> {
    if expected.len() > MAX_READ_ONLY_TOOLS || actual.len() > MAX_READ_ONLY_TOOLS {
        bail!("read-only tool contract exceeds the {MAX_READ_ONLY_TOOLS}-tool build-plane limit");
    }
    let expected_set = expected.iter().copied().collect::<BTreeSet<_>>();
    let actual_set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if expected_set.len() != expected.len() {
        bail!("iteron-agents READ_ONLY_TOOLS contains duplicate names");
    }
    if actual_set.len() != actual.len() {
        bail!("iteron-tools read-only registry contains duplicate names");
    }
    if actual_set != expected_set {
        let missing = expected_set
            .difference(&actual_set)
            .copied()
            .collect::<Vec<_>>();
        let unexpected = actual_set
            .difference(&expected_set)
            .copied()
            .collect::<Vec<_>>();
        bail!(
            "read-only capability contract drifted: missing registrations {missing:?}; unexpected registrations {unexpected:?}"
        );
    }
    Ok(())
}

fn validate_kernel_negative_space(root: &Path) -> Result<()> {
    validate_kernel_dependencies(&read_bounded_utf8(
        root,
        KERNEL_MANIFEST,
        MAX_KERNEL_FILE_BYTES,
    )?)?;

    let source_dir = root.join(KERNEL_SOURCE_DIR);
    let mut files = std::fs::read_dir(&source_dir)
        .with_context(|| format!("cannot inspect {}", source_dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .filter(|path| {
            !path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| stem.ends_with("_tests"))
        })
        .collect::<Vec<_>>();
    files.sort();

    let mut failures = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .expect("kernel source is below repository root")
            .to_string_lossy()
            .replace('\\', "/");
        let source = read_bounded_utf8(root, &relative, MAX_KERNEL_FILE_BYTES)?;
        failures.extend(
            production_source_violations(&source)
                .with_context(|| format!("cannot parse conformance source `{relative}`"))?
                .into_iter()
                .map(|violation| format!("{relative}: {violation}")),
        );
    }
    if !failures.is_empty() {
        bail!(
            "kernel negative-space contract violated:\n{}",
            failures.join("\n")
        );
    }
    Ok(())
}

fn validate_kernel_dependencies(source: &str) -> Result<()> {
    let manifest = source
        .parse::<toml::Table>()
        .context("kernel manifest is not valid TOML")?;
    let mut path_dependencies = BTreeSet::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(dependencies) = manifest.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, specification) in dependencies {
            if specification
                .as_table()
                .and_then(|table| table.get("path"))
                .is_some()
            {
                path_dependencies.insert(name.as_str());
            }
        }
    }
    let required = REQUIRED_KERNEL_PATH_DEPENDENCIES.into_iter().collect();
    if path_dependencies != required {
        bail!(
            "kernel path dependencies must be exactly {:?}, found {:?}",
            required,
            path_dependencies
        );
    }
    Ok(())
}

#[derive(Default)]
struct NegativeSpaceVisitor {
    violations: BTreeMap<String, usize>,
}

impl NegativeSpaceVisitor {
    fn record(&mut self, value: impl Into<String>) {
        *self.violations.entry(value.into()).or_default() += 1;
    }

    fn inspect_path(&mut self, path: &syn::Path) {
        let rendered = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        let first = path
            .segments
            .first()
            .map(|segment| segment.ident.to_string());
        if first
            .as_deref()
            .is_some_and(|name| FORBIDDEN_WORLD_CRATES.contains(&name))
        {
            self.record(format!("world-crate reference `{rendered}`"));
        }
        if FORBIDDEN_WORLD_PATHS.iter().any(|forbidden| {
            rendered == *forbidden || rendered.starts_with(&format!("{forbidden}::"))
        }) {
            self.record(format!("world operation `{rendered}`"));
        }
    }

    fn item_is_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attribute| {
            let compact = attribute
                .meta
                .to_token_stream()
                .to_string()
                .replace(' ', "");
            compact == "test"
                || compact.contains("cfg(test)")
                || compact.contains("cfg(any(test,")
                || compact.contains("cfg_attr(test,")
        })
    }
}

impl<'ast> Visit<'ast> for NegativeSpaceVisitor {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Const(item) => &item.attrs,
            syn::Item::Enum(item) => &item.attrs,
            syn::Item::ExternCrate(item) => &item.attrs,
            syn::Item::Fn(item) => &item.attrs,
            syn::Item::ForeignMod(item) => &item.attrs,
            syn::Item::Impl(item) => &item.attrs,
            syn::Item::Macro(item) => &item.attrs,
            syn::Item::Mod(item) => &item.attrs,
            syn::Item::Static(item) => &item.attrs,
            syn::Item::Struct(item) => &item.attrs,
            syn::Item::Trait(item) => &item.attrs,
            syn::Item::TraitAlias(item) => &item.attrs,
            syn::Item::Type(item) => &item.attrs,
            syn::Item::Union(item) => &item.attrs,
            syn::Item::Use(item) => &item.attrs,
            _ => &[],
        };
        if !Self::item_is_test(attrs) {
            visit::visit_item(self, item);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.inspect_path(path);
        visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if FORBIDDEN_WORLD_PATHS.contains(&method.as_str()) {
            self.record(format!("world method `{method}`"));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, call: &'ast syn::Macro) {
        let name = call
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        if ["env", "include_bytes", "include_str", "option_env"].contains(&name.as_str()) {
            self.record(format!("world-reading macro `{name}!`"));
        }
        visit::visit_macro(self, call);
    }
}

fn production_source_violations(source: &str) -> Result<Vec<String>> {
    let parsed = syn::parse_file(source)?;
    let mut visitor = NegativeSpaceVisitor::default();
    visitor.visit_file(&parsed);
    Ok(visitor
        .violations
        .into_iter()
        .map(|(violation, count)| format!("{violation} ({count} occurrence(s))"))
        .collect())
}

fn validate_runtime_budget_binding(source: &str) -> Result<()> {
    let body = runtime_spawn_body(source)?;
    let bindings = body
        .lines()
        .filter(|line| line.trim() == BUDGET_BINDING)
        .count();
    if bindings != 1 {
        bail!(
            "CLI runtime spawn_subagent must bind its budget exactly once through def.rs::subagent_budget()"
        );
    }
    if body.contains("Budget {") || body.contains("budget.max_") {
        bail!(
            "CLI runtime spawn_subagent must not construct or mutate a second subagent budget policy"
        );
    }
    Ok(())
}

fn runtime_spawn_body(source: &str) -> Result<&str> {
    let mut starts = source.match_indices(SPAWN_SIGNATURE);
    let (start, _) = starts
        .next()
        .context("CLI runtime source lacks spawn_subagent")?;
    if starts.next().is_some() {
        bail!("CLI runtime source repeats spawn_subagent");
    }
    let after_start = &source[start + SPAWN_SIGNATURE.len()..];
    let end = [
        "\n    fn ",
        "\n    async fn ",
        "\n    pub fn ",
        "\n    pub async fn ",
        "\n    pub(super) fn ",
        "\n    pub(super) async fn ",
        "\n}",
    ]
    .into_iter()
    .filter_map(|signature| after_start.find(signature))
    .min()
    .context("CLI runtime spawn_subagent has no following method boundary")?;
    Ok(&after_start[..end])
}

fn read_bounded_utf8(root: &Path, relative: &str, max_bytes: u64) -> Result<String> {
    let path = root.join(relative);
    let metadata = std::fs::metadata(&path)
        .with_context(|| format!("cannot inspect conformance source `{relative}`"))?;
    if metadata.len() > max_bytes {
        bail!("conformance source `{relative}` exceeds its {max_bytes}-byte limit");
    }
    std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read UTF-8 conformance source `{relative}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d11_10_real_read_only_registration_is_the_agent_contract() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        validate_read_only_registry(root).unwrap();
    }

    #[test]
    fn w1_tool_policy_matches_the_real_registry() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        validate_tool_policy_registry(root).unwrap();
    }

    #[test]
    fn w1_tool_policy_capability_mismatch_fails_conformance() {
        let proposal = iteron_tools::ToolPolicyProposal {
            intent: iteron_protocol::intent::ToolIntent::denied(
                iteron_protocol::slot::SlotId("core/tool_policy".into()),
                ToolUse {
                    id: "mismatch".into(),
                    name: "sample".into(),
                    input: serde_json::json!({}),
                },
                iteron_protocol::Purity::Pure,
                Trust::Workspace,
            ),
            eligible: CapabilitySet::only(Capability::CodeExecuting),
        };
        assert!(
            validate_tool_policy_projection(
                "sample",
                iteron_protocol::Purity::Pure,
                Capability::ReadOnly,
                &proposal,
            )
            .is_err()
        );
    }

    #[test]
    fn w1_context_and_skills_placement_matrix_matches_live_modules() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        validate_w1_placement_matrix(root).unwrap();
        validate_kernel_context_facade(root).unwrap();
    }

    #[test]
    fn d11_10_read_only_registration_drift_fails() {
        let expected = ["read_file", "grep"];
        let exact = vec!["grep".to_string(), "read_file".to_string()];
        assert!(validate_read_only_names(&expected, &exact).is_ok());

        let missing = vec!["read_file".to_string()];
        assert!(validate_read_only_names(&expected, &missing).is_err());

        let unexpected = vec![
            "read_file".to_string(),
            "grep".to_string(),
            "edit".to_string(),
        ];
        assert!(validate_read_only_names(&expected, &unexpected).is_err());
    }

    #[test]
    fn d11_10_runtime_budget_drift_fails() {
        let bound = format!(
            "{SPAWN_SIGNATURE}&mut self) {{\n        {BUDGET_BINDING}\n        }};\n    }}\n\n    fn next("
        );
        assert!(validate_runtime_budget_binding(&bound).is_ok());

        let inline = format!(
            "{SPAWN_SIGNATURE}&mut self) {{\n        let budget = Budget {{ max_turns: 16 }};\n    }}\n\n    fn next("
        );
        assert!(validate_runtime_budget_binding(&inline).is_err());

        let widened = format!(
            "{SPAWN_SIGNATURE}&mut self) {{\n        {BUDGET_BINDING}\n        }};\n        budget.max_turns = 16;\n    }}\n\n    fn next("
        );
        assert!(validate_runtime_budget_binding(&widened).is_err());
    }

    #[test]
    fn kernel_path_dependency_allowlist_is_exact() {
        let exact = r#"
            [dependencies]
            iteron-protocol = { path = "../protocol" }
            iteron-record = { path = "../record" }
            iteron-obs = { path = "../obs" }
            serde = "1"
        "#;
        assert!(validate_kernel_dependencies(exact).is_ok());
        assert!(
            validate_kernel_dependencies(&format!(
                "{exact}\ncore-provider = {{ path = \"../provider\" }}"
            ))
            .is_err()
        );
    }

    fn assert_red(fixture: &str) {
        assert!(
            !production_source_violations(fixture).unwrap().is_empty(),
            "red-team fixture escaped: {fixture}"
        );
    }

    #[test]
    fn negative_n1_file_and_environment_access_turn_red() {
        assert_red("fn red_team() { std::fs::read(\"prompt\"); }");
        assert_red("fn red_team() { std::env::var(\"MODEL\"); }");
    }

    #[test]
    fn negative_n2_provider_access_turns_red() {
        assert_red("fn red_team() { iteron_provider::Client::new(); }");
    }

    #[test]
    fn negative_n3_prompt_building_turns_red() {
        assert_red("fn red_team() { PromptBuilder::new().build_prompt(); }");
    }

    #[test]
    fn negative_n4_context_selection_turns_red() {
        assert_red("fn red_team() { iteron_ctx::select_context(request); }");
    }

    #[test]
    fn negative_n5_process_spawn_turns_red() {
        assert_red("fn red_team() { std::process::Command::new(\"sh\"); }");
    }

    #[test]
    fn negative_n6_mcp_parsing_turns_red() {
        assert_red("fn red_team() { parse_tool_call(bytes); }");
    }

    #[test]
    fn negative_n7_ui_rendering_turns_red() {
        assert_red("fn red_team() { ratatui::Frame::render_widget(widget, area); }");
    }

    #[test]
    fn negative_n8_policy_training_and_activation_turn_red() {
        assert_red("fn red_team() { train_policy(samples); }");
        assert_red("fn red_team() { activate_policy(candidate); }");
    }

    #[test]
    fn test_only_world_access_does_not_pollute_the_kernel_contract() {
        let fixture = r#"
            pub fn reduce() {}
            #[cfg(test)]
            mod tests {
                #[test]
                fn fixture() { std::fs::read("fixture").unwrap(); }
            }
        "#;
        assert!(production_source_violations(fixture).unwrap().is_empty());
    }

    #[test]
    fn a_planted_tcb_snapshot_change_turns_the_freeze_proof_red() {
        assert!(require_identical_snapshot("fixture", b"frozen", b"frozen").is_ok());
        assert!(require_identical_snapshot("fixture", b"frozen", b"changed").is_err());
    }

    /// The pin used to compare for equality, and that made the constant unable to move at all --
    /// which, because every typed event kind must appear in two existing record corpora, meant no
    /// event kind could ever be added again. Both halves of the replacement are pinned here: an
    /// advance is permitted because it is what the spec prescribes for a moved shape, and a
    /// regression is refused because reverting a shape on the wire is the actual breaking diff.
    ///
    /// Written against explicit values rather than the live constant so that a future bump does not
    /// quietly re-aim it, and so restoring equality turns this red instead of passing vacuously.
    #[test]
    fn the_w1_protocol_pin_permits_an_advance_and_refuses_a_regression() {
        require_monotone_protocol_version(1, 1).expect("standing still is not a diff");
        require_monotone_protocol_version(1, 2)
            .expect("an advance is how a moved shape is declared");
        require_monotone_protocol_version(1, u32::MAX).expect("any advance, not just by one");

        let regression = require_monotone_protocol_version(2, 1)
            .expect_err("a regression reverts a shape on the wire and must be refused");
        let rendered = regression.to_string();
        assert!(
            rendered.contains("regressed") && rendered.contains("never go backwards"),
            "the refusal must say which direction is forbidden, or the next reader re-derives it: {rendered}"
        );
        assert!(
            require_monotone_protocol_version(u32::MAX, 0).is_err(),
            "a regression to zero is still a regression"
        );
    }

    #[test]
    fn current_tcb_snapshot_matches_the_w1_freeze() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        validate_tcb_freeze(root).unwrap();
    }
}
