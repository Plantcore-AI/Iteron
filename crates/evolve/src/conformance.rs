//! Evolution conformance rows: one capability class per row, each carrying executable evidence.
//!
//! The table lives in `crates/evolve` rather than in `xtask` for the same reason the crate is
//! outside the runtime trusted computing base: the control plane has to be able to certify
//! itself from a standalone binary, with no dependency on the workspace validator. `xtask`
//! consumes this table when it assembles the shared capability-mapping §7.2 matrix; the
//! `evolve-gate` binary consumes it directly.
//!
//! A row is admissible only when every test it cites exists in the file it cites, it names at
//! least one plane placement, every `StrategySlot` it names is a valid slot identity, and every
//! world module it names is a regular file on disk. There is deliberately no "target" state: a
//! capability class either has evidence that runs, or the gate is red.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Bounds are defence in depth behind a repository checkout, not a substitute for one.
const MAX_EVIDENCE_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EVOLUTION_ROWS: usize = 32;
const MAX_EVIDENCE_PER_ROW: usize = 8;

/// The five operators §6.4 defines. Naming them here is what makes "all five" machine-checkable
/// instead of a claim in prose: [`validate`] refuses the table unless every operator is covered
/// by a distinct named test.
pub const CHECKPOINT_ALGEBRA_OPERATORS: [&str; 5] =
    ["diff", "merge", "restrict", "retire", "transfer"];

/// The six modules the Sept-1 gate must prove end to end.
pub const PROVEN_MODULES: [&str; 6] = [
    "producer",
    "independent-held-out-evaluator",
    "shadow-canary",
    "checkpoint-algebra",
    "cross-model-transfer",
    "second-producer",
];

/// One executable proof: a test that must exist in a source file and pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    /// Repository-relative source file that defines the test.
    pub path: &'static str,
    /// Test function name, matched as a definition rather than a mention.
    pub test: &'static str,
}

/// One evolution capability class and the evidence that it holds.
///
/// The three plane fields are the A/B/C placement §7.1 defines: A is the authority boundary that
/// admits or refuses the class, B is the `StrategySlot` space it ranges over, C is the world
/// module that implements it. A class may legitimately occupy only one plane -- an offline
/// control-plane invariant has no strategy slot -- so the rule is "at least one", not "all three".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvolutionRow {
    /// The capability class as the Sept-1 gate names it.
    pub class: &'static str,
    /// Plane A.
    pub authority_boundaries: &'static [&'static str],
    /// Plane B.
    pub strategy_slots: &'static [&'static str],
    /// Plane C.
    pub world_modules: &'static [&'static str],
    /// Which of [`PROVEN_MODULES`] this row certifies, if any. Rows that certify a structural
    /// invariant rather than a runnable module carry `None`.
    pub proven_module: Option<&'static str>,
    /// Non-empty; every entry is checked to exist.
    pub evidence: &'static [Evidence],
}

/// The evolution rows of the Sept-1 conformance matrix.
///
/// Every cited test predates this table except the two structural invariants at the end, which
/// this module owns. Nothing here was written to make a row green: the tests already existed as
/// the acceptance evidence of #26 through #30, and the table's job is to name them so a machine
/// can refuse the gate when one disappears.
pub const EVOLUTION_MATRIX: &[EvolutionRow] = &[
    EvolutionRow {
        class: "PolicyManifest schema v3 + frozen base-model identity",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &[],
        world_modules: &[
            "crates/evolve/src/schema.rs",
            "crates/evolve/src/base_model.rs",
        ],
        proven_module: None,
        evidence: &[
            Evidence {
                path: "crates/evolve/tests/policy_manifest_freeze.rs",
                test: "every_frozen_shape_decodes_its_own_snapshot_without_moving_it",
            },
            Evidence {
                path: "crates/evolve/src/verifier_tests.rs",
                test: "a_manifest_migrated_from_schema_2_loads_and_is_permanently_unpromotable",
            },
            Evidence {
                path: "crates/evolve/src/verifier_tests.rs",
                test: "a_candidate_naming_no_admissible_base_model_is_refused_before_any_promotion_decision",
            },
        ],
    },
    EvolutionRow {
        class: "capability-monotone intersection-only admission",
        authority_boundaries: &["evolution-control", "kernel-runtime"],
        strategy_slots: &["core/tool_policy", "core/context"],
        world_modules: &["crates/evolve/src/admission.rs"],
        proven_module: None,
        evidence: &[
            Evidence {
                path: "crates/evolve/src/checkpoint_algebra_tests.rs",
                test: "restrict_is_monotone_cannot_widen",
            },
            Evidence {
                path: "crates/evolve/src/producer_tests.rs",
                test: "producer_rejects_capabilities_above_trusted_slot_ceiling",
            },
        ],
    },
    EvolutionRow {
        class: "independent held-out evaluator + separation of duties",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &[],
        world_modules: &[
            "crates/evolve/src/promotion_evaluation.rs",
            "crates/evolve/src/held_out.rs",
        ],
        proven_module: Some("independent-held-out-evaluator"),
        evidence: &[
            Evidence {
                path: "crates/evolve/src/held_out_tests.rs",
                test: "signed_evidence_matches_the_independent_key_not_the_promotion_key",
            },
            Evidence {
                path: "crates/evolve/src/held_out_tests.rs",
                test: "producer_anchor_cannot_sign_held_out",
            },
            Evidence {
                path: "crates/evolve/src/promotion_tests.rs",
                test: "authority_authenticates_independent_held_out_and_rejects_a_promotion_key_signature",
            },
            Evidence {
                path: "crates/evolve/src/promotion_tests.rs",
                test: "authority_rejects_cross_role_key_aliases_even_under_different_ids",
            },
        ],
    },
    EvolutionRow {
        class: "deny-by-default PromotionAuthority + hash-chained journal",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &[],
        world_modules: &[
            "crates/evolve/src/promotion_authority.rs",
            "crates/evolve/src/promotion_journal.rs",
        ],
        proven_module: None,
        evidence: &[
            Evidence {
                path: "crates/evolve/src/promotion_tests.rs",
                test: "promotion_authority_rejects_unbounded_contracts_and_a_second_writer",
            },
            Evidence {
                path: "crates/evolve/src/promotion_tests.rs",
                test: "promotion_audit_hash_chain_detects_authorizing_party_tampering",
            },
            Evidence {
                path: "crates/evolve/src/promotion_tests.rs",
                test: "d14_13_g4_candidate_cannot_self_authorize_change_policy_or_relax_safety_budgets",
            },
        ],
    },
    EvolutionRow {
        class: "DeploymentStage shadow / canary / active / rollback",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &[],
        world_modules: &[
            "crates/evolve/src/promotion.rs",
            "crates/evolve/src/promotion_state.rs",
        ],
        proven_module: Some("shadow-canary"),
        evidence: &[
            Evidence {
                path: "crates/evolve/src/promotion_tests.rs",
                test: "d14_13_g2_bounded_shadow_canary_and_failed_invariant_are_enforced_and_audited",
            },
            Evidence {
                path: "crates/evolve/src/promotion_tests.rs",
                test: "d14_13_g3_rollback_and_reopen_restore_exact_prior_bundle_bytes_and_identity",
            },
        ],
    },
    EvolutionRow {
        class: "checkpoint algebra: diff / merge / restrict / retire / transfer",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &["core/context", "core/tool_policy"],
        world_modules: &[
            "crates/evolve/src/checkpoint_algebra.rs",
            "crates/evolve/src/checkpoint_transfer.rs",
        ],
        proven_module: Some("checkpoint-algebra"),
        evidence: &[
            Evidence {
                path: "crates/evolve/src/checkpoint_algebra_tests.rs",
                test: "diff_is_slot_level_and_attributes_delta",
            },
            Evidence {
                path: "crates/evolve/src/checkpoint_algebra_tests.rs",
                test: "merge_rejects_duplicate_slot_and_reruns_admission",
            },
            Evidence {
                path: "crates/evolve/src/checkpoint_algebra_tests.rs",
                test: "restrict_is_monotone_cannot_widen",
            },
            Evidence {
                path: "crates/evolve/src/checkpoint_algebra_tests.rs",
                test: "retire_drops_slot_to_baseline_as_event",
            },
            Evidence {
                path: "crates/evolve/src/checkpoint_algebra_tests.rs",
                test: "transfer_reports_portable_fraction_without_offsetting_gate",
            },
            Evidence {
                path: "crates/evolve/src/checkpoint_algebra_tests.rs",
                test: "every_operator_output_validates_as_policy_bundle",
            },
        ],
    },
    EvolutionRow {
        class: "cross-model transfer + reported portable fraction",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &["core/tool_policy"],
        world_modules: &["crates/evolve/src/checkpoint_transfer.rs"],
        proven_module: Some("cross-model-transfer"),
        evidence: &[
            Evidence {
                path: "crates/evolve/src/transcript_tests.rs",
                test: "portable_fraction_is_reported_not_offsetting",
            },
            Evidence {
                path: "crates/evolve/src/checkpoint_algebra_tests.rs",
                test: "transfer_requires_matching_from_and_to_base_models",
            },
            Evidence {
                path: "crates/evolve/src/checkpoint_algebra_tests.rs",
                test: "transfer_rebinds_every_slot_with_independent_evidence",
            },
        ],
    },
    EvolutionRow {
        class: "second producer of a different method and ArtifactKind",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &["core/context"],
        world_modules: &[
            "crates/evolve/src/prompt_producer.rs",
            "crates/evolve/src/producer.rs",
        ],
        proven_module: Some("second-producer"),
        evidence: &[
            Evidence {
                path: "crates/evolve/src/prompt_producer_tests.rs",
                test: "second_producer_emits_frozen_prompt_and_preference_variants",
            },
            Evidence {
                path: "crates/evolve/src/transcript_tests.rs",
                test: "second_producer_roundtrips_full_pipeline",
            },
            Evidence {
                path: "crates/evolve/src/transcript_tests.rs",
                test: "promotion_decision_is_independent_of_method_field",
            },
        ],
    },
    EvolutionRow {
        class: "offline candidate producer bound to governed inputs",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &["core/tool_policy"],
        world_modules: &["crates/evolve/src/producer.rs"],
        proven_module: Some("producer"),
        evidence: &[
            Evidence {
                path: "crates/evolve/src/producer_tests.rs",
                test: "producer_requires_governed_training_proofs",
            },
            Evidence {
                path: "crates/evolve/src/producer_tests.rs",
                test: "same_governed_input_reproduces_artifact_and_candidate_digest",
            },
        ],
    },
    EvolutionRow {
        class: "consent-gated dataset registry",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &[],
        world_modules: &[
            "crates/evolve/src/dataset_registry.rs",
            "crates/evolve/src/training.rs",
        ],
        proven_module: None,
        evidence: &[
            Evidence {
                path: "crates/evolve/src/verifier_tests.rs",
                test: "d14_12_g1_builder_refuses_every_unverified_or_ineligible_governance_class",
            },
            Evidence {
                path: "crates/evolve/src/verifier_tests.rs",
                test: "d14_12_g3_revocation_excludes_future_membership_and_is_auditable",
            },
            Evidence {
                path: "crates/evolve/src/trajectory_projection_tests.rs",
                test: "revoked_or_denied_consent_run_is_not_projected",
            },
        ],
    },
    EvolutionRow {
        class: "read-only boot-time PolicyBundle resolution",
        authority_boundaries: &["cli-host"],
        strategy_slots: &["core/tool_policy"],
        world_modules: &[
            "crates/agents/src/policy.rs",
            "crates/cli/src/bundle_adapter.rs",
        ],
        proven_module: None,
        evidence: &[
            Evidence {
                path: "crates/agents/src/policy_tests.rs",
                test: "resolution_is_boot_time_and_immutable",
            },
            Evidence {
                path: "crates/agents/src/policy_tests.rs",
                test: "a_promoted_policy_cannot_widen_a_narrowed_filter",
            },
            Evidence {
                path: "crates/cli/src/bundle_adapter_tests.rs",
                test: "the_projection_carries_identity_and_never_a_policy_body",
            },
        ],
    },
    EvolutionRow {
        class: "live self-evolution activation is NO-GO",
        authority_boundaries: &["evolution-control", "kernel-runtime"],
        strategy_slots: &[],
        world_modules: &["crates/evolve/src/conformance.rs"],
        proven_module: None,
        evidence: &[
            Evidence {
                path: "crates/evolve/src/conformance_tests.rs",
                test: "no_runtime_activation_surface_exists_in_kernel_or_agents",
            },
            Evidence {
                path: "crates/evolve/src/conformance_tests.rs",
                test: "kernel_and_agents_do_not_depend_on_core_evolve",
            },
        ],
    },
    EvolutionRow {
        class: "honest disclosure matches spec 6.10",
        authority_boundaries: &["evolution-control"],
        strategy_slots: &[],
        world_modules: &["docs/spec/evolution.md"],
        proven_module: None,
        evidence: &[Evidence {
            path: "crates/evolve/src/conformance_tests.rs",
            test: "the_disclosure_block_states_every_limit_the_code_actually_has",
        }],
    },
];

/// Crates that must never be able to name the control plane. A dependency edge from either into
/// `core-evolve` would put a policy loader inside the runtime trusted computing base, which is
/// the exact thing §6.9 forbids.
const TCB_CRATES_WITHOUT_EVOLVE: [&str; 2] = ["crates/kernel", "crates/agents"];

/// Identifiers that would constitute a runtime activation surface. The check is deliberately
/// lexical and run over the TCB crates only: a match is not proof of a live loader, but the
/// absence of every one of them is a cheap, stable proof that no such surface was added by
/// accident. Semantic enforcement is the kernel's negative-space gate; this is the evolution
/// side of the same claim.
const RUNTIME_ACTIVATION_MARKERS: [&str; 6] = [
    "activate_policy",
    "hot_swap_policy",
    "load_policy_bundle",
    "PolicyLoader",
    "PolicyTrainer",
    "train_policy",
];

/// Clauses the disclosure block in `docs/spec/evolution.md` §6.10 must still carry. Each one is a
/// limit the code genuinely has; if an implementation ever removes the limit, the clause has to
/// be edited in the same change, and until then the gate holds the prose to the code.
const DISCLOSURE_CLAUSES: [&str; 3] = [
    "live self-evolution activation 是 NO-GO",
    "无 loader",
    "无 runtime registry handle",
];

#[derive(Debug)]
pub enum ConformanceError {
    TooManyRows {
        max: usize,
        actual: usize,
    },
    TooMuchEvidence {
        class: String,
        max: usize,
        actual: usize,
    },
    DuplicateClass(String),
    UnplacedRow(String),
    EmptyEvidence(String),
    InvalidSlot {
        class: String,
        slot: String,
        reason: String,
    },
    MissingWorldModule {
        class: String,
        path: PathBuf,
    },
    UnbackedRow {
        class: String,
        test: String,
        path: String,
    },
    OperatorNotCovered(String),
    ModuleNotCovered(String),
    RuntimeActivationSurface {
        path: PathBuf,
        marker: String,
    },
    TcbDependsOnEvolve(PathBuf),
    DisclosureClauseMissing(String),
    SourceTooLarge {
        path: PathBuf,
        max: u64,
        actual: u64,
    },
    InvalidPath(PathBuf),
    Io(std::io::Error),
}

impl std::fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyRows { max, actual } => {
                write!(
                    f,
                    "evolution matrix has {actual} rows, over its {max}-row bound"
                )
            }
            Self::TooMuchEvidence { class, max, actual } => write!(
                f,
                "row `{class}` cites {actual} tests, over its {max}-evidence bound"
            ),
            Self::DuplicateClass(class) => write!(f, "duplicate capability class `{class}`"),
            Self::UnplacedRow(class) => write!(
                f,
                "row `{class}` names no A/B/C plane placement, so it certifies nothing"
            ),
            Self::EmptyEvidence(class) => write!(
                f,
                "row `{class}` is target-only: it cites no test, and a target is not evidence"
            ),
            Self::InvalidSlot {
                class,
                slot,
                reason,
            } => {
                write!(
                    f,
                    "row `{class}` names slot `{slot}`, which is invalid: {reason}"
                )
            }
            Self::MissingWorldModule { class, path } => write!(
                f,
                "row `{class}` names world module `{}`, which is not a file",
                path.display()
            ),
            Self::UnbackedRow { class, test, path } => write!(
                f,
                "row `{class}` is unbacked: test `{test}` is absent from {path}"
            ),
            Self::OperatorNotCovered(operator) => write!(
                f,
                "checkpoint algebra operator `{operator}` has no named test in the matrix"
            ),
            Self::ModuleNotCovered(module) => {
                write!(f, "proven module `{module}` is claimed by no matrix row")
            }
            Self::RuntimeActivationSurface { path, marker } => write!(
                f,
                "runtime activation surface `{marker}` appeared in {}; live self-activation is NO-GO",
                path.display()
            ),
            Self::TcbDependsOnEvolve(path) => write!(
                f,
                "{} names core-evolve; the control plane must stay outside the runtime TCB",
                path.display()
            ),
            Self::DisclosureClauseMissing(clause) => write!(
                f,
                "disclosure clause `{clause}` is missing from docs/spec/evolution.md 6.10"
            ),
            Self::SourceTooLarge { path, max, actual } => write!(
                f,
                "{} is {actual} bytes, over its {max}-byte read bound",
                path.display()
            ),
            Self::InvalidPath(path) => write!(f, "{} is not a regular file", path.display()),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConformanceError {}

impl From<std::io::Error> for ConformanceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Refuse the table unless every row is placed, bounded, backed by tests that exist, and unless
/// the two structural invariants still hold. This is the whole of "zero target-only rows".
pub fn validate(root: &Path) -> Result<(), ConformanceError> {
    validate_rows(root)?;
    validate_operator_coverage()?;
    validate_module_coverage()?;
    validate_no_runtime_activation(root)?;
    validate_disclosure(root)
}

fn validate_rows(root: &Path) -> Result<(), ConformanceError> {
    if EVOLUTION_MATRIX.len() > MAX_EVOLUTION_ROWS {
        return Err(ConformanceError::TooManyRows {
            max: MAX_EVOLUTION_ROWS,
            actual: EVOLUTION_MATRIX.len(),
        });
    }
    let mut seen = BTreeSet::new();
    let mut sources: Vec<(&str, String)> = Vec::new();
    for row in EVOLUTION_MATRIX {
        if !seen.insert(row.class) {
            return Err(ConformanceError::DuplicateClass(row.class.to_owned()));
        }
        if row.authority_boundaries.is_empty()
            && row.strategy_slots.is_empty()
            && row.world_modules.is_empty()
        {
            return Err(ConformanceError::UnplacedRow(row.class.to_owned()));
        }
        if row.evidence.is_empty() {
            return Err(ConformanceError::EmptyEvidence(row.class.to_owned()));
        }
        if row.evidence.len() > MAX_EVIDENCE_PER_ROW {
            return Err(ConformanceError::TooMuchEvidence {
                class: row.class.to_owned(),
                max: MAX_EVIDENCE_PER_ROW,
                actual: row.evidence.len(),
            });
        }
        for slot in row.strategy_slots {
            let id = core_protocol::slot::SlotId((*slot).to_owned());
            if let Err(reason) = id.validate() {
                return Err(ConformanceError::InvalidSlot {
                    class: row.class.to_owned(),
                    slot: (*slot).to_owned(),
                    reason: reason.to_owned(),
                });
            }
        }
        for module in row.world_modules {
            let path = root.join(module);
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
                ConformanceError::MissingWorldModule {
                    class: row.class.to_owned(),
                    path: path.clone(),
                }
            })?;
            if !metadata.is_file() {
                return Err(ConformanceError::MissingWorldModule {
                    class: row.class.to_owned(),
                    path,
                });
            }
        }
        for evidence in row.evidence {
            let source = match sources.iter().find(|(path, _)| *path == evidence.path) {
                Some((_, source)) => source,
                None => {
                    let source = read_bounded(root, evidence.path)?;
                    sources.push((evidence.path, source));
                    &sources.last().expect("evidence source was just pushed").1
                }
            };
            if !defines_test(source, evidence.test) {
                return Err(ConformanceError::UnbackedRow {
                    class: row.class.to_owned(),
                    test: evidence.test.to_owned(),
                    path: evidence.path.to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// A mention is not a definition. Matching `fn name(` (and the async form) is what stops a row
/// from being satisfied by a comment or a call site.
fn defines_test(source: &str, test: &str) -> bool {
    source.contains(&format!("fn {test}(")) || source.contains(&format!("async fn {test}("))
}

fn validate_operator_coverage() -> Result<(), ConformanceError> {
    for operator in CHECKPOINT_ALGEBRA_OPERATORS {
        let covered = EVOLUTION_MATRIX.iter().any(|row| {
            row.evidence
                .iter()
                .any(|evidence| evidence.test.contains(operator))
        });
        if !covered {
            return Err(ConformanceError::OperatorNotCovered(operator.to_owned()));
        }
    }
    Ok(())
}

fn validate_module_coverage() -> Result<(), ConformanceError> {
    for module in PROVEN_MODULES {
        let covered = EVOLUTION_MATRIX
            .iter()
            .any(|row| row.proven_module == Some(module));
        if !covered {
            return Err(ConformanceError::ModuleNotCovered(module.to_owned()));
        }
    }
    Ok(())
}

/// The evolution half of the frozen-TCB claim: neither TCB crate may name `core-evolve`, and
/// neither may carry an activation identifier.
pub fn validate_no_runtime_activation(root: &Path) -> Result<(), ConformanceError> {
    for crate_dir in TCB_CRATES_WITHOUT_EVOLVE {
        let manifest = root.join(crate_dir).join("Cargo.toml");
        let source = read_bounded_path(&manifest)?;
        if source.contains("core-evolve") || source.contains("core_evolve") {
            return Err(ConformanceError::TcbDependsOnEvolve(manifest));
        }
        for entry in source_files(&root.join(crate_dir).join("src"))? {
            let body = read_bounded_path(&entry)?;
            for marker in RUNTIME_ACTIVATION_MARKERS {
                if body.contains(marker) {
                    return Err(ConformanceError::RuntimeActivationSurface {
                        path: entry,
                        marker: marker.to_owned(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Hold the disclosure prose to the code. Each clause names a limit the implementation has; the
/// gate fails if the prose drops one while the limit is still real.
pub fn validate_disclosure(root: &Path) -> Result<(), ConformanceError> {
    let spec = read_bounded(root, "docs/spec/evolution.md")?;
    for clause in DISCLOSURE_CLAUSES {
        if !spec.contains(clause) {
            return Err(ConformanceError::DisclosureClauseMissing(clause.to_owned()));
        }
    }
    Ok(())
}

/// Emit the rows as a tab-separated table. `xtask` appends these lines to the shared §7.2 matrix;
/// the standalone binary prints them directly. Every emitted row is already validated, so there
/// is no status column other than `PASS`.
pub fn emit(root: &Path) -> Result<(), ConformanceError> {
    validate(root)?;
    println!("class\tplane-a\tplane-b\tplane-c\tmodule\tstatus\tevidence");
    for row in EVOLUTION_MATRIX {
        let evidence = row
            .evidence
            .iter()
            .map(|item| format!("test:{}::{}", item.path, item.test))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{}\t{}\t{}\t{}\t{}\tPASS\t{}",
            row.class,
            join_or_dash(row.authority_boundaries),
            join_or_dash(row.strategy_slots),
            join_or_dash(row.world_modules),
            row.proven_module.unwrap_or("-"),
            evidence
        );
    }
    Ok(())
}

fn join_or_dash(values: &[&str]) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values.join("+")
    }
}

fn source_files(directory: &Path) -> Result<Vec<PathBuf>, ConformanceError> {
    let mut files = Vec::new();
    let mut stack = vec![directory.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn read_bounded(root: &Path, relative: &str) -> Result<String, ConformanceError> {
    read_bounded_path(&root.join(relative))
}

fn read_bounded_path(path: &Path) -> Result<String, ConformanceError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConformanceError::InvalidPath(path.to_path_buf()));
    }
    if metadata.len() > MAX_EVIDENCE_SOURCE_BYTES {
        return Err(ConformanceError::SourceTooLarge {
            path: path.to_path_buf(),
            max: MAX_EVIDENCE_SOURCE_BYTES,
            actual: metadata.len(),
        });
    }
    Ok(std::fs::read_to_string(path)?)
}
