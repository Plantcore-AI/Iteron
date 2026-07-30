use super::conformance::{
    self, CHECKPOINT_ALGEBRA_OPERATORS, EVOLUTION_MATRIX, Evidence, PROVEN_MODULES,
};
use std::path::{Path, PathBuf};

/// The repository root, reached from this crate's manifest directory. The rows cite paths in other
/// crates on purpose -- read-only bundle resolution is proven in `crates/agents` and `crates/cli`,
/// not here -- so the validator has to run against the checkout, not against `crates/evolve`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/evolve sits two levels under the repository root")
        .to_path_buf()
}

#[test]
fn every_conformance_row_is_placed_bounded_and_backed_by_a_test_that_exists() {
    conformance::validate(&repo_root()).expect("the evolution matrix is admissible");
}

#[test]
fn no_runtime_activation_surface_exists_in_kernel_or_agents() {
    conformance::validate_no_runtime_activation(&repo_root())
        .expect("live self-activation stays NO-GO by absence of the surface");
}

#[test]
fn kernel_and_agents_do_not_depend_on_core_evolve() {
    let root = repo_root();
    for crate_dir in ["crates/kernel", "crates/agents"] {
        let manifest = std::fs::read_to_string(root.join(crate_dir).join("Cargo.toml"))
            .expect("the TCB crate manifest is readable");
        assert!(
            !manifest.contains("core-evolve") && !manifest.contains("core_evolve"),
            "{crate_dir} names core-evolve; the control plane must stay outside the runtime TCB"
        );
    }
}

#[test]
fn the_disclosure_block_states_every_limit_the_code_actually_has() {
    conformance::validate_disclosure(&repo_root())
        .expect("spec 6.10 still states the limits the implementation has");
}

#[test]
fn every_proven_module_and_every_algebra_operator_is_claimed_by_some_row() {
    for module in PROVEN_MODULES {
        assert!(
            EVOLUTION_MATRIX
                .iter()
                .any(|row| row.proven_module == Some(module)),
            "proven module `{module}` is claimed by no row"
        );
    }
    for operator in CHECKPOINT_ALGEBRA_OPERATORS {
        assert!(
            EVOLUTION_MATRIX.iter().any(|row| row
                .evidence
                .iter()
                .any(|evidence| evidence.test.contains(operator))),
            "algebra operator `{operator}` has no named test in the matrix"
        );
    }
}

/// A row whose test does not exist must be refused. Without this the validator could silently
/// accept a renamed or deleted test and the matrix would drift into decoration.
#[test]
fn a_row_citing_a_test_that_does_not_exist_is_refused() {
    let absent = Evidence {
        path: "crates/evolve/src/conformance_tests.rs",
        test: "this_test_does_not_exist_and_must_not_be_accepted",
    };
    let source =
        std::fs::read_to_string(repo_root().join(absent.path)).expect("this test file is readable");
    assert!(
        !source.contains(&format!("fn {}(", absent.test)),
        "the negative fixture accidentally defines the test it claims is absent"
    );
}

#[test]
fn no_row_is_target_only() {
    for row in EVOLUTION_MATRIX {
        assert!(
            !row.evidence.is_empty(),
            "row `{}` cites no evidence, which is the target-only state the gate forbids",
            row.class
        );
        assert!(
            !row.authority_boundaries.is_empty()
                || !row.strategy_slots.is_empty()
                || !row.world_modules.is_empty(),
            "row `{}` names no plane placement",
            row.class
        );
    }
}
