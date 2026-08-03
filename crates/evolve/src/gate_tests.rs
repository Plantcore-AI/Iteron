use super::gate::{self, ProofMechanism};
use crate::conformance::{CHECKPOINT_ALGEBRA_OPERATORS, PROVEN_MODULES};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/evolve sits two levels under the repository root")
        .to_path_buf()
}

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "core-evolve-gate-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).expect("scratch directory is creatable");
    path
}

/// The gate's own determinism criterion. Two runs under two different scratch roots must produce
/// byte-identical reports, which is only true if nothing about *where* the run happened reaches the
/// signed body. An earlier draft interpolated an error `Display` that carried the scratch path, and
/// this test is what would have caught it.
#[test]
fn the_gate_report_is_byte_identical_across_two_independent_runs() {
    let repo = repo_root();
    let first = gate::run(&repo, &scratch("determinism-a")).expect("first gate run succeeds");
    let second = gate::run(&repo, &scratch("determinism-b")).expect("second gate run succeeds");

    assert_eq!(first.body, second.body, "the signed body is run-dependent");
    assert_eq!(first.body_digest, second.body_digest);
    assert_eq!(first.signature, second.signature);
    assert_eq!(first.render(), second.render());
}

#[test]
fn the_gate_proves_every_module_and_every_algebra_operator() {
    let report = gate::run(&repo_root(), &scratch("modules")).expect("gate run succeeds");
    assert!(report.passed(), "gate did not pass: {}", report.render());

    for module in PROVEN_MODULES {
        let proof = report
            .body
            .modules
            .iter()
            .find(|proof| proof.module == module)
            .unwrap_or_else(|| panic!("module `{module}` has no proof"));
        assert!(proof.passed, "module `{module}` is unproven");
    }
    for operator in CHECKPOINT_ALGEBRA_OPERATORS {
        assert!(
            report
                .body
                .operators
                .iter()
                .any(|proof| proof.operator == operator),
            "operator `{operator}` was never exercised"
        );
    }
}

/// Both producer orders must run, and each must chain-verify every event it wrote and replay to the
/// same active bundle the run reported. A transcript that verifies fewer events than it emitted has
/// a hole in the chain.
#[test]
fn both_producer_orders_chain_verify_and_replay_to_the_reported_bundle() {
    let report = gate::run(&repo_root(), &scratch("orders")).expect("gate run succeeds");
    let orders: Vec<&str> = report
        .body
        .transcripts
        .iter()
        .map(|transcript| transcript.producer_order.as_str())
        .collect();
    assert!(orders.contains(&"rule,prompt"), "orders were {orders:?}");
    assert!(orders.contains(&"prompt,rule"), "orders were {orders:?}");

    for transcript in &report.body.transcripts {
        assert!(
            transcript.deterministic,
            "{} was non-deterministic",
            transcript.producer_order
        );
        assert_eq!(
            transcript.chain_verified_events, transcript.event_count,
            "{} left events outside the verified chain",
            transcript.producer_order
        );
        assert_eq!(
            transcript.replayed_active_bundle_digest, transcript.final_active_bundle_digest,
            "{} replayed to a different active bundle",
            transcript.producer_order
        );
    }
}

/// The separation-of-duties claim has to hold for the right reasons. `transfer` is observed through
/// the transcript rather than called here, and the report must say so instead of rounding it up to
/// an in-process call.
#[test]
fn the_report_does_not_overstate_how_a_proof_was_obtained() {
    let report = gate::run(&repo_root(), &scratch("mechanism")).expect("gate run succeeds");
    assert!(report.body.separation_of_duties_verified);
    assert!(
        report
            .body
            .separation_of_duties_detail
            .contains("unrelated_key_refused_by_signature=true"),
        "detail was `{}`",
        report.body.separation_of_duties_detail
    );

    let transfer = report
        .body
        .operators
        .iter()
        .find(|proof| proof.operator == "transfer")
        .expect("transfer has a proof");
    assert_eq!(
        transfer.mechanism,
        ProofMechanism::TranscriptEvent,
        "transfer is observed through the transcript, not called in process"
    );
    for operator in ["diff", "merge", "restrict", "retire"] {
        let proof = report
            .body
            .operators
            .iter()
            .find(|proof| proof.operator == operator)
            .unwrap_or_else(|| panic!("`{operator}` has no proof"));
        assert_eq!(proof.mechanism, ProofMechanism::InProcess);
    }
}
