#![cfg(unix)]

use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn provider_free_cycle_reaches_activation_and_exact_rollback() {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let authorization = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/synthetic-cycle-authorization-v1.json")
        .canonicalize()
        .unwrap();
    let output = std::env::temp_dir().join(format!(
        "iteron-engineering-cycle-{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    let status = iteron_eval::engineering_cycle::run_synthetic_cycle_cli(&[
        "--authorization".into(),
        authorization.to_string_lossy().into_owned(),
        "--output".into(),
        output.to_string_lossy().into_owned(),
    ]);
    assert_eq!(status, ExitCode::SUCCESS);
    let receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("synthetic-cycle-receipt.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["provider"], "none");
    assert_eq!(receipt["provider_calls"], 0);
    assert_eq!(receipt["primary_producer"], "rule_search");
    assert_eq!(receipt["secondary_producer"], "prompt_preference");
    assert_eq!(receipt["stage_order_observed"], true);
    assert_eq!(receipt["held_out_separation_observed"], true);
    assert_eq!(receipt["human_authorized_promotion_input_consumed"], true);
    assert_eq!(receipt["activation_observed"], true);
    assert_eq!(receipt["exact_rollback_observed"], true);
    assert_eq!(receipt["model_training_performed"], false);
    assert_eq!(receipt["live_score_claimed"], false);
    std::fs::remove_dir_all(&output).unwrap();
}
