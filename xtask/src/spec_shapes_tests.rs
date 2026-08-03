use super::*;

struct Fixture(std::path::PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A repository whose spec prints `spec` and whose protocol declares `protocol`.
///
/// The protocol side carries enough real types to clear the anti-vacuity floor, so a test that
/// wants to prove a *shape* failure is not accidentally proving the floor instead.
fn fixture(spec: &str, protocol: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "core-spec-shapes-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join(SPEC_DIR)).unwrap();
    std::fs::create_dir_all(root.join(PROTOCOL_DIR)).unwrap();
    std::fs::write(root.join(SPEC_DIR).join("abi.md"), spec).unwrap();
    std::fs::write(root.join(PROTOCOL_DIR).join("lib.rs"), protocol).unwrap();
    Fixture(root)
}

/// Eight matching types, so the anti-vacuity floor is cleared and a failure is about the shape.
fn ballast() -> (String, String) {
    let mut spec = String::new();
    let mut code = String::new();
    for index in 0..8 {
        spec.push_str(&format!(
            "```rust\npub struct Ballast{index} {{ pub a: u8 }}\n```\n"
        ));
        code.push_str(&format!("pub struct Ballast{index} {{ pub a: u8 }}\n"));
    }
    (spec, code)
}

#[test]
fn a_clean_pair_passes() {
    let (spec, code) = ballast();
    let fixture = fixture(&spec, &code);
    validate_with(&fixture.0, &[]).expect("matching shapes must pass");
}

/// The exact regression this gate exists for: the pre-freeze `kind` sketch, reintroduced.
#[test]
fn a_field_the_code_does_not_declare_turns_the_gate_red() {
    let (mut spec, code) = ballast();
    spec.push_str(
        "```rust\npub struct ContextRequest {\n    pub kind: RequestKind,\n    pub selectors: \
         Vec<ContextSelector>,\n}\n```\n",
    );
    let code = format!("{code}pub struct ContextRequest {{ pub selectors: Vec<u8> }}\n");
    let fixture = fixture(&spec, &code);
    let error = validate_with(&fixture.0, &[]).unwrap_err().to_string();
    assert!(error.contains("ContextRequest"), "{error}");
    assert!(
        error.contains("kind"),
        "names the offending member: {error}"
    );
    assert!(
        error.contains("abi.md:"),
        "names the file and line: {error}"
    );
    assert!(
        error.contains("selectors"),
        "prints the real shape: {error}"
    );
}

/// A degrading arm is the ABI's forward-compatibility rule; dropping it from a block is a defect.
#[test]
fn deleting_a_degrading_unknown_arm_turns_the_gate_red() {
    let (mut spec, code) = ballast();
    spec.push_str("```rust\npub enum Producer {\n    Slot,\n    Tool,\n    Run,\n}\n```\n");
    let code = format!("{code}pub enum Producer {{ Slot, Tool, Run, Unknown(String) }}\n");
    let fixture = fixture(&spec, &code);
    let error = validate_with(&fixture.0, &[]).unwrap_err().to_string();
    assert!(error.contains("Producer"), "{error}");
    assert!(error.contains("Unknown"), "names the missing arm: {error}");
}

/// A rename that makes the checker stop looking must fail, not pass.
#[test]
fn matching_nothing_is_a_failure_not_a_pass() {
    let (spec, _) = ballast();
    let fixture = fixture(&spec, "pub struct RenamedAwayEntirely { pub a: u8 }\n");
    let error = validate_with(&fixture.0, &[]).unwrap_err().to_string();
    assert!(
        error.contains("anti-vacuity"),
        "a vacuous match must say so: {error}"
    );
}

/// A recorded divergence is accepted, and only for the members it names.
#[test]
fn a_recorded_divergence_is_accepted_but_does_not_licence_the_rest() {
    const RECORDED: &[Divergence] = &[Divergence {
        ty: "ContextSelector",
        code_only: &["Unknown"],
        spec_only: &[],
        reason: "the degrading arm is the forward-compatibility rule, not a member of the \
                 vocabulary the spec enumerates",
    }];

    let (mut spec, code) = ballast();
    spec.push_str("```rust\npub enum ContextSelector {\n    Repo,\n    Memory,\n}\n```\n");
    let accepted = format!("{code}pub enum ContextSelector {{ Repo, Memory, Unknown }}\n");
    let recorded = fixture(&spec, &accepted);
    validate_with(&recorded.0, RECORDED).expect("the recorded `Unknown` divergence is accepted");

    let extra = format!("{code}pub enum ContextSelector {{ Repo, Memory, Unknown, Smuggled }}\n");
    let smuggled = fixture(&spec, &extra);
    let error = validate_with(&smuggled.0, RECORDED)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("Smuggled"),
        "an unrecorded member must still fail: {error}"
    );
}

/// An allowlist entry that stops being true must fail, or it rots into the comment it replaced.
#[test]
fn a_divergence_that_is_no_longer_live_turns_the_gate_red() {
    const STALE: &[Divergence] = &[Divergence {
        ty: "ContextSelector",
        code_only: &["Unknown"],
        spec_only: &[],
        reason: "recorded once, then the spec was corrected and nobody deleted this",
    }];

    let (mut spec, code) = ballast();
    // The spec now prints the arm, so the recorded divergence describes nothing.
    spec.push_str("```rust\npub enum ContextSelector {\n    Repo,\n    Unknown,\n}\n```\n");
    let agreed = format!("{code}pub enum ContextSelector {{ Repo, Unknown }}\n");
    let stale = fixture(&spec, &agreed);
    let error = validate_with(&stale.0, STALE).unwrap_err().to_string();
    assert!(
        error.contains("not live") || error.contains("now agree"),
        "a stale allowlist entry must be named as stale: {error}"
    );
}

/// Prose that says a token does not exist is the warning, not the defect.
#[test]
fn prose_naming_a_token_to_deny_it_is_not_a_failure() {
    let (mut spec, code) = ballast();
    spec.push_str("\n全仓不存在名为 `CapabilityTier` 的类型,本节亦 MUST NOT 引入这个名字。\n");
    spec.push_str("\n内容寻址字段名为 `hash`,不是 `content_hash`。\n");
    let prose = fixture(&spec, &code);
    validate_with(&prose.0, &[]).expect("a prose warning must not be read as a declaration");
}

/// The tokens that named nothing and were printed as a normative shape anyway.
#[test]
fn a_denied_identifier_in_a_fenced_block_turns_the_gate_red() {
    let (mut spec, code) = ballast();
    spec.push_str(
        "```rust\npub struct EffectProposal {\n    pub effect_kind: CapabilityTier,\n    pub \
         capability_handle: u64,\n}\n```\n",
    );
    let printed = fixture(&spec, &code);
    let error = validate_with(&printed.0, &[]).unwrap_err().to_string();
    assert!(error.contains("CapabilityTier"), "{error}");
    assert!(error.contains("capability_handle"), "{error}");
    assert!(error.contains("effect_kind"), "{error}");
    assert!(
        error.contains("abi.md:"),
        "names the file and line: {error}"
    );
}

/// `hash` is a real field; a whole-word rule must not let `content_hash` hide behind it.
#[test]
fn the_denied_scan_matches_whole_words_only() {
    assert!(word_appears("pub hash: String,", "hash"));
    assert!(!word_appears("pub content_hash: String,", "hash"));
    assert!(word_appears("pub content_hash: String,", "content_hash"));
}

/// Every recorded divergence has to carry a reason, or the allowlist becomes a shrug.
#[test]
fn every_recorded_divergence_states_a_reason() {
    for divergence in DIVERGENCES {
        assert!(
            divergence.reason.len() > 30,
            "`{}` needs a reason, not a placeholder",
            divergence.ty
        );
        assert!(
            !divergence.code_only.is_empty() || !divergence.spec_only.is_empty(),
            "`{}` records no divergence and should be deleted",
            divergence.ty
        );
    }
    for (identifier, reason) in DENIED_IDENTIFIERS {
        assert!(
            reason.len() > 20,
            "`{identifier}` needs a reason it names nothing"
        );
    }
}
