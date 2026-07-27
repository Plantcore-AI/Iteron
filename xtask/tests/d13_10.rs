//! D13-10 — Ownership / review-contract enforcement must not be fully inactive in bootstrap.
//!
//! Honest bootstrap keeps *ordinary* responsibility review non-enforcing, but the ownership
//! registry (`governance/boundaries.json`) is the root of trust: it defines every boundary and
//! the enforcement mode itself. A registry change must therefore still carry the Owner's
//! accountable authorship or a current-commit Owner approval, even while the registry is in
//! bootstrap mode. Before the fix, `boundaries check-reviews` returned a blanket non-enforcing
//! success for *every* bootstrap change, so an unrelated contributor could rewrite the registry.
//!
//! `core-xtask` is a managed binary crate with no library target (the repo's own conformance
//! rule forbids one), so this exercises the behavior end to end through the built CLI against a
//! throwaway fixture repository seeded from the current tree.

use std::path::{Path, PathBuf};
use std::process::Command;

const OWNER_LOGIN: &str = "fr0m-scratch";

fn xtask_bin() -> &'static str {
    env!("CARGO_BIN_EXE_core-xtask")
}

fn source_repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits directly under the repository root")
        .to_path_buf()
}

struct Fixture {
    root: PathBuf,
    reviews: PathBuf,
    base: String,
}

impl Fixture {
    /// Seed a standalone repo from the current tree (so the full `validate()` precondition
    /// passes), commit it as the base, then commit an ownership-registry change as the candidate.
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("core-d13-10-{}-{nonce}", std::process::id()));
        let root = dir.join("repo");
        std::fs::create_dir_all(&root).unwrap();

        // Export the tracked tree at HEAD (no `.git`, no build artifacts) into the fixture.
        let src = source_repo();
        let piped = format!(
            "git -C {src} archive --format=tar HEAD | tar -x -C {dst}",
            src = shell_quote(&src),
            dst = shell_quote(&root),
        );
        run_ok(Command::new("sh").arg("-c").arg(&piped), "git archive | tar");

        git(&root, &["init", "--quiet", "--initial-branch=main"]);
        git(&root, &["config", "user.name", "D13 Test"]);
        git(&root, &["config", "user.email", "d13-test@example.invalid"]);
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "--quiet", "--no-gpg-sign", "-m", "seed"]);
        let base = git(&root, &["rev-parse", "HEAD"]);

        // Candidate mutates the ownership registry. A byte-level change is enough: the diff now
        // reports `governance/boundaries.json`, so the Owner review-floor groups form. The parsed
        // registry is unchanged (trailing whitespace is JSON-insignificant), so `validate()` and
        // registry validity still hold — only the review floor decides the outcome.
        let registry_path = root.join("governance/boundaries.json");
        let mut contents = std::fs::read_to_string(&registry_path).unwrap();
        contents.push('\n');
        std::fs::write(&registry_path, contents).unwrap();
        git(&root, &["add", "--", "governance/boundaries.json"]);
        git(&root, &["commit", "--quiet", "--no-gpg-sign", "-m", "registry change"]);

        let reviews = dir.join("reviews.json");
        std::fs::write(&reviews, "[]").unwrap();

        Fixture { root, reviews, base }
    }

    /// Invoke `core-xtask boundaries check-reviews` for the given PR author with empty reviews.
    fn check_reviews(&self, author: &str) -> std::process::Output {
        Command::new(xtask_bin())
            .args(["--repo"])
            .arg(&self.root)
            .args(["boundaries", "check-reviews", "--base", &self.base])
            .env("PR_AUTHOR", author)
            .env("REVIEWS_FILE", &self.reviews)
            .output()
            .expect("run core-xtask boundaries check-reviews")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(parent) = self.root.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}

fn git(root: &Path, args: &[&str]) -> String {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .current_dir(root);
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn run_ok(cmd: &mut Command, label: &str) {
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{label} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The bootstrap ownership-registry floor: a registry change by an outside contributor with no
/// Owner approval must be REJECTED, while the same change authored by the Owner is ACCEPTED. The
/// only difference between the two invocations is the PR author, so a green result proves the
/// floor (not some unrelated `validate()` failure) is what rejects the contributor. Before the
/// fix both invocations succeeded.
#[test]
fn bootstrap_registry_change_enforces_the_owner_floor() {
    let fixture = Fixture::new();

    let contributor = fixture.check_reviews("outside-contributor");
    assert!(
        !contributor.status.success(),
        "an ownership-registry change by a non-owner with no Owner approval must be rejected \
         even in bootstrap mode.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&contributor.stdout),
        String::from_utf8_lossy(&contributor.stderr),
    );

    let owner = fixture.check_reviews(OWNER_LOGIN);
    assert!(
        owner.status.success(),
        "the Owner's accountable authorship must satisfy the bootstrap registry floor \
         (a failure here means validate() rejected the fixture, not the review floor).\n\
         stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&owner.stdout),
        String::from_utf8_lossy(&owner.stderr),
    );
}
