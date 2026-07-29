use super::super::{BuilderRef, MATRIX_PATH, Matrix, ReceiptRef, parse_matrix};
use super::{RuntimeReceipt, require_pending_state};
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::{Command, ExitStatus};

const MAX_GIT_OUTPUT_BYTES: usize = 512 * 1024;

pub(super) fn validate_builder_configuration(root: &Path, builder: &BuilderRef) -> Result<()> {
    let head = git_text(
        root,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        "resolve current client policy commit",
    )?;
    require_builder_ancestor(root, &builder.commit, head.trim())
}

pub(super) fn validate_history(
    root: &Path,
    matrix: &Matrix,
    reference: &ReceiptRef,
    receipt: &RuntimeReceipt,
    builder: &BuilderRef,
) -> Result<()> {
    require_clean_evidence_paths(root, reference)?;
    require_commit_and_tree(root, &receipt.tested_commit, &receipt.tested_tree)?;
    require_builder_ancestor(root, &builder.commit, &receipt.tested_commit)?;
    require_evidence_only_delta(root, &receipt.tested_commit, reference)?;
    require_semantically_unchanged_matrix(root, matrix, &receipt.tested_commit)
}

fn require_builder_ancestor(root: &Path, builder: &str, tested_commit: &str) -> Result<()> {
    let revision = format!("{builder}^{{commit}}");
    let resolved = git_text(
        root,
        &["rev-parse", "--verify", "--end-of-options", &revision],
        "resolve runtime builder commit",
    )?;
    if resolved.trim() != builder {
        bail!("runtime builder commit does not resolve exactly");
    }
    let status = git_status(
        root,
        &["merge-base", "--is-ancestor", builder, tested_commit],
        "compare runtime builder with tested commit",
    )?;
    match status.code() {
        Some(0) if builder != tested_commit => Ok(()),
        Some(0) => bail!("runtime builder commit must predate the tested commit"),
        Some(1) => bail!("runtime builder commit is not an ancestor of the tested commit"),
        _ => bail!("git failed while comparing runtime builder with the tested commit"),
    }
}

fn require_clean_evidence_paths(root: &Path, reference: &ReceiptRef) -> Result<()> {
    let paths = [MATRIX_PATH, &reference.path, &reference.attestation_path];
    for args in [
        vec![
            "diff",
            "--quiet",
            "--no-ext-diff",
            "--",
            paths[0],
            paths[1],
            paths[2],
        ],
        vec![
            "diff",
            "--cached",
            "--quiet",
            "--no-ext-diff",
            "--",
            paths[0],
            paths[1],
            paths[2],
        ],
    ] {
        if !git_quiet(root, &args)? {
            bail!("runtime receipt evidence paths have staged or unstaged changes");
        }
    }
    Ok(())
}

fn require_commit_and_tree(root: &Path, tested_commit: &str, tested_tree: &str) -> Result<()> {
    let revision = format!("{tested_commit}^{{commit}}");
    let resolved = git_text(
        root,
        &["rev-parse", "--verify", "--end-of-options", &revision],
        "resolve runtime receipt tested commit",
    )?;
    if resolved.trim() != tested_commit {
        bail!("runtime receipt tested commit does not resolve exactly");
    }
    let tree_revision = format!("{tested_commit}^{{tree}}");
    let tree = git_text(
        root,
        &["rev-parse", "--verify", "--end-of-options", &tree_revision],
        "resolve runtime receipt tested tree",
    )?;
    if tree.trim() != tested_tree {
        bail!("runtime receipt tested tree does not match Git");
    }
    let status = git_status(
        root,
        &["merge-base", "--is-ancestor", tested_commit, "HEAD"],
        "compare runtime receipt tested commit with HEAD",
    )?;
    match status.code() {
        Some(0) => Ok(()),
        Some(1) => bail!("runtime receipt tested commit is not an ancestor of HEAD"),
        _ => bail!("git failed while comparing runtime receipt tested commit with HEAD"),
    }
}

fn require_evidence_only_delta(
    root: &Path,
    tested_commit: &str,
    reference: &ReceiptRef,
) -> Result<()> {
    let exclusions = [
        format!(":(exclude){MATRIX_PATH}"),
        format!(":(exclude){}", reference.path),
        format!(":(exclude){}", reference.attestation_path),
    ];
    if !git_quiet(
        root,
        &[
            "diff",
            "--quiet",
            "--no-ext-diff",
            tested_commit,
            "HEAD",
            "--",
            ".",
            &exclusions[0],
            &exclusions[1],
            &exclusions[2],
        ],
    )? {
        bail!("runtime receipt promotion contains changes outside its three evidence paths");
    }
    require_diff_status(root, tested_commit, MATRIX_PATH, "M")?;
    require_diff_status(root, tested_commit, &reference.path, "A")?;
    require_diff_status(root, tested_commit, &reference.attestation_path, "A")?;
    require_tree_entry(root, tested_commit, MATRIX_PATH)?;
    require_tree_entry(root, "HEAD", MATRIX_PATH)?;
    require_tree_entry(root, "HEAD", &reference.path)?;
    require_tree_entry(root, "HEAD", &reference.attestation_path)
}

fn require_diff_status(root: &Path, base: &str, path: &str, expected: &str) -> Result<()> {
    let output = git_bytes(
        root,
        &[
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            base,
            "HEAD",
            "--",
            path,
        ],
        "inspect runtime receipt evidence delta",
    )?;
    let expected_output = format!("{expected}\0{path}\0");
    if output != expected_output.as_bytes() {
        bail!("runtime receipt evidence path `{path}` must have exact Git status {expected}");
    }
    Ok(())
}

fn require_tree_entry(root: &Path, revision: &str, path: &str) -> Result<()> {
    let output = git_bytes(
        root,
        &["ls-tree", "-z", revision, "--", path],
        "inspect runtime receipt evidence tree entry",
    )?;
    let text = std::str::from_utf8(&output).context("Git tree entry is not UTF-8")?;
    let expected_suffix = format!("\t{path}\0");
    if !text.starts_with("100644 blob ")
        || !text.ends_with(&expected_suffix)
        || text.matches('\0').count() != 1
    {
        bail!("runtime receipt evidence path `{path}` must be one mode-100644 blob");
    }
    Ok(())
}

fn require_semantically_unchanged_matrix(
    root: &Path,
    matrix: &Matrix,
    tested_commit: &str,
) -> Result<()> {
    let object = format!("{tested_commit}:{MATRIX_PATH}");
    let size = git_text(
        root,
        &["cat-file", "-s", &object],
        "inspect base client conformance matrix size",
    )?
    .trim()
    .parse::<u64>()
    .context("base client conformance matrix size is invalid")?;
    if size > super::super::MAX_MATRIX_BYTES {
        bail!("base client conformance matrix exceeds its byte limit");
    }
    let source = git_bytes(
        root,
        &["show", "--no-textconv", &object],
        "read base client conformance matrix",
    )?;
    let base = parse_matrix(&source, "base client conformance matrix")?;
    if base.schema_version != 2 {
        bail!("base client conformance matrix schema_version must be 2");
    }
    require_pending_state(&base)
        .context("base client conformance matrix is not the null/pending receipt state")?;
    let mut normalized = matrix.clone();
    normalized.runtime_receipt = None;
    normalized.version_independence.status = "pending".into();
    for row in &mut normalized.platform_smoke {
        row.status = "pending".into();
    }
    if normalized != base {
        bail!("runtime receipt promotion changes matrix semantics beyond receipt/status promotion");
    }
    Ok(())
}

fn git_text(root: &Path, args: &[&str], label: &str) -> Result<String> {
    String::from_utf8(git_bytes(root, args, label)?).with_context(|| format!("{label}: non-UTF-8"))
}

fn git_bytes(root: &Path, args: &[&str], label: &str) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .with_context(|| format!("cannot {label}"))?;
    if !output.status.success() {
        bail!(
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.stdout.len() > MAX_GIT_OUTPUT_BYTES || output.stderr.len() > MAX_GIT_OUTPUT_BYTES {
        bail!("{label}: Git output exceeds its byte limit");
    }
    Ok(output.stdout)
}

fn git_status(root: &Path, args: &[&str], label: &str) -> Result<ExitStatus> {
    Command::new("git")
        .args(args)
        .current_dir(root)
        .status()
        .with_context(|| format!("cannot {label}"))
}

fn git_quiet(root: &Path, args: &[&str]) -> Result<bool> {
    let status = git_status(root, args, "inspect runtime receipt Git state")?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("git failed while inspecting runtime receipt state"),
    }
}

#[cfg(test)]
mod tests;
