mod model;
mod render;
mod validate;

use anyhow::{Context, Result, bail};
use model::Registry;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let root = selected_root(&mut args)?;
    let registry = load_registry(&root)?;

    match args.as_slice() {
        [group, command] if group == "boundaries" && command == "check" => {
            let report = validate::validate(&root, &registry)?;
            render::check_generated(&root, &registry)?;
            println!(
                "boundary contract valid: {} files, {} boundaries, {} overlays, {} packages",
                report.files,
                registry.boundaries.len(),
                registry.overlays.len(),
                report.packages
            );
        }
        [group, command] if group == "boundaries" && command == "generate" => {
            validate::validate(&root, &registry)?;
            render::write_generated(&root, &registry)?;
            println!("generated OWNERSHIP.md and .github/CODEOWNERS");
        }
        [group, command] if group == "boundaries" && command == "list" => {
            validate::validate(&root, &registry)?;
            validate::list(&registry, false);
        }
        [group, command, flag]
            if group == "boundaries" && command == "list" && flag == "--open" =>
        {
            validate::validate(&root, &registry)?;
            validate::list(&registry, true);
        }
        [group, command] if group == "boundaries" && command == "readiness" => {
            validate::validate(&root, &registry)?;
            validate::readiness(&registry)?;
        }
        [group, command, path] if group == "boundaries" && command == "explain" => {
            validate::validate(&root, &registry)?;
            validate::explain(&registry, path)?;
        }
        [group, command, flag, base]
            if group == "boundaries" && command == "affected" && flag == "--base" =>
        {
            validate::validate(&root, &registry)?;
            validate::affected(&root, &registry, base)?;
        }
        [group, command, flag, base]
            if group == "boundaries" && command == "check-pr" && flag == "--base" =>
        {
            validate::validate(&root, &registry)?;
            let body = std::env::var("PR_BODY").context("PR_BODY is not set")?;
            validate::check_pr(&root, &registry, base, &body)?;
        }
        [group, command, flag, base]
            if group == "boundaries" && command == "check-reviews" && flag == "--base" =>
        {
            validate::validate(&root, &registry)?;
            let author = std::env::var("PR_AUTHOR").context("PR_AUTHOR is not set")?;
            let reviews_file = std::env::var("REVIEWS_FILE").context("REVIEWS_FILE is not set")?;
            let reviews = std::fs::read(&reviews_file)
                .with_context(|| format!("cannot read review evidence `{reviews_file}`"))?;
            validate::check_reviews(&root, &registry, base, &author, &reviews)?;
        }
        _ => {
            bail!(
                "usage: core-xtask [--repo PATH] boundaries <check|generate|list [--open]|readiness|explain PATH|affected --base REV|check-pr --base REV|check-reviews --base REV>"
            )
        }
    }
    Ok(())
}

fn selected_root(args: &mut Vec<String>) -> Result<PathBuf> {
    if args.first().is_some_and(|argument| argument == "--repo") {
        if args.len() < 2 {
            bail!("--repo requires a repository path");
        }
        let root = std::fs::canonicalize(&args[1])
            .with_context(|| format!("cannot resolve repository path `{}`", args[1]))?;
        if !root.is_dir() || !root.join(".git").exists() {
            bail!("--repo must name a Git working tree root");
        }
        args.drain(0..2);
        Ok(root)
    } else {
        repository_root()
    }
}

fn repository_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("xtask must be directly below the repository root")
}

fn load_registry(root: &Path) -> Result<Registry> {
    let path = root.join("governance/boundaries.json");
    let bytes = std::fs::read(&path)
        .with_context(|| format!("cannot read boundary registry at {}", path.display()))?;
    if bytes.len() > 2 * 1024 * 1024 {
        bail!("boundary registry exceeds the 2 MiB limit");
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid boundary registry at {}", path.display()))
}
