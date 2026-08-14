use anyhow::{Context, Result, bail};
use std::io::Read;
use std::path::Path;

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Keep the research harness source-accessible while structurally excluding it from the public
/// release archive, installer, and release build matrix.
pub(super) fn validate(root: &Path) -> Result<()> {
    let workflow = read(root, ".github/workflows/release.yml")?;
    let release_binaries = workflow
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("binary:"))
        .collect::<Vec<_>>();
    if release_binaries != ["binary: iteron", "binary: iteron", "binary: iteron"]
        || !workflow.contains("--release --locked -p iteron-cli")
    {
        bail!("release CI must build exactly the three platform variants of `iteron`");
    }

    let package = read(root, "release-tools/package.py")?;
    if package.contains("iteron-harness")
        || !package.contains("(arguments.binary, binary_filename(target), 0o755),")
    {
        bail!("release archive packaging must contain only the selected Iteron binary");
    }

    for relative in ["install.sh", "release-tools/verify_release.py"] {
        if read(root, relative)?.contains("iteron-harness") {
            bail!("{relative} must not install or verify the repository-only research harness");
        }
    }
    Ok(())
}

fn read(root: &Path, relative: &str) -> Result<String> {
    let path = root.join(relative);
    let mut source = String::new();
    std::fs::File::open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut source)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if source.len() as u64 > MAX_FILE_BYTES {
        bail!("{relative} exceeds the research-distribution conformance byte bound");
    }
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn research_harness_is_not_a_release_payload() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        validate(root).unwrap();
    }
}
