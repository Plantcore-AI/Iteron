use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

const KERNEL_SOURCE: &str = "crates/kernel/src/lib.rs";
const MAX_KERNEL_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_READ_ONLY_TOOLS: usize = 256;
const SPAWN_SIGNATURE: &str = "    async fn spawn_subagent(";
const BUDGET_BINDING: &str =
    "let Some(budget) = core_agents::subagent_budget(remaining_turns, remaining_wall) else {";

/// Validate cross-crate contracts that intentionally do not belong in the runtime dependency
/// graph. The build plane may depend on both policy and executor crates; `core-agents` remains
/// provider/executor-free.
pub fn validate(root: &Path) -> Result<()> {
    validate_read_only_registry(root)?;
    let kernel = read_bounded_utf8(root, KERNEL_SOURCE, MAX_KERNEL_SOURCE_BYTES)?;
    validate_kernel_budget_binding(&kernel)
}

fn validate_read_only_registry(root: &Path) -> Result<()> {
    let registry = core_tools::Registry::read_only(root).map_err(|error| {
        anyhow::anyhow!("cannot construct core-tools read-only registry: {error}")
    })?;
    let actual = registry
        .specs()
        .into_iter()
        .map(|spec| spec.name)
        .collect::<Vec<_>>();
    validate_read_only_names(core_agents::READ_ONLY_TOOLS, &actual)
}

fn validate_read_only_names(expected: &[&str], actual: &[String]) -> Result<()> {
    if expected.len() > MAX_READ_ONLY_TOOLS || actual.len() > MAX_READ_ONLY_TOOLS {
        bail!("read-only tool contract exceeds the {MAX_READ_ONLY_TOOLS}-tool build-plane limit");
    }
    let expected_set = expected.iter().copied().collect::<BTreeSet<_>>();
    let actual_set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if expected_set.len() != expected.len() {
        bail!("core-agents READ_ONLY_TOOLS contains duplicate names");
    }
    if actual_set.len() != actual.len() {
        bail!("core-tools read-only registry contains duplicate names");
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

fn validate_kernel_budget_binding(source: &str) -> Result<()> {
    let body = kernel_spawn_body(source)?;
    let bindings = body
        .lines()
        .filter(|line| line.trim() == BUDGET_BINDING)
        .count();
    if bindings != 1 {
        bail!(
            "kernel spawn_subagent must bind its budget exactly once through def.rs::subagent_budget()"
        );
    }
    if body.contains("Budget {") || body.contains("budget.max_") {
        bail!("kernel spawn_subagent must not construct or mutate a second subagent budget policy");
    }
    Ok(())
}

fn kernel_spawn_body(source: &str) -> Result<&str> {
    let mut starts = source.match_indices(SPAWN_SIGNATURE);
    let (start, _) = starts
        .next()
        .context("kernel source lacks spawn_subagent")?;
    if starts.next().is_some() {
        bail!("kernel source repeats spawn_subagent");
    }
    let after_start = &source[start + SPAWN_SIGNATURE.len()..];
    let end = [
        "\n    fn ",
        "\n    async fn ",
        "\n    pub fn ",
        "\n    pub async fn ",
    ]
    .into_iter()
    .filter_map(|signature| after_start.find(signature))
    .min()
    .context("kernel spawn_subagent has no following method boundary")?;
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
    fn d11_10_kernel_budget_drift_fails() {
        let bound = format!(
            "{SPAWN_SIGNATURE}&mut self) {{\n        {BUDGET_BINDING}\n        }};\n    }}\n\n    fn next("
        );
        assert!(validate_kernel_budget_binding(&bound).is_ok());

        let inline = format!(
            "{SPAWN_SIGNATURE}&mut self) {{\n        let budget = Budget {{ max_turns: 16 }};\n    }}\n\n    fn next("
        );
        assert!(validate_kernel_budget_binding(&inline).is_err());

        let widened = format!(
            "{SPAWN_SIGNATURE}&mut self) {{\n        {BUDGET_BINDING}\n        }};\n        budget.max_turns = 16;\n    }}\n\n    fn next("
        );
        assert!(validate_kernel_budget_binding(&widened).is_err());
    }
}
