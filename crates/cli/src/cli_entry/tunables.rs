//! Operator tunables rendering, independent of session lifecycle.

use super::options::TunablesExportFormat;

/// Render the optimization surface, optionally narrowed.
///
/// The unfiltered JSON is twenty-three thousand lines. That is the right shape for a machine and
/// the wrong shape for someone looking for one knob, which is why the table exists and why both
/// accept the same filters — an operator who finds a row in the table can re-run with `--format
/// json` and get exactly that subset.
pub(crate) fn tunables_surface_view(
    format: TunablesExportFormat,
    module: Option<&str>,
    filter: Option<&str>,
) -> anyhow::Result<String> {
    let surface = iteron_tunables::surface();
    let needle = filter.map(str::to_ascii_lowercase);
    let matches_family = |entry: &iteron_tunables::export::FamilyEntry| {
        module.is_none_or(|module| entry.module.as_str() == module)
            && needle.as_ref().is_none_or(|needle| {
                entry.id.to_ascii_lowercase().contains(needle)
                    || entry.summary.to_ascii_lowercase().contains(needle)
                    || entry.semantic_key.to_ascii_lowercase().contains(needle)
            })
    };
    let matches_param = |param: &iteron_tunables::Param| {
        module.is_none_or(|module| param.module.as_str() == module)
            && needle
                .as_ref()
                .is_none_or(|needle| param.id.to_ascii_lowercase().contains(needle))
    };
    if let Some(module) = module
        && iteron_tunables::ModuleId::parse(module).is_none()
    {
        anyhow::bail!(
            "unknown module `{module}`; there are 28, listed by `--tunables-export --format table`"
        );
    }

    let families: Vec<_> = surface
        .families
        .iter()
        .filter(|e| matches_family(e))
        .collect();
    let params: Vec<_> = surface.params.iter().filter(|p| matches_param(p)).collect();

    match format {
        TunablesExportFormat::Json => {
            if module.is_none() && filter.is_none() {
                return Ok(iteron_tunables::surface_json()?);
            }
            let mut json = serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": iteron_tunables::SURFACE_SCHEMA_VERSION,
                "filtered": true,
                "families": families,
                "params": params,
            }))?;
            json.push('\n');
            Ok(json)
        }
        TunablesExportFormat::Table => {
            let mut out = String::new();
            if module.is_none() && filter.is_none() {
                out.push_str("MODULES\n");
                for entry in &surface.modules {
                    out.push_str(&format!(
                        "  {:<26} {:>3} families {:>5} params {:>3} artifacts\n",
                        entry.id, entry.families, entry.params, entry.artifacts
                    ));
                }
                out.push('\n');
            }
            out.push_str(&format!("FAMILIES ({})\n", families.len()));
            for entry in families {
                out.push_str(&format!(
                    "  {:<44} {:<24} {}\n",
                    entry.id,
                    entry.module.as_str(),
                    if entry.profile_addressable {
                        "settable"
                    } else {
                        "read-only"
                    }
                ));
            }
            out.push_str(&format!("\nPARAMETERS ({})\n", params.len()));
            for param in params {
                out.push_str(&format!(
                    "  {:<58} {:<22} {:<10} {}\n",
                    param.id,
                    param.module.as_str(),
                    param.default.chars().take(10).collect::<String>(),
                    if param.applied { "applied" } else { "INERT" }
                ));
            }
            Ok(out)
        }
    }
}
