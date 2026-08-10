//! Operator projection of the immutable runtime-effective tunables checkpoint.

use core_protocol::{RunGenesisTunableEntryV2, RunGenesisTunablesSnapshotV2};
use serde::Serialize;
use std::io::Write as _;

#[derive(Serialize)]
struct EffectiveConfigDocument<'a> {
    kind: &'static str,
    runtime_bound: bool,
    registry_id: &'a str,
    registry_revision: u16,
    registry_digest_sha256: &'a str,
    profile_digest_sha256: Option<&'a str>,
    effective_digest_sha256: &'a str,
    resolution_digest_sha256: &'a str,
    entries: Vec<&'a RunGenesisTunableEntryV2>,
}

pub(crate) fn emit(
    snapshot: &RunGenesisTunablesSnapshotV2,
    family: Option<&str>,
    format: crate::tunables::ExplainFormat,
) -> anyhow::Result<u8> {
    let entries = select_entries(snapshot, family)?;
    match format {
        crate::tunables::ExplainFormat::Json => {
            let document = EffectiveConfigDocument {
                kind: "runtime_effective_config",
                runtime_bound: true,
                registry_id: &snapshot.registry_id,
                registry_revision: snapshot.registry_revision,
                registry_digest_sha256: &snapshot.registry_digest_sha256,
                profile_digest_sha256: snapshot.profile_digest_sha256.as_deref(),
                effective_digest_sha256: &snapshot.effective_digest_sha256,
                resolution_digest_sha256: &snapshot.resolution_digest_sha256,
                entries,
            };
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer_pretty(&mut stdout, &document)?;
            stdout.write_all(b"\n")?;
        }
        crate::tunables::ExplainFormat::Text => emit_text(snapshot, &entries)?,
    }
    Ok(crate::output::EXIT_SUCCESS)
}

fn select_entries<'a>(
    snapshot: &'a RunGenesisTunablesSnapshotV2,
    selector: Option<&str>,
) -> anyhow::Result<Vec<&'a RunGenesisTunableEntryV2>> {
    let Some(selector) = selector else {
        return Ok(snapshot.entries.iter().collect());
    };
    let entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.family_id == selector || entry.semantic_key == selector)
        .ok_or_else(|| anyhow::anyhow!("unknown effective tunable family `{selector}`"))?;
    Ok(vec![entry])
}

fn emit_text(
    snapshot: &RunGenesisTunablesSnapshotV2,
    entries: &[&RunGenesisTunableEntryV2],
) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "runtime-effective tunables · registry {}@{} · effective {} · profile {}",
        snapshot.registry_id,
        snapshot.registry_revision,
        snapshot.effective_digest_sha256,
        snapshot.profile_digest_sha256.as_deref().unwrap_or("none"),
    )?;
    for entry in entries {
        writeln!(
            stdout,
            "{} {} ({}) · state={:?} · profile={}",
            entry.ordinal, entry.family_id, entry.semantic_key, entry.state, entry.profile_applied,
        )?;
        write_json_line(&mut stdout, "  value", entry.effective_value.as_ref())?;
        write_json_line(&mut stdout, "  provenance", entry.provenance.as_ref())?;
        if !entry.ceiling_adjustments.is_empty() {
            writeln!(
                stdout,
                "  ceilings={}",
                serde_json::to_string(&entry.ceiling_adjustments)?
            )?;
        }
        write_json_line(&mut stdout, "  inactive", entry.inactive_reason.as_ref())?;
    }
    Ok(())
}

fn write_json_line(
    output: &mut impl std::io::Write,
    label: &str,
    value: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    if let Some(value) = value {
        writeln!(output, "{label}={}", serde_json::to_string(value)?)?;
    }
    Ok(())
}
