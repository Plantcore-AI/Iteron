//! Local record maintenance and history presentation; never constructs a provider.

use super::options::{Cli, RecordAction};
use crate::output;
use iteron_protocol::TenantId;
use std::path::PathBuf;
const UNIX_MS_ON_UNUSABLE_CLOCK: u64 = 0;

/// `--runs-dir` as an absolute location. An absolute value is honoured verbatim; a relative one
/// (including the `.iteron/runs` default) resolves under the CANONICALIZED repo, never against the
/// process working directory — `iteron -C /elsewhere` must write its audit record under
/// `/elsewhere/.iteron/runs`, not beside wherever the shell happened to be.
pub(crate) fn resolve_runs_dir(cli: &Cli, repo: &std::path::Path) -> PathBuf {
    if cli.runs_dir.is_absolute() {
        cli.runs_dir.clone()
    } else {
        repo.join(&cli.runs_dir)
    }
}

pub(crate) fn erasure_now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(iteron_tunables::param_integer(
            "cli.main.unix_ms_on_unusable_clock",
            UNIX_MS_ON_UNUSABLE_CLOCK,
        ))
}

pub(crate) fn local_erasure_request(
    runs_dir: &std::path::Path,
    operation_id: &str,
    target: iteron_protocol::ErasureTarget,
) -> anyhow::Result<iteron_protocol::ErasureRequest> {
    let authority = iteron_record::erasure::authorize_local_erasure(runs_dir)?;
    Ok(iteron_protocol::ErasureRequest {
        operation_id: iteron_protocol::ErasureOperationId::new(operation_id)?,
        authority_id: authority.id().clone(),
        requested_at_unix_ms: erasure_now_unix_ms(),
        target,
    })
}

pub(crate) fn print_erasure_receipt(
    runs_dir: &std::path::Path,
    receipt: &iteron_protocol::ErasureReceipt,
) -> anyhow::Result<u8> {
    if receipt.state() == iteron_protocol::ErasureState::Verified
        && matches!(
            receipt.request().target,
            iteron_protocol::ErasureTarget::ExactSession { .. }
        )
    {
        crate::artifacts::remove_erased_catalog(runs_dir, receipt).map_err(|_| {
            anyhow::anyhow!("verified session artifact index cleanup is unavailable")
        })?;
    }
    println!("{}", serde_json::to_string_pretty(receipt)?);
    Ok(output::EXIT_SUCCESS)
}

pub(crate) fn run_record_command(
    runs_dir: &std::path::Path,
    action: &RecordAction,
) -> anyhow::Result<u8> {
    use iteron_protocol::{ErasureContentDigest, ErasureScopeId, ErasureTarget, ErasureTargetId};

    let scope = || ErasureScopeId::new(TenantId::default().0);
    match action {
        RecordAction::Delete {
            run_id,
            operation_id,
        } => {
            let request = local_erasure_request(
                runs_dir,
                operation_id,
                ErasureTarget::ExactSession {
                    scope_id: scope()?,
                    run_id: ErasureTargetId::new(run_id.clone())?,
                },
            )?;
            print_erasure_receipt(
                runs_dir,
                &iteron_record::erasure::execute_erasure(runs_dir, request)?,
            )
        }
        RecordAction::Revoke {
            digest,
            operation_id,
        } => {
            let request = local_erasure_request(
                runs_dir,
                operation_id,
                ErasureTarget::ContentRevocation {
                    scope_id: scope()?,
                    content_digest: ErasureContentDigest::new(digest.clone())?,
                },
            )?;
            print_erasure_receipt(
                runs_dir,
                &iteron_record::erasure::execute_erasure(runs_dir, request)?,
            )
        }
        RecordAction::Prune {
            older_than_days,
            keep_last,
            operation_id,
        } => {
            if older_than_days.is_none() && keep_last.is_none() {
                anyhow::bail!("record prune needs --older-than-days and/or --keep-last");
            }
            let request = local_erasure_request(
                runs_dir,
                operation_id,
                ErasureTarget::RetentionPrune {
                    scope_id: scope()?,
                    max_age_secs: older_than_days.map(|days| days.saturating_mul(24 * 60 * 60)),
                    keep_last: *keep_last,
                },
            )?;
            print_erasure_receipt(
                runs_dir,
                &iteron_record::erasure::execute_erasure(runs_dir, request)?,
            )
        }
        RecordAction::Receipt { operation_id } => {
            let operation_id = iteron_protocol::ErasureOperationId::new(operation_id.clone())?;
            let receipt = iteron_record::erasure::read_erasure_receipt(runs_dir, &operation_id)?
                .ok_or_else(|| anyhow::anyhow!("erasure operation {operation_id} was not found"))?;
            print_erasure_receipt(runs_dir, &receipt)
        }
        RecordAction::Receipts { limit } => {
            let receipts = iteron_record::erasure::list_erasure_receipts(runs_dir, *limit)?;
            println!("{}", serde_json::to_string_pretty(&receipts)?);
            Ok(output::EXIT_SUCCESS)
        }
        RecordAction::Resume { operation_id } => {
            let operation_id = iteron_protocol::ErasureOperationId::new(operation_id.clone())?;
            let receipt = iteron_record::erasure::read_erasure_receipt(runs_dir, &operation_id)?
                .ok_or_else(|| anyhow::anyhow!("erasure operation {operation_id} was not found"))?;
            if receipt.state().is_terminal() {
                return print_erasure_receipt(runs_dir, &receipt);
            }
            print_erasure_receipt(
                runs_dir,
                &iteron_record::erasure::execute_erasure(runs_dir, receipt.request().clone())?,
            )
        }
    }
}

/// `iteron prune` — the only path that ever deletes a run journal. The policy must be stated: run
/// journals are append-only and are the sole durable evidence a run happened, so "prune" with no
/// rule is a question, not a command.
pub(crate) fn run_prune_command(
    runs_dir: &std::path::Path,
    older_than_days: Option<u64>,
    keep_last: Option<usize>,
    dry_run: bool,
) -> anyhow::Result<u8> {
    if older_than_days.is_none() && keep_last.is_none() {
        anyhow::bail!(
            "prune needs an explicit retention policy: --older-than-days <DAYS> and/or --keep-last <N>"
        );
    }
    let policy = iteron_record::session::PrunePolicy {
        max_age_secs: older_than_days.map(|days| days.saturating_mul(24 * 60 * 60)),
        keep_last,
        dry_run,
    };
    if !dry_run {
        let operation_id = format!("prune.{}.{}", std::process::id(), erasure_now_unix_ms());
        let keep_last = keep_last
            .map(u32::try_from)
            .transpose()
            .map_err(|_| anyhow::anyhow!("--keep-last exceeds the erasure receipt bound"))?;
        return run_record_command(
            runs_dir,
            &RecordAction::Prune {
                older_than_days,
                keep_last,
                operation_id,
            },
        );
    }
    let report = iteron_record::session::prune(runs_dir, &TenantId::default(), &policy)?;
    let verb = if dry_run { "would remove" } else { "removed" };
    for run in &report.removed {
        println!("{verb} {run}");
    }
    for run in &report.active {
        eprintln!("kept {run}: another process is writing it");
    }
    for run in &report.ancestors {
        eprintln!("kept {run}: a retained fork replays through its prefix");
    }
    println!(
        "{verb} {} session{}, {} retained in {}",
        report.removed.len(),
        if report.removed.len() == 1 { "" } else { "s" },
        report.retained,
        runs_dir.display()
    );
    Ok(output::EXIT_SUCCESS)
}

/// Human rendering of the offline timeline (#104).
///
/// Two rules the layout enforces rather than documents. Every unknown prints the word `unknown`,
/// never a dash or a zero, because a reader skimming a column of numbers will read a zero as a
/// measurement. And the residual gets its own line with an explanation attached, because a
/// breakdown that quietly summed to less than the wall clock would be read as a partition, which
/// it is not: pure tools overlap decode by design.
pub(crate) fn print_timeline(
    run: &iteron_protocol::RunId,
    report: &iteron_obs::timeline::Timeline,
) {
    fn ms(value: Option<u64>) -> String {
        value.map_or_else(|| "unknown".into(), |value| format!("{value}ms"))
    }

    println!("run {}", run.0);
    println!(
        "  lines={} timed={}{}",
        report.coverage.lines,
        report.coverage.timed_lines,
        if report.coverage.timed_lines < report.coverage.lines {
            "  (written before per-line timestamps; spans are unknown)"
        } else {
            ""
        }
    );
    println!("  segments={}", report.segments.len());
    for (index, segment) in report.segments.iter().enumerate() {
        println!(
            "    [{index}] seq {}..{}  events={}  span={}",
            segment.first_seq,
            segment.last_seq,
            segment.events,
            ms(segment.span_ms)
        );
    }
    if report.segments.len() > 1 {
        println!(
            "    the gap between segments is a resume: two monotonic origins, so it is unknown, not zero"
        );
    }

    if report.turns.count > 0 {
        println!(
            "  turns={}  ttft p50={} p90={} max={}  decode p50={} max={}  stream_items={}",
            report.turns.count,
            ms(report.turns.ttft.p50_ms),
            ms(report.turns.ttft.p90_ms),
            ms(report.turns.ttft.max_ms),
            ms(report.turns.decode.p50_ms),
            ms(report.turns.decode.max_ms),
            report.turns.stream_items,
        );
        if report.turns.ttft.unmeasured > 0 {
            println!(
                "    {} turn(s) carry no first-token measurement",
                report.turns.ttft.unmeasured
            );
        }
    }

    let economy = &report.token_economy;
    if economy.turns_with_usage > 0 {
        let equivalent_full_prompts = economy.max_turn_prompt_tokens.and_then(|maximum| {
            (maximum > 0).then(|| economy.prompt_tokens as f64 / maximum as f64)
        });
        println!(
            "  tokens: prompt={} (input={} cache_read={} cache_create={}) output={} thinking={}",
            economy.prompt_tokens,
            economy.input_tokens,
            economy.cache_read_tokens,
            economy.cache_creation_tokens,
            economy.output_tokens,
            economy.thinking_tokens,
        );
        println!(
            "    prompt first={} last={} max={} growth={} cache_hit={:.1}% replay_amplification={}",
            economy
                .first_turn_prompt_tokens
                .map_or_else(|| "unknown".into(), |value| value.to_string()),
            economy
                .last_turn_prompt_tokens
                .map_or_else(|| "unknown".into(), |value| value.to_string()),
            economy
                .max_turn_prompt_tokens
                .map_or_else(|| "unknown".into(), |value| value.to_string()),
            economy
                .prompt_growth_tokens
                .map_or_else(|| "unknown".into(), |value| value.to_string()),
            f64::from(economy.cache_hit_ratio_ppm) / 10_000.0,
            equivalent_full_prompts
                .map_or_else(|| "unknown".into(), |value| format!("{value:.2}x")),
        );
        println!(
            "    model_visible_tool_results={}B max_result={}B compactions={}",
            economy.model_visible_tool_result_bytes,
            economy.max_tool_result_bytes,
            economy.compactions,
        );
    }

    for (title, table) in [
        ("phases", &report.phases),
        ("effects", &report.effects),
        ("tools", &report.tools),
    ] {
        if table.is_empty() {
            continue;
        }
        println!("  {title}:");
        for (name, distribution) in table.iter() {
            println!(
                "    {name:<14} n={:<4} total={:<9} p50={:<9} p90={:<9} p99={:<9} max={}{}",
                distribution.count,
                format!("{}ms", distribution.total_ms),
                ms(distribution.p50_ms),
                ms(distribution.p90_ms),
                ms(distribution.p99_ms),
                ms(distribution.max_ms),
                if distribution.unmeasured > 0 {
                    format!("  ({} unmeasured)", distribution.unmeasured)
                } else {
                    String::new()
                }
            );
        }
    }

    println!(
        "  wall={}  attributed={}ms  residual={}",
        ms(report.coverage.wall_ms),
        report.coverage.attributed_ms,
        report
            .coverage
            .residual_ms
            .map_or_else(|| "unknown".into(), |value| format!("{value}ms")),
    );
    if report.coverage.residual_ms.is_some_and(|value| value < 0) {
        println!(
            "    negative residual = overlap: pure tools ran during the stream, which is the harness working"
        );
    }
    println!(
        "  phase_attributed={}ms  phase_residual={}",
        report.coverage.phase_attributed_ms,
        report
            .coverage
            .phase_residual_ms
            .map_or_else(|| "unknown".into(), |value| format!("{value}ms")),
    );
    if report
        .coverage
        .phase_residual_ms
        .is_some_and(|value| value > 0)
    {
        println!(
            "    positive phase residual = time outside a declared controller phase; inspect run-start/finalization gaps"
        );
    }
}
