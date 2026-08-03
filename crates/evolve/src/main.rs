use core_evolve::{
    BaseModelId, OfflineTranscriptConfig, TranscriptProducerKind, conformance, gate,
    run_offline_transcript_with_config, verify_offline_transcript,
};
use std::path::PathBuf;

struct Cli {
    root: PathBuf,
    config: OfflineTranscriptConfig,
}

fn main() {
    let program = std::env::args()
        .next()
        .unwrap_or_else(|| "evolve-transcript".to_owned());
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    // The Sept-1 evolution gate is a subcommand of this binary rather than a second one, because
    // the ownership registry requires a managed crate to declare exactly one binary. Without a
    // subcommand the argument grammar is untouched, so every existing invocation keeps working.
    if arguments.first().map(String::as_str) == Some("gate") {
        std::process::exit(run_gate(&program, &arguments[1..]));
    }

    let cli = match parse_cli(arguments) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            println!("{}", usage(&program));
            return;
        }
        Err(error) => {
            eprintln!("{error}\n{}", usage(&program));
            std::process::exit(2);
        }
    };

    match run_offline_transcript_with_config(&cli.root, &cli.config).and_then(|result| {
        let verified = verify_offline_transcript(&result.transcript_path)?;
        Ok((result, verified))
    }) {
        Ok((result, verified)) => {
            println!("transcript={}", result.transcript_path.display());
            println!(
                "promotion_journal={}",
                result.promotion_journal_path.display()
            );
            println!(
                "target_promotion_journal={}",
                result.target_promotion_journal_path.display()
            );
            println!(
                "trajectory_registry={}",
                result.trajectory_registry_path.display()
            );
            println!("verified_records={verified}");
            println!(
                "final_active_bundle_digest={}",
                result.final_active_bundle_digest
            );
        }
        Err(error) => {
            eprintln!("evolve-transcript failed: {error}");
            std::process::exit(1);
        }
    }
}

fn parse_cli(args: Vec<String>) -> Result<Option<Cli>, String> {
    let defaults = OfflineTranscriptConfig::default();
    let mut source = defaults.source_base_model().clone();
    let mut target = defaults.target_base_model().clone();
    let mut primary = defaults.primary_producer();
    let mut secondary = defaults.secondary_producer();
    let mut root = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => return Ok(None),
            "--source-model" | "--target-model" => {
                let flag = args[index].clone();
                let parts = args
                    .get(index + 1..index + 4)
                    .ok_or_else(|| format!("{flag} requires FAMILY ID DIGEST"))?;
                let model = BaseModelId {
                    model_family: parts[0].clone(),
                    model_id: parts[1].clone(),
                    model_digest: parts[2].clone(),
                };
                if flag == "--source-model" {
                    source = model;
                } else {
                    target = model;
                }
                index += 4;
            }
            "--producer-order" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--producer-order requires rule,prompt or prompt,rule".to_owned()
                })?;
                (primary, secondary) = parse_producer_order(value)?;
                index += 2;
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option `{value}`"));
            }
            value => {
                if root.replace(PathBuf::from(value)).is_some() {
                    return Err("exactly one output directory is required".into());
                }
                index += 1;
            }
        }
    }
    let root = root.ok_or_else(|| "an output directory is required".to_owned())?;
    let config = OfflineTranscriptConfig::new(source, target, primary, secondary)
        .map_err(|error| error.to_string())?;
    Ok(Some(Cli { root, config }))
}

fn parse_producer_order(
    value: &str,
) -> Result<(TranscriptProducerKind, TranscriptProducerKind), String> {
    match value {
        "rule,prompt" => Ok((
            TranscriptProducerKind::RuleSearch,
            TranscriptProducerKind::PromptPreference,
        )),
        "prompt,rule" => Ok((
            TranscriptProducerKind::PromptPreference,
            TranscriptProducerKind::RuleSearch,
        )),
        _ => Err("--producer-order must be `rule,prompt` or `prompt,rule`".into()),
    }
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} [--source-model FAMILY ID DIGEST] \
         [--target-model FAMILY ID DIGEST] [--producer-order rule,prompt|prompt,rule] \
         <output-directory>\n\
         \x20      {program} gate <rows|prove> [--repo PATH] [--scratch PATH]"
    )
}

/// `gate rows` emits the evolution conformance rows and refuses any row without executable
/// evidence. `gate prove` runs the deterministic `evolution-proven` artifact. Both return a
/// process exit code, because this is what CI reads.
fn run_gate(program: &str, arguments: &[String]) -> i32 {
    let request = match parse_gate(arguments) {
        Ok(Some(request)) => request,
        Ok(None) => {
            println!("{}", usage(program));
            return 0;
        }
        Err(error) => {
            eprintln!("{error}\n{}", usage(program));
            return 2;
        }
    };
    match request.mode {
        GateMode::Rows => match conformance::emit(&request.repo) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("evolution conformance rows are not admissible: {error}");
                1
            }
        },
        GateMode::Prove => {
            let scratch = request.scratch.unwrap_or_else(|| {
                std::env::temp_dir().join(format!("core-evolve-gate-{}", std::process::id()))
            });
            if let Err(error) = std::fs::create_dir_all(&scratch) {
                eprintln!(
                    "cannot create scratch directory {}: {error}",
                    scratch.display()
                );
                return 1;
            }
            match gate::run(&request.repo, &scratch) {
                Ok(report) => {
                    print!("{}", report.render());
                    if report.passed() {
                        0
                    } else {
                        eprintln!("evolution gate is red: at least one module is unproven");
                        1
                    }
                }
                Err(error) => {
                    eprintln!("evolution gate failed: {error}");
                    1
                }
            }
        }
    }
}

enum GateMode {
    Rows,
    Prove,
}

struct GateRequest {
    mode: GateMode,
    repo: PathBuf,
    scratch: Option<PathBuf>,
}

fn parse_gate(arguments: &[String]) -> Result<Option<GateRequest>, String> {
    let mut mode = None;
    let mut repo = PathBuf::from(".");
    let mut scratch = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "-h" | "--help" => return Ok(None),
            "rows" => {
                mode = Some(GateMode::Rows);
                index += 1;
            }
            "prove" => {
                mode = Some(GateMode::Prove);
                index += 1;
            }
            "--repo" => {
                repo = PathBuf::from(
                    arguments
                        .get(index + 1)
                        .ok_or_else(|| "--repo requires a path".to_owned())?,
                );
                index += 2;
            }
            "--scratch" => {
                scratch = Some(PathBuf::from(
                    arguments
                        .get(index + 1)
                        .ok_or_else(|| "--scratch requires a path".to_owned())?,
                ));
                index += 2;
            }
            other => return Err(format!("unexpected argument `{other}`")),
        }
    }
    let mode = mode.ok_or_else(|| "expected `gate rows` or `gate prove`".to_owned())?;
    Ok(Some(GateRequest {
        mode,
        repo,
        scratch,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_exposes_model_and_producer_parameters() {
        let args = vec![
            "--source-model".into(),
            "demo/frozen".into(),
            "source".into(),
            "a".repeat(64),
            "--target-model".into(),
            "demo/frozen".into(),
            "target".into(),
            "b".repeat(64),
            "--producer-order".into(),
            "prompt,rule".into(),
            "out".into(),
        ];
        let cli = parse_cli(args).unwrap().unwrap();
        assert_eq!(cli.config.source_base_model().model_id, "source");
        assert_eq!(cli.config.target_base_model().model_id, "target");
        assert_eq!(
            cli.config.primary_producer(),
            TranscriptProducerKind::PromptPreference
        );
    }

    /// The gate subcommand must not disturb the transcript grammar: `gate` is only a subcommand
    /// when it is the first argument, and a bare output directory named `gate` was never valid
    /// before this change either.
    #[test]
    fn the_gate_subcommand_parses_its_own_grammar_and_leaves_the_transcript_grammar_alone() {
        let rows = parse_gate(&["rows".to_owned(), "--repo".to_owned(), "..".to_owned()])
            .unwrap()
            .unwrap();
        assert!(matches!(rows.mode, GateMode::Rows));
        assert_eq!(rows.repo, PathBuf::from(".."));
        assert!(rows.scratch.is_none());

        let prove = parse_gate(&[
            "prove".to_owned(),
            "--scratch".to_owned(),
            "/tmp/x".to_owned(),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(prove.mode, GateMode::Prove));
        assert_eq!(prove.scratch, Some(PathBuf::from("/tmp/x")));

        assert!(parse_gate(&[]).is_err(), "a bare `gate` names no mode");
        assert!(parse_gate(&["rows".to_owned(), "--repo".to_owned()]).is_err());

        let transcript = parse_cli(vec!["out".to_owned()]).unwrap().unwrap();
        assert_eq!(transcript.root, PathBuf::from("out"));
    }
}
