use core_evolve::{
    BaseModelId, OfflineTranscriptConfig, TranscriptProducerKind,
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
    let cli = match parse_cli(std::env::args().skip(1).collect()) {
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
         <output-directory>"
    )
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
}
