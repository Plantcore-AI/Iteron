//! `iteron-research/1` CLI. Persistent runs are dry-run unless the operator selects execute mode.

use iteron_eval::{
    AdapterOperation, MAX_PROTOCOL_REQUEST_BYTES, MAX_PROTOCOL_RESPONSE_BYTES,
    PerformanceThresholds, ResearchExecutionMode, ResearchSession, compare_performance_manifests,
    parse_research_request,
};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

const MAX_EVALUATION_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;

fn main() -> std::process::ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|operation| operation == "campaign")
    {
        return iteron_eval::qualification_campaign::run_campaign_cli(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|operation| operation == "qualification-provider")
    {
        return iteron_eval::qualification_campaign::run_provider_cli(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|operation| operation == "hermetic-fixture")
    {
        return iteron_eval::run_hermetic_fixture_cli(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|operation| operation == "synthetic-cycle")
    {
        return iteron_eval::engineering_cycle::run_synthetic_cycle_cli(&args[1..]);
    }
    let result = match args.as_slice() {
        [operation] if operation == "surface" => one_shot(AdapterOperation::Surface),
        [operation] if operation == "candidate-validate" => {
            one_shot(AdapterOperation::CandidateValidate)
        }
        [operation, bundle, trusted_public_key] if operation == "scoreboard" => {
            scoreboard(Path::new(bundle), trusted_public_key)
        }
        [
            operation,
            baseline_path,
            baseline_arm,
            treatment_path,
            treatment_arm,
            minimum_pairs,
            resolution_margin,
            latency_reduction,
            token_reduction,
        ] if operation == "compare-performance" => compare_performance_args(
            Path::new(baseline_path),
            baseline_arm,
            Path::new(treatment_path),
            treatment_arm,
            minimum_pairs,
            resolution_margin,
            latency_reduction,
            token_reduction,
        ),
        [operation, flag, binary_flag, binary]
            if operation == "serve"
                && flag == "--execute"
                && binary_flag == "--iteron-cli" =>
        {
            serve(ResearchExecutionMode::Execute, Some(Path::new(binary)))
        }
        [operation, flag, binary_flag, binary]
            if operation == "serve"
                && flag == "--execute"
                && binary_flag == "--native-adapter" =>
        {
            serve_native(Path::new(binary))
        }
        [operation] if operation == "serve" => serve(ResearchExecutionMode::DryRun, None),
        _ => Err(
            "usage: iteron-harness <surface|candidate-validate|scoreboard BUNDLE_DIR TRUSTED_PUBLIC_KEY|compare-performance BASELINE_JSON BASELINE_ARM TREATMENT_JSON TREATMENT_ARM MIN_PAIRS RESOLUTION_MARGIN LATENCY_REDUCTION TOKEN_REDUCTION|hermetic-fixture --output CREATE_NEW_FILE|synthetic-cycle --authorization FILE --output CREATE_NEW_DIRECTORY|serve|serve --execute --iteron-cli PATH|serve --execute --native-adapter PATH|campaign [--qualification-id ID]>; serve defaults to dry-run"
                .into(),
        ),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("iteron-harness: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_performance_args(
    baseline_path: &Path,
    baseline_arm: &str,
    treatment_path: &Path,
    treatment_arm: &str,
    minimum_pairs: &str,
    resolution_margin: &str,
    latency_reduction: &str,
    token_reduction: &str,
) -> Result<(), String> {
    let thresholds = PerformanceThresholds {
        minimum_pairs: minimum_pairs
            .parse()
            .map_err(|_| "minimum pairs must be an unsigned integer".to_owned())?,
        resolution_noninferiority_margin: resolution_margin
            .parse()
            .map_err(|_| "resolution margin must be numeric".to_owned())?,
        minimum_latency_reduction_ratio: latency_reduction
            .parse()
            .map_err(|_| "latency reduction must be numeric".to_owned())?,
        minimum_token_reduction_ratio: token_reduction
            .parse()
            .map_err(|_| "token reduction must be numeric".to_owned())?,
    };
    let baseline = read_manifest(baseline_path)?;
    let treatment = read_manifest(treatment_path)?;
    let report = compare_performance_manifests(
        &baseline,
        baseline_arm,
        &treatment,
        treatment_arm,
        thresholds,
    )
    .map_err(|error| error.to_string())?;
    let mut bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_PROTOCOL_RESPONSE_BYTES {
        return Err("performance report exceeds the protocol response byte bound".into());
    }
    io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(|error| error.to_string())
}

fn read_manifest(path: &Path) -> Result<iteron_eval::EvaluationManifest, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_EVALUATION_MANIFEST_BYTES
    {
        return Err("evaluation manifest must be a bounded regular non-symlink file".into());
    }
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_EVALUATION_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_EVALUATION_MANIFEST_BYTES {
        return Err("evaluation manifest grew beyond its byte bound".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn scoreboard(bundle: &Path, trusted_public_key: &str) -> Result<(), String> {
    let board = iteron_eval::generate_evidence_scoreboard(bundle, trusted_public_key)
        .map_err(|error| error.to_string())?;
    let mut bytes = serde_json::to_vec_pretty(&board).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > MAX_PROTOCOL_RESPONSE_BYTES {
        return Err("scoreboard exceeds the protocol response byte bound".into());
    }
    io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(|error| error.to_string())
}

fn serve_native(path: &Path) -> Result<(), String> {
    serve_session(
        ResearchSession::with_pinned_native_adapter(path).map_err(|error| error.to_string())?,
    )
}

fn one_shot(expected: AdapterOperation) -> Result<(), String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_PROTOCOL_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_PROTOCOL_REQUEST_BYTES {
        return Err("request exceeds the protocol byte bound".into());
    }
    let request = parse_research_request(&bytes).map_err(|error| error.to_string())?;
    if request.operation() != expected {
        return Err("one-shot subcommand does not match request operation".into());
    }
    let response = ResearchSession::new().handle(request);
    write_response(&response)
}

fn serve(execution_mode: ResearchExecutionMode, iteron_cli: Option<&Path>) -> Result<(), String> {
    let session = match (execution_mode, iteron_cli) {
        (ResearchExecutionMode::DryRun, None) => ResearchSession::new(),
        (ResearchExecutionMode::Execute, Some(path)) => {
            ResearchSession::with_pinned_iteron_cli(path).map_err(|error| error.to_string())?
        }
        _ => return Err("execute mode requires one operator-pinned Iteron CLI path".into()),
    };
    serve_session(session)
}

fn serve_session(mut session: ResearchSession) -> Result<(), String> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let Some(line) = read_bounded_line(&mut input)? else {
            return Ok(());
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let request = match parse_research_request(&line) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("iteron-harness: refused NDJSON request: {error}");
                continue;
            }
        };
        let response = session.handle(request);
        write_response(&response)?;
    }
}

fn write_response(response: &iteron_eval::ResearchResponseEnvelope) -> Result<(), String> {
    let bytes = serde_json::to_vec(response).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_PROTOCOL_RESPONSE_BYTES {
        return Err("response exceeds the protocol byte bound".into());
    }
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    output.write_all(b"\n").map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())
}

fn read_bounded_line<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    let mut over_limit = false;
    let mut saw_bytes = false;
    loop {
        let available = reader.fill_buf().map_err(|error| error.to_string())?;
        if available.is_empty() {
            if !saw_bytes {
                return Ok(None);
            }
            break;
        }
        saw_bytes = true;
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if !over_limit {
            let remaining = MAX_PROTOCOL_REQUEST_BYTES.saturating_add(1) - line.len();
            line.extend_from_slice(&available[..consumed.min(remaining)]);
            over_limit = line.len() > MAX_PROTOCOL_REQUEST_BYTES;
        }
        let ended = available[..consumed].ends_with(b"\n");
        reader.consume(consumed);
        if ended {
            break;
        }
    }
    if over_limit {
        return Err("NDJSON line exceeds the protocol byte bound".into());
    }
    Ok(Some(line))
}
