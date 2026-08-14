//! `iteron-research/1` CLI. Persistent runs are dry-run unless the operator selects execute mode.

use iteron_eval::{
    AdapterOperation, MAX_PROTOCOL_REQUEST_BYTES, MAX_PROTOCOL_RESPONSE_BYTES,
    ResearchExecutionMode, ResearchSession, parse_research_request,
};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

fn main() -> std::process::ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [operation] if operation == "surface" => one_shot(AdapterOperation::Surface),
        [operation] if operation == "candidate-validate" => {
            one_shot(AdapterOperation::CandidateValidate)
        }
        [operation, flag, binary_flag, binary]
            if operation == "serve"
                && flag == "--execute"
                && binary_flag == "--iteron-cli" =>
        {
            serve(ResearchExecutionMode::Execute, Some(Path::new(binary)))
        }
        [operation] if operation == "serve" => serve(ResearchExecutionMode::DryRun, None),
        _ => Err(
            "usage: iteron-harness <surface|candidate-validate|serve|serve --execute --iteron-cli PATH>; serve defaults to dry-run"
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
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut session = match (execution_mode, iteron_cli) {
        (ResearchExecutionMode::DryRun, None) => ResearchSession::new(),
        (ResearchExecutionMode::Execute, Some(path)) => {
            ResearchSession::with_pinned_iteron_cli(path).map_err(|error| error.to_string())?
        }
        _ => return Err("execute mode requires one operator-pinned Iteron CLI path".into()),
    };
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
