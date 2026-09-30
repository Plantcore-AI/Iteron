//! Pure, bounded presentation adapter for tool output and approval evidence.

use super::frontend_events::UiEvent;
use iteron_protocol::{ToolResult, ToolUse};

/// Keep the tail of a long string (test failures print last) within a bound. UTF-8-safe
/// (delegates to protocol::text::tail; a raw byte slice would panic on a multibyte cut).
pub(super) fn truncate_tail(s: &str, max: usize) -> String {
    iteron_protocol::text::tail(s, max)
}

pub(crate) fn bounded_child_report(
    policy: crate::runtime_tunables::execution_policy::ExecutionRuntimePolicy,
    report: &str,
) -> String {
    strict_utf8_head(report.trim(), policy.report_budget_bytes)
}

/// Build the `ToolEnd` UI event from a completed `ToolResult`: correlate by the tool_use id and
/// carry the scrubbed+bounded output so the TUI can render a collapsible result card (ADR-015).
pub(super) fn tool_end_ui(tu: &ToolUse, r: &ToolResult) -> UiEvent {
    UiEvent::ToolEnd {
        id: r.tool_use_id.clone(),
        ok: !r.is_error, // UNCHANGED — is_error drives failed-action dedup + verify gate (C9)
        exit_code: bash_exit_code(tu, r),
        output: tool_card_output(tu, r),
        diff: edit_diff_from(tu, r),
    }
}

fn tool_card_output(tu: &ToolUse, r: &ToolResult) -> String {
    if tu.name != "bash" {
        return ui_tool_output(&r.content);
    }

    let output = parse_bash_operator_output(&r.content)
        .map(render_bash_operator_output)
        .unwrap_or_else(|| strip_bash_protocol_fallback(&strip_exit_line(tu, &r.content)));
    ui_tool_output(&output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BashOperatorState {
    Done,
    Running,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
struct BashOperatorOutput {
    state: BashOperatorState,
    job_id: Option<String>,
    failure_kind: Option<String>,
    stdout: String,
    stderr: String,
}

fn parse_bash_operator_output(content: &str) -> Option<BashOperatorOutput> {
    let (header, body) = content.split_once('\n').unwrap_or((content, ""));
    let (state, job_id, failure_kind) = if header == "[done]" {
        (BashOperatorState::Done, None, None)
    } else if let Some(fields) = header
        .strip_prefix("[running ")
        .and_then(|header| header.strip_suffix(']'))
    {
        let job_id = fields
            .split(';')
            .find_map(|field| field.trim().strip_prefix("session_id="))
            .filter(|job_id| !job_id.is_empty())
            .map(str::to_owned);
        (BashOperatorState::Running, job_id, None)
    } else {
        let state_json = header
            .strip_prefix("[failed state=")
            .and_then(|header| header.strip_suffix(']'))?;
        let failure_kind = serde_json::from_str::<serde_json::Value>(state_json)
            .ok()
            .and_then(|state| state.get("kind")?.as_str().map(str::to_owned));
        (BashOperatorState::Failed, None, failure_kind)
    };

    let mut parsed = BashOperatorOutput {
        state,
        job_id,
        failure_kind,
        stdout: String::new(),
        stderr: String::new(),
    };
    if body.starts_with("[stream ") {
        parse_length_prefixed_bash_streams(body, &mut parsed)?;
    } else {
        parse_complete_bash_streams(body, &mut parsed)?;
    }
    Some(parsed)
}

fn parse_length_prefixed_bash_streams(
    mut remaining: &str,
    parsed: &mut BashOperatorOutput,
) -> Option<()> {
    while remaining.starts_with("[stream ") {
        let header_end = remaining.find('\n')?;
        let header = &remaining[..header_end];
        let frame = header.strip_prefix("[stream ")?.strip_suffix(']')?;
        let (stream, metadata) = frame.split_once(';')?;
        let content_bytes = metadata
            .split(';')
            .find_map(|field| field.trim().strip_prefix("contentBytes="))?
            .parse::<usize>()
            .ok()?;
        let content_start = header_end.checked_add(1)?;
        let content_end = content_start.checked_add(content_bytes)?;
        let payload = remaining.get(content_start..content_end)?;
        let suffix = remaining.get(content_end..)?;
        let closing = format!("\n[/stream {stream}]\n");
        remaining = suffix.strip_prefix(&closing)?;
        match stream {
            "stdout" => parsed.stdout.push_str(payload),
            "stderr" => parsed.stderr.push_str(payload),
            _ => return None,
        }
    }

    if remaining.is_empty() || remaining.starts_with("[resumeHint:") {
        Some(())
    } else {
        None
    }
}

fn parse_complete_bash_streams(body: &str, parsed: &mut BashOperatorOutput) -> Option<()> {
    if body.is_empty() {
        return Some(());
    }
    if let Some(stdout) = body.strip_prefix("[stdout]\n") {
        if let Some(marker) = stdout.rfind("\n[stderr]\n")
            && !stdout[marker + "\n[stderr]\n".len()..].is_empty()
        {
            parsed.stdout.push_str(&stdout[..marker]);
            parsed
                .stderr
                .push_str(&stdout[marker + "\n[stderr]\n".len()..]);
        } else {
            parsed.stdout.push_str(stdout);
        }
        return Some(());
    }
    if let Some(stderr) = body.strip_prefix("[stderr]\n") {
        parsed.stderr.push_str(stderr);
        return Some(());
    }
    None
}

fn render_bash_operator_output(parsed: BashOperatorOutput) -> String {
    let mut output = String::new();
    append_operator_stream(&mut output, &parsed.stdout);
    append_operator_stream(&mut output, &parsed.stderr);
    match parsed.state {
        BashOperatorState::Done => {}
        BashOperatorState::Running => {
            let status = parsed.job_id.map_or_else(
                || "process continues in background".to_owned(),
                |job_id| format!("process continues in background · {job_id}"),
            );
            append_operator_status(&mut output, &status);
        }
        BashOperatorState::Failed if output.is_empty() => {
            let status = parsed.failure_kind.map_or_else(
                || "process failed".to_owned(),
                |kind| format!("process failed · {}", kind.replace('_', " ")),
            );
            output.push_str(&status);
        }
        BashOperatorState::Failed => {}
    }
    output
}

fn append_operator_stream(output: &mut String, stream: &str) {
    let stream = stream.trim_end_matches('\n');
    if stream.is_empty() {
        return;
    }
    if !output.is_empty() {
        output.push('\n');
    }
    output.push_str(stream);
}

fn append_operator_status(output: &mut String, status: &str) {
    if !output.is_empty() {
        output.push_str("\n\n");
    }
    output.push_str(status);
}

fn strip_bash_protocol_fallback(content: &str) -> String {
    content
        .lines()
        .filter(|line| !is_bash_protocol_line(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_bash_protocol_line(line: &str) -> bool {
    line == "[done]"
        || line == "[stdout]"
        || line == "[stderr]"
        || line.starts_with("[running session_id=")
        || line.starts_with("[failed state=")
        || line.starts_with("[stream stdout;")
        || line.starts_with("[stream stderr;")
        || line == "[/stream stdout]"
        || line == "[/stream stderr]"
        || line.starts_with("[resumeHint:")
}

/// Build a one-hunk `FileDiff` from an edit/write tool's args (path/old/new) — KERNEL-side, so the
/// tool's result string stays terse and the durable record is not polluted (ADR-015 C8). The old/new
/// text is secret-scrubbed BEFORE it becomes a diff (C10; `from_replacement` also caps at 200 lines).
pub(super) fn edit_diff_from(tu: &ToolUse, r: &ToolResult) -> Option<iteron_protocol::FileDiff> {
    if r.is_error {
        return None; // a refused/failed edit landed no change
    }
    let get = |k: &str| tu.input.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let path = get("path");
    if path.is_empty() {
        return None;
    }
    let (old, new) = match tu.name.as_str() {
        "edit" | "str_replace" => (get("old"), get("new")),
        "write" | "create" | "write_file" => (
            "",
            tu.input
                .get("content")
                .or_else(|| tu.input.get("file_text"))
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        ),
        _ => return None,
    };
    let old = iteron_record::redact::scrub(old);
    let new = iteron_record::redact::scrub(new);
    Some(iteron_protocol::FileDiff::from_replacement(
        path, &old, &new,
    ))
}

/// The bash tool embeds `[exit N]` as the FIRST line of its (non-error) result (shell.rs) without
/// setting is_error. Surface that code as `ToolEnd.exit_code` so the card colors ✗/red on a non-zero
/// exit WITHOUT flipping is_error (C9). Parsed from RAW content (the marker has no secrets).
pub(super) fn bash_exit_code(tu: &ToolUse, r: &ToolResult) -> Option<i32> {
    if tu.name != "bash" {
        return None;
    }
    let first = r.content.lines().next()?;
    if let Some(exit) = first
        .strip_prefix("[exit ")
        .and_then(|line| line.strip_suffix(']'))
    {
        return exit.trim().parse::<i32>().ok();
    }
    let state_json = first.strip_prefix("[failed state=")?.strip_suffix(']')?;
    let state = serde_json::from_str::<serde_json::Value>(state_json).ok()?;
    i32::try_from(state.get("exit_code")?.as_i64()?).ok()
}

/// For bash, drop a leading `[exit N]` line so it is not duplicated with the card's exit-code label.
pub(super) fn strip_exit_line(tu: &ToolUse, content: &str) -> String {
    if tu.name == "bash"
        && let Some(rest) = content.strip_prefix("[exit ")
    {
        if let Some(nl) = rest.find('\n') {
            return rest[nl + 1..].to_string();
        }
        return String::new(); // only the exit line, nothing else
    }
    content.to_string()
}

/// Prepare tool output for the UI seam (ADR-015 R1/R5): secret-scrub it (the record is already
/// masked, but the live UI / `/export` / scrollback are new exfiltration surfaces), then BOUND it at
/// ingest — a collapsed card is a few rows but must not retain multi-MB raw output (bounded
/// invariant #1). Keep the first 60 + last 20 lines, then a hard char cap.
pub(super) fn ui_tool_output(content: &str) -> String {
    let scrubbed = iteron_record::redact::scrub(content);
    let bounded = bound_middle(&scrubbed, 60, 20);
    iteron_protocol::text::head(&bounded, 12_000)
}

/// Strict UTF-8-safe prefix bound including its truncation marker.
pub(super) fn strict_utf8_head(content: &str, max_bytes: usize) -> String {
    if content.len() <= max_bytes {
        return content.to_string();
    }
    if max_bytes < '…'.len_utf8() {
        return String::new();
    }
    let mut end = max_bytes - '…'.len_utf8();
    while end > 0 && !content.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &content[..end])
}

/// Keep the first `head` and last `tail` lines of a multi-line string, eliding the middle with a
/// marker. Short strings pass through unchanged.
pub(super) fn bound_middle(s: &str, head: usize, tail: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() <= head + tail + 1 {
        return s.to_string();
    }
    let elided = lines.len() - head - tail;
    let mut out: Vec<String> = lines[..head].iter().map(|l| (*l).to_string()).collect();
    out.push(format!("… {elided} lines elided …"));
    out.extend(lines[lines.len() - tail..].iter().map(|l| (*l).to_string()));
    out.join("\n")
}

/// Recursively secret-scrub the string leaves of a tool's args `Value` before it crosses the UI seam
/// (ADR-015 R1): a bash `args.command` or an env var could carry a secret.
pub(super) fn scrub_value(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::String(s) => Value::String(iteron_record::redact::scrub(s)),
        Value::Array(a) => Value::Array(a.iter().map(scrub_value).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, v)| (k.clone(), scrub_value(v))).collect())
        }
        other => other.clone(),
    }
}

const MAX_UI_APPROVAL_ARGS_BYTES: usize = 16 * 1024;

/// Keep approval evidence bounded without reducing a large request to an unhelpful bare tool name.
/// Normal arguments cross unchanged after secret scrubbing. Oversize objects retain only the
/// operation-identifying fields and an explicit truncation marker; the canonical ToolCall event
/// remains the durable source of truth.
pub(super) fn ui_approval_arguments(value: &serde_json::Value) -> serde_json::Value {
    let scrubbed = scrub_value(value);
    if serde_json::to_vec(&scrubbed).is_ok_and(|encoded| {
        encoded.len()
            <= iteron_tunables::param_integer(
                "cli.runtime.max_ui_approval_args_bytes",
                MAX_UI_APPROVAL_ARGS_BYTES,
            )
    }) {
        return scrubbed;
    }

    let mut retained = serde_json::Map::new();
    if let serde_json::Value::Object(fields) = &scrubbed {
        for key in [
            "command",
            "cmd",
            "path",
            "file",
            "file_path",
            "filename",
            "pattern",
            "query",
            "url",
            "host",
        ] {
            let Some(value) = fields.get(key) else {
                continue;
            };
            let bounded = match value {
                serde_json::Value::String(text) => {
                    serde_json::Value::String(strict_utf8_head(text, 8 * 1024))
                }
                other
                    if serde_json::to_vec(other).is_ok_and(|encoded| encoded.len() <= 2 * 1024) =>
                {
                    other.clone()
                }
                _ => serde_json::Value::String("[oversize value omitted]".into()),
            };
            retained.insert(key.to_string(), bounded);
        }
    }
    retained.insert("_truncated_for_ui".into(), serde_json::Value::Bool(true));
    serde_json::Value::Object(retained)
}

/// Preserve the internally-generated structural digests that bind a verification rollback
/// approval while continuing to scrub every operator-controlled string (notably paths).  The
/// generic scanner intentionally masks long hex strings because arbitrary tool arguments may
/// contain credentials; these four fields are different: they are computed by the checkpoint and
/// verification-policy owners, and the operator must see the exact identities being approved.
/// A model cannot reach this projection through a registered tool -- `verification_rollback` is
/// an internal pseudo-tool used only by the verification runtime.
pub(super) fn ui_verification_rollback_arguments(
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    fn exact_hex(value: &serde_json::Value, lengths: &[usize]) -> Option<String> {
        let value = value.as_str()?;
        (lengths.contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| value.to_owned())
    }

    let source = value.as_object()?;
    let mut projected = ui_approval_arguments(value).as_object()?.clone();
    for (field, lengths) in [
        ("checkpoint_tree_ref", &[40_usize, 64_usize][..]),
        ("live_workspace_tree_ref", &[40_usize, 64_usize][..]),
        ("policy_digest_sha256", &[64_usize][..]),
        ("scope_digest_sha256", &[64_usize][..]),
    ] {
        projected.insert(
            field.to_owned(),
            serde_json::Value::String(exact_hex(source.get(field)?, lengths)?),
        );
    }
    Some(serde_json::Value::Object(projected))
}

#[cfg(test)]
#[path = "tool_presentation_tests.rs"]
mod tests;
