//! Structured composer context: typed source provenance, exact-byte audit, preview and deletion.

use super::*;
use crate::file_input::ContextKind;

const PREVIEW_BYTES: usize = 4 * 1024;
const PREVIEW_LINES: usize = 24;

pub(super) async fn handle(app: &mut App, session: &Session, arg: &str) {
    let input = arg.trim();
    if input.is_empty() || input == "stats" {
        show_stats(app, session);
        return;
    }
    if input == "list" {
        show_list(app);
        return;
    }
    if input == "help" {
        show_help(app);
        return;
    }
    if let Some(raw) = input.strip_prefix("preview ") {
        let Some(index) = parse_index(raw) else {
            usage_error(app);
            return;
        };
        preview(app, index);
        return;
    }
    if let Some(raw) = input.strip_prefix("delete ") {
        let Some(index) = parse_index(raw) else {
            usage_error(app);
            return;
        };
        if app.editor.remove_context(index) {
            app.note(
                block::NoticeLevel::Ok,
                format!("removed context chip #{index}"),
            );
        } else {
            app.note(
                block::NoticeLevel::Err,
                format!("context chip #{index} does not exist"),
            );
        }
        return;
    }
    if let Some(rest) = input.strip_prefix("add ") {
        add(app, session, rest.trim()).await;
        return;
    }
    usage_error(app);
}

async fn add(app: &mut App, session: &Session, input: &str) {
    if let Some(raw_path) = input.strip_prefix("file ") {
        add_path(app, session, ContextKind::File, raw_path);
        return;
    }
    if let Some(raw_path) = input.strip_prefix("ide ") {
        add_path(app, session, ContextKind::Ide, raw_path);
        return;
    }
    if let Some(raw_path) = input.strip_prefix("lsp ") {
        add_path(app, session, ContextKind::Lsp, raw_path);
        return;
    }
    if input == "diff" || input.starts_with("diff ") {
        let scope = input.strip_prefix("diff").unwrap_or_default().trim();
        if !matches!(scope, "" | "all" | "staged" | "unstaged") {
            usage_error(app);
            return;
        }
        match diff_document(session.workspace(), scope).await {
            Ok((label, document)) => {
                let attached = app
                    .editor
                    .attach_context(ContextKind::Diff, &label, document)
                    .map(|chip| {
                        (
                            chip.display_name().to_owned(),
                            chip.text_bytes(),
                            short_digest(chip.digest()).to_owned(),
                        )
                    });
                match attached {
                    Ok((name, bytes, digest)) => app.note(
                        block::NoticeLevel::Ok,
                        format!(
                            "attached {} context · {} bytes · sha256:{}",
                            name, bytes, digest
                        ),
                    ),
                    Err(error) => app.note(
                        block::NoticeLevel::Err,
                        format!("diff context refused: {error}"),
                    ),
                }
            }
            Err(error) => app.note(block::NoticeLevel::Err, error),
        }
        return;
    }
    usage_error(app);
}

fn add_path(app: &mut App, session: &Session, kind: ContextKind, raw_path: &str) {
    let raw_path = unquote(raw_path.trim());
    if raw_path.is_empty() {
        usage_error(app);
        return;
    }
    let result = if kind == ContextKind::File {
        app.editor
            .attach_file_path(session.workspace(), Path::new(raw_path))
    } else {
        app.editor
            .attach_context_path(kind, session.workspace(), Path::new(raw_path))
    }
    .map(|chip| {
        (
            chip.display_name().to_owned(),
            chip.text_bytes(),
            short_digest(chip.digest()).to_owned(),
        )
    });
    match result {
        Ok((name, bytes, digest)) => app.note(
            block::NoticeLevel::Ok,
            format!(
                "attached {} {} · {} bytes · sha256:{}",
                kind.label(),
                name,
                bytes,
                digest
            ),
        ),
        Err(error) => app.note(
            block::NoticeLevel::Err,
            format!("{} context refused: {error}", kind.label()),
        ),
    }
}

async fn diff_document(workspace: &Path, scope: &str) -> Result<(String, String), String> {
    let review = crate::workspace_review::observe(workspace).await?;
    // Verify every non-empty document before it is allowed to become model context. This prevents
    // a partial/torn subprocess response from being presented as a complete review snapshot.
    let _ = review.verified_diffs()?;
    let mut document = String::new();
    match scope {
        "staged" => document.push_str(&review.staged_diff),
        "unstaged" => document.push_str(&review.unstaged_diff),
        "" | "all" => {
            if !review.staged_diff.trim().is_empty() {
                document.push_str("# staged\n");
                document.push_str(&review.staged_diff);
            }
            if !review.unstaged_diff.trim().is_empty() {
                if !document.is_empty() {
                    document.push('\n');
                }
                document.push_str("# unstaged\n");
                document.push_str(&review.unstaged_diff);
            }
        }
        _ => unreachable!("scope checked by the command parser"),
    }
    if document.trim().is_empty() || document.trim() == "(no uncommitted changes)" {
        return Err(format!(
            "no {}diff is available to attach",
            if matches!(scope, "staged" | "unstaged") {
                format!("{scope} ")
            } else {
                String::new()
            }
        ));
    }
    let scope_label = if scope.is_empty() { "all" } else { scope };
    Ok((format!("git diff ({scope_label})"), document))
}

fn show_list(app: &mut App) {
    let files = app.editor.files().as_slice();
    let mut rows = Vec::new();
    for (index, chip) in files.iter().enumerate() {
        rows.push(item(
            chip.kind().glyph(),
            &format!(
                "#{} [{}] {}",
                index + 1,
                chip.kind().label(),
                chip.display_name()
            ),
            &format!(
                "{} · sha256:{} · {}",
                format_attachment_size(chip.text_bytes()),
                short_digest(chip.digest()),
                chip.relative_path()
            ),
        ));
    }
    if rows.is_empty() {
        rows.push(block::PanelRow::Note(
            "no text context chips on this draft".into(),
        ));
    } else {
        rows.push(block::PanelRow::Note(
            "submission order is top-to-bottom; `/context preview N` or `/context delete N`".into(),
        ));
    }
    app.panel("◇", "draft context", rows);
}

fn preview(app: &mut App, one_based: usize) {
    let Some(chip) = one_based
        .checked_sub(1)
        .and_then(|index| app.editor.files().as_slice().get(index))
    else {
        app.note(
            block::NoticeLevel::Err,
            format!("context chip #{one_based} does not exist"),
        );
        return;
    };
    let mut rows = vec![
        kv("kind", chip.kind().label()),
        kv("source", chip.relative_path()),
        kv("submitted bytes", &chip.text_bytes().to_string()),
        kv("sha256", chip.digest()),
    ];
    let mut consumed = 0_usize;
    for (lines, line) in chip.text().lines().enumerate() {
        if lines == PREVIEW_LINES || consumed.saturating_add(line.len()) > PREVIEW_BYTES {
            break;
        }
        rows.push(block::PanelRow::Note(line.into()));
        consumed = consumed.saturating_add(line.len() + 1);
    }
    if consumed < chip.text_bytes() {
        rows.push(block::PanelRow::Note(format!(
            "preview shows {consumed}/{} bytes; digest covers the complete submitted value",
            chip.text_bytes()
        )));
    }
    app.panel(
        chip.kind().glyph(),
        &format!("context #{} — {}", one_based, chip.display_name()),
        rows,
    );
}

fn show_help(app: &mut App) {
    app.panel(
        "◇",
        "context chips",
        vec![
            item(
                "/",
                "context list",
                "ordered draft context with exact byte counts and digests",
            ),
            item(
                "/",
                "context add file PATH",
                "attach a complete text file snapshot",
            ),
            item(
                "/",
                "context add diff [all|staged|unstaged]",
                "attach a verified Git diff snapshot",
            ),
            item(
                "/",
                "context add ide PATH",
                "attach an IDE-exported selection/document",
            ),
            item(
                "/",
                "context add lsp PATH",
                "attach an LSP-exported result document",
            ),
            item(
                "/",
                "context preview N",
                "bounded preview; digest covers complete submitted bytes",
            ),
            item(
                "/",
                "context delete N",
                "remove exactly one text context chip",
            ),
            block::PanelRow::Note(
                "quoted paths with spaces are accepted; integrations are frozen at attach time"
                    .into(),
            ),
        ],
    );
}

fn show_stats(app: &mut App, session: &Session) {
    let mut rows = Vec::new();
    if let Some(context) = app.last_context {
        rows.extend([
            kv(
                "request estimate",
                &format!("≈{} tokens", fmt_token_count(context.total_tokens as u64)),
            ),
            kv(
                "  system / tools",
                &format!(
                    "≈{} / ≈{}",
                    fmt_token_count(context.system_tokens as u64),
                    fmt_token_count(context.tool_tokens as u64)
                ),
            ),
            kv(
                "  transcript / framing",
                &format!(
                    "≈{} / ≈{}",
                    fmt_token_count(context.transcript_tokens as u64),
                    fmt_token_count(context.framing_tokens as u64)
                ),
            ),
            block::PanelRow::Note(
                "estimate: deterministic UTF-8 bytes/3.5 plus wire framing".into(),
            ),
        ]);
    } else {
        rows.push(block::PanelRow::Note(
            "no provider request has completed in this UI session yet".into(),
        ));
    }
    if let Some(usage) = app.last_turn_usage {
        rows.extend([
            kv(
                "provider-reported input",
                &format!("{} tokens", fmt_token_count(request_input_tokens(usage))),
            ),
            kv(
                "  uncached / cache read / write",
                &format!(
                    "{} / {} / {}",
                    fmt_token_count(usage.input),
                    fmt_token_count(usage.cache_read),
                    fmt_token_count(usage.cache_creation)
                ),
            ),
            kv(
                "output / thinking",
                &format!(
                    "{} / {}",
                    fmt_token_count(usage.output),
                    fmt_token_count(usage.thinking)
                ),
            ),
            kv(
                "last-turn cache hit",
                &format!("{:.0}%", usage.cache_hit_ratio() * 100.0),
            ),
        ]);
    }
    match app.model_context_window.filter(|window| *window > 0) {
        Some(window) => {
            let estimated_input = app
                .last_context
                .map(|context| context.total_tokens as u64)
                .unwrap_or(0);
            let reserve = u64::from(app.reserved_output_tokens.unwrap_or_default());
            let remaining = window.saturating_sub(estimated_input.saturating_add(reserve));
            let pct_left = remaining as f64 / window as f64 * 100.0;
            rows.push(kv(
                "model context window",
                &format!(
                    "{} · {} admission headroom ({pct_left:.0}%)",
                    fmt_token_count(window),
                    fmt_token_count(remaining)
                ),
            ));
            if app.last_context.is_some() {
                rows.push(kv(
                    "reserved output",
                    &format!("{} tokens", fmt_token_count(reserve)),
                ));
            }
        }
        None => rows.push(kv(
            "model context window",
            "unknown (not proven for this exact route)",
        )),
    }
    rows.push(kv(
        "compaction trigger",
        &format!(
            "{} tokens (policy threshold, not the model window)",
            fmt_token_count(session.compaction_trigger_tokens() as u64)
        ),
    ));
    if let Some(application) = app.effort_application {
        rows.push(kv(
            "effort applied",
            &effort_application_detail(application),
        ));
    }
    rows.push(block::PanelRow::Note(
        "`/context list` inspects structured chips; `/context help` shows attachment commands"
            .into(),
    ));
    app.panel("◔", "context — last provider turn", rows);
}

fn parse_index(raw: &str) -> Option<usize> {
    raw.trim().parse::<usize>().ok().filter(|value| *value > 0)
}

fn unquote(raw: &str) -> &str {
    raw.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            raw.strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(raw)
}

fn short_digest(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

fn usage_error(app: &mut App) {
    app.note(
        block::NoticeLevel::Err,
        "usage: /context [stats|list|help|preview N|delete N|add file PATH|add diff [all|staged|unstaged]|add ide PATH|add lsp PATH]",
    );
}
