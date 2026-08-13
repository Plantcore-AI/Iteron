//! Byte-capped reconstruction of parsed Markdown for the transcript projection worker.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::markdown::{Inline, MarkdownDoc, MdBlock};

/// Ceiling on the buffer reserved before any Markdown is reconstructed. The caller's byte cap can
/// be far larger than the document it bounds, so reserving the cap itself would charge every short
/// reply for the longest one the viewer tolerates.
const MARKDOWN_RESERVE_BYTES: usize = 64 * 1024;

pub(super) fn project(
    document: &MarkdownDoc,
    max_bytes: usize,
    cancelled: &AtomicBool,
) -> Option<(String, bool)> {
    let mut out = BoundedMarkdown::new(max_bytes, cancelled);
    for block in &document.blocks {
        if !out.active() {
            break;
        }
        match block {
            MdBlock::Heading(level, spans) => {
                out.repeat("#", usize::from(*level));
                out.push(" ");
                out.inline(spans);
                out.push("\n");
            }
            MdBlock::Para(spans) => {
                out.inline(spans);
                out.push("\n");
            }
            MdBlock::Bullet {
                depth,
                task,
                spans,
                continuation,
            } => {
                out.repeat("  ", usize::from(*depth));
                out.push("- ");
                if let Some(checked) = task {
                    out.push(if *checked { "[x] " } else { "[ ] " });
                }
                out.inline(spans);
                out.push("\n");
                let indent = usize::from(*depth)
                    .saturating_mul(2)
                    .saturating_add(2)
                    .saturating_add(task.map_or(0, |_| 4));
                for line in continuation {
                    if !out.active() {
                        break;
                    }
                    out.repeat(" ", indent);
                    out.inline(line);
                    out.push("\n");
                }
            }
            MdBlock::Numbered {
                depth,
                n,
                task,
                spans,
                continuation,
            } => {
                out.repeat("  ", usize::from(*depth));
                let number = n.to_string();
                out.push(&number);
                out.push(". ");
                if let Some(checked) = task {
                    out.push(if *checked { "[x] " } else { "[ ] " });
                }
                out.inline(spans);
                out.push("\n");
                let indent = usize::from(*depth)
                    .saturating_mul(2)
                    .saturating_add(number.chars().count())
                    .saturating_add(2)
                    .saturating_add(task.map_or(0, |_| 4));
                for line in continuation {
                    if !out.active() {
                        break;
                    }
                    out.repeat(" ", indent);
                    out.inline(line);
                    out.push("\n");
                }
            }
            MdBlock::Quote(spans) => {
                out.push("> ");
                out.inline(spans);
                out.push("\n");
            }
            MdBlock::Code { lang, lines } => {
                out.push("```");
                if let Some(language) = lang {
                    out.push(language);
                }
                out.push("\n");
                for line in lines {
                    if !out.active() {
                        break;
                    }
                    out.push(line);
                    out.push("\n");
                }
                out.push("```\n");
            }
            MdBlock::Rule => out.push("---\n"),
            MdBlock::Table { headers, rows } => {
                out.push("|");
                for cell in headers {
                    out.push(" ");
                    out.inline(cell);
                    out.push(" |");
                }
                out.push("\n|");
                for _ in headers {
                    out.push(" --- |");
                }
                out.push("\n");
                for row in rows {
                    if !out.active() {
                        break;
                    }
                    out.push("|");
                    for cell in row {
                        out.push(" ");
                        out.inline(cell);
                        out.push(" |");
                    }
                    out.push("\n");
                }
            }
        }
    }
    out.finish()
}

struct BoundedMarkdown<'a> {
    text: String,
    max_bytes: usize,
    truncated: bool,
    cancelled: &'a AtomicBool,
}

impl<'a> BoundedMarkdown<'a> {
    fn new(max_bytes: usize, cancelled: &'a AtomicBool) -> Self {
        Self {
            text: String::with_capacity(max_bytes.min(iteron_tunables::param_integer(
                "cli.tui.transcript_viewer.semantic_text.markdown.markdown_reserve_bytes",
                MARKDOWN_RESERVE_BYTES,
            ))),
            max_bytes,
            truncated: false,
            cancelled,
        }
    }

    fn active(&self) -> bool {
        !self.truncated && !self.cancelled.load(Ordering::Relaxed)
    }

    fn push(&mut self, value: &str) {
        if !self.active() {
            return;
        }
        if self.text.len().saturating_add(value.len()) > self.max_bytes {
            self.truncated = true;
            return;
        }
        self.text.push_str(value);
    }

    fn repeat(&mut self, value: &str, count: usize) {
        for _ in 0..count {
            if !self.active() {
                break;
            }
            self.push(value);
        }
    }

    fn inline(&mut self, spans: &[Inline]) {
        for span in spans {
            if !self.active() {
                break;
            }
            match span {
                Inline::Text(text) => self.push(text),
                Inline::Bold(text) => {
                    self.push("**");
                    self.push(text);
                    self.push("**");
                }
                Inline::Italic(text) => {
                    self.push("_");
                    self.push(text);
                    self.push("_");
                }
                Inline::Code(text) => {
                    self.push("`");
                    self.push(text);
                    self.push("`");
                }
                Inline::Link { text, url } => {
                    self.push("[");
                    self.push(text);
                    self.push("](");
                    self.push(url);
                    self.push(")");
                }
            }
        }
    }

    fn finish(self) -> Option<(String, bool)> {
        (!self.cancelled.load(Ordering::Relaxed)).then_some((self.text, self.truncated))
    }
}
