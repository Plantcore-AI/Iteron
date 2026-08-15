//! Retained incremental layout for the active assistant answer.
//!
//! Settled Markdown is rendered only when its semantic prefix changes. The unresolved literal tail
//! is wrapped from appended bytes, retaining at most one mutable display row. Frames clone only the
//! visible rows, so a one-megabyte unfinished paragraph is neither reparsed nor rewrapped per tick.

use super::hyperlink::Policy as HyperlinkPolicy;
use crate::markdown::{MarkdownDoc, StreamingParse, render_doc_with_hyperlinks};
use crate::render::{HyperlinkRegion, RenderedLines};
use crate::theme::Theme;
use ratatui::style::Style;
use ratatui::text::{Line, Span};

#[derive(Debug, Default)]
pub(crate) struct LiveMarkdownLayout {
    width: u16,
    theme_epoch: u64,
    settled_blocks: usize,
    settled_len: usize,
    observed_len: usize,
    fenced: bool,
    prefix: RenderedLines,
    pending: IncrementalLiteralWrap,
    #[cfg(test)]
    laid_out_source_bytes: usize,
}

pub(crate) struct LiveMarkdownRenderContext<'a> {
    pub(crate) width: u16,
    pub(crate) theme_epoch: u64,
    pub(crate) theme: &'a Theme,
    pub(crate) hyperlinks: &'a HyperlinkPolicy,
}

impl LiveMarkdownLayout {
    pub(crate) fn update(
        &mut self,
        doc: &MarkdownDoc,
        parse: &StreamingParse,
        source: &str,
        context: LiveMarkdownRenderContext<'_>,
    ) {
        let LiveMarkdownRenderContext {
            width,
            theme_epoch,
            theme,
            hyperlinks,
        } = context;
        let settled_blocks = parse.settled_blocks();
        let settled_len = parse.settled_len();
        let fenced = parse.pending_fenced();
        let rebuild = self.width != width
            || self.theme_epoch != theme_epoch
            || self.settled_blocks != settled_blocks
            || self.settled_len != settled_len
            || self.fenced != fenced
            || source.len() < self.observed_len
            || !source.is_char_boundary(self.observed_len);
        if rebuild {
            self.rebuild(
                doc,
                parse,
                source,
                LiveMarkdownRenderContext {
                    width,
                    theme_epoch,
                    theme,
                    hyperlinks,
                },
            );
            return;
        }
        if self.observed_len < source.len() {
            let appended = &source[self.observed_len..];
            self.pending.extend(appended);
            self.observed_len = source.len();
            #[cfg(test)]
            {
                self.laid_out_source_bytes =
                    self.laid_out_source_bytes.saturating_add(appended.len());
            }
        }
    }

    fn rebuild(
        &mut self,
        doc: &MarkdownDoc,
        parse: &StreamingParse,
        source: &str,
        context: LiveMarkdownRenderContext<'_>,
    ) {
        let LiveMarkdownRenderContext {
            width,
            theme_epoch,
            theme,
            hyperlinks,
        } = context;
        let gutter = crate::block::assistant_gutter(width);
        let content_width = width.saturating_sub(gutter).max(1);
        let settled_blocks = parse.settled_blocks();
        self.prefix = if settled_blocks == 0 {
            RenderedLines::default()
        } else {
            render_doc_with_hyperlinks(
                &MarkdownDoc {
                    blocks: doc.blocks[..settled_blocks.min(doc.blocks.len())].to_vec(),
                    source: None,
                },
                content_width,
                theme,
                hyperlinks,
            )
        };
        let pending_source = &source[parse.settled_len().min(source.len())..];
        if !self.prefix.lines.is_empty() && !pending_source.is_empty() {
            self.prefix.push_plain(Line::from(""));
        }
        let style = if parse.pending_fenced() {
            Style::default().fg(theme.fg).bg(theme.code_bg)
        } else {
            Style::default().fg(theme.fg)
        };
        self.pending = IncrementalLiteralWrap::new(content_width, style);
        self.pending.extend(pending_source);
        self.width = width;
        self.theme_epoch = theme_epoch;
        self.settled_blocks = settled_blocks;
        self.settled_len = parse.settled_len();
        self.observed_len = source.len();
        self.fenced = parse.pending_fenced();
        #[cfg(test)]
        {
            self.laid_out_source_bytes = self
                .laid_out_source_bytes
                .saturating_add(pending_source.len());
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.prefix.lines.len().saturating_add(self.pending.len())
    }

    pub(crate) fn line(&self, row: usize, theme: &Theme) -> Option<Line<'static>> {
        let mut line = if row < self.prefix.lines.len() {
            self.prefix.lines.get(row)?.clone()
        } else {
            self.pending.line(row - self.prefix.lines.len())?
        };
        if crate::block::assistant_gutter(self.width) > 0 {
            let mut spans = vec![Span::styled(
                if row == 0 { "● " } else { "  " },
                if row == 0 {
                    Style::default().fg(theme.role_assistant)
                } else {
                    Style::default()
                },
            )];
            spans.append(&mut line.spans);
            line = Line::from(spans);
        }
        Some(line)
    }

    pub(crate) fn visible_hyperlinks(
        &self,
        from: usize,
        to: usize,
        segment_start: usize,
    ) -> Vec<HyperlinkRegion> {
        let gutter = crate::block::assistant_gutter(self.width);
        self.prefix
            .hyperlinks
            .iter()
            .filter(|region| region.row >= from && region.row < to)
            .cloned()
            .map(|mut region| {
                region.row = region.row.saturating_add(segment_start);
                region.col = region.col.saturating_add(gutter);
                region
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn laid_out_source_bytes(&self) -> usize {
        self.laid_out_source_bytes
    }
}

#[derive(Debug, Default)]
struct IncrementalLiteralWrap {
    width: u16,
    style: Style,
    committed: Vec<Line<'static>>,
    current: Vec<char>,
    current_width: u16,
    last_space: Option<usize>,
}

impl IncrementalLiteralWrap {
    fn new(width: u16, style: Style) -> Self {
        Self {
            width: width.max(1),
            style,
            ..Self::default()
        }
    }

    fn extend(&mut self, appended: &str) {
        let safe = terminal_safe_literal(appended);
        for character in safe.chars() {
            let character = if matches!(character, '\r' | '\n') {
                ' '
            } else if super::char_width(character) > self.width {
                '?'
            } else {
                character
            };
            let character_width = super::char_width(character);
            if self.current_width.saturating_add(character_width) > self.width
                && !self.current.is_empty()
            {
                if let Some(space) = self
                    .last_space
                    .filter(|space| *space > 0 && *space < self.current.len())
                {
                    let tail = self.current.split_off(space);
                    while self
                        .current
                        .last()
                        .is_some_and(|character| *character == ' ')
                    {
                        self.current.pop();
                    }
                    self.commit_current();
                    self.current = tail;
                } else {
                    self.commit_current();
                }
                self.remeasure_current();
            }
            self.current.push(character);
            self.current_width = self.current_width.saturating_add(character_width);
            if character == ' ' {
                self.last_space = Some(self.current.len());
            }
        }
    }

    fn commit_current(&mut self) {
        let text: String = self.current.drain(..).collect();
        self.committed
            .push(Line::from(Span::styled(text, self.style)));
        self.current_width = 0;
        self.last_space = None;
    }

    fn remeasure_current(&mut self) {
        self.current_width = self
            .current
            .iter()
            .map(|character| super::char_width(*character))
            .fold(0u16, u16::saturating_add);
        self.last_space = self
            .current
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, character)| (*character == ' ').then_some(index + 1));
    }

    fn len(&self) -> usize {
        self.committed.len().saturating_add(usize::from(
            !self.current.is_empty() || self.committed.is_empty(),
        ))
    }

    fn line(&self, row: usize) -> Option<Line<'static>> {
        if let Some(line) = self.committed.get(row) {
            return Some(line.clone());
        }
        (row == self.committed.len()).then(|| {
            Line::from(Span::styled(
                self.current.iter().collect::<String>(),
                self.style,
            ))
        })
    }
}

fn terminal_safe_literal(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for character in text.chars() {
        if matches!(character, '\r' | '\n') {
            safe.push(character);
        } else if character.is_control() {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}
