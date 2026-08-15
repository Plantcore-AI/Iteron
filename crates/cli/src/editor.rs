//! A small, pure, terminal-agnostic line editor for the TUI input box (R6 SOTA UX).
//!
//! It owns the input buffer + cursor + history and exposes readline-style edits as plain method
//! calls, so ALL of it is unit-testable without a TTY (the crossterm key loop just translates key
//! events into these calls). This is the same testability discipline the kernel uses: the effectful
//! shell (crossterm) is thin; the logic is pure.
//!
//! Supported (Claude Code parity + a bit more): insert, Backspace/Delete, ←/→, Home/End
//! (Ctrl-A/Ctrl-E), word-left/right, Ctrl-W (delete word), Ctrl-U (kill to start), Ctrl-K (kill to
//! end), multi-line newline insertion, and ↑/↓ input history with a stash of the in-progress line.

use crate::file_input::{
    ContextKind, FileAttachment, FileAttachments, FileInputError, PreparedFile,
};
use crate::image_input::{ImageAttachment, ImageAttachments, ImageInputError, PreparedImage};
use crate::paste_input::{ImageAnchors, PasteCapture, PasteInputError, PastedTexts};
#[cfg(test)]
use std::path::Path;
use unicode_segmentation::UnicodeSegmentation as _;

/// A cleared draft is a convenience, not another unbounded transcript. Count source UTF-8 bytes
/// so the retained allocation has a hard, portable ceiling while the editor remains char-based.
const MAX_RECOVERABLE_DRAFT_BYTES: usize = 64 * 1024;

/// THE sanitiser for foreign text entering the composer — a paste, a completion, an external-editor
/// round trip, a block held aside by [`crate::paste_input`]. It is one function on purpose: a
/// second "almost the same" rule elsewhere is how a control byte eventually reaches the terminal.
/// Newlines and tabs survive; every other control/format character is dropped, char by char so a
/// multibyte character is never split.
pub fn sanitize_foreign_text(text: &str) -> String {
    text.chars()
        .filter(|c| *c == '\n' || *c == '\t' || !is_stripped_control(*c))
        .collect()
}

/// True if `c` is a control/format char that must be stripped from pasted input (everything except
/// the newline/tab handled by the caller): the C0/C1 control ranges, DEL, and the zero-width
/// bidi/format controls that corrupt column math and cause overlapping/garbled redraw (乱码).
fn is_stripped_control(c: char) -> bool {
    let u = c as u32;
    matches!(u,
        0x00..=0x1F           // C0 controls incl. ESC (0x1B), CR (0x0D), BEL, BS
        | 0x7F                // DEL
        | 0x80..=0x9F         // C1 controls
        | 0x200B              // zero-width space
        // U+200C/U+200D are legitimate grapheme-shaping controls (ZWNJ/ZWJ); stripping them tears
        // apart Indic shaping and emoji-family clusters. U+200E/U+200F remain disallowed bidi marks.
        | 0x200E..=0x200F
        | 0x202A..=0x202E     // bidi embedding/override
        | 0x2060..=0x2064     // word joiner / invisible operators
        | 0xFEFF              // BOM / zero-width no-break space
    )
}

/// Translate the editor's compatibility scalar offset to the leading edge of its grapheme.
fn grapheme_floor_char_boundary(text: &str, target: usize) -> usize {
    let target = target.min(text.chars().count());
    let mut start = 0usize;
    for grapheme in text.graphemes(true) {
        let end = start.saturating_add(grapheme.chars().count());
        if target < end {
            return start;
        }
        if target == end {
            return end;
        }
        start = end;
    }
    start
}

/// Translate a scalar offset to the trailing edge of its grapheme.
fn grapheme_ceil_char_boundary(text: &str, target: usize) -> usize {
    let target = target.min(text.chars().count());
    let mut start = 0usize;
    for grapheme in text.graphemes(true) {
        let end = start.saturating_add(grapheme.chars().count());
        if target <= start {
            return start;
        }
        if target <= end {
            return end;
        }
        start = end;
    }
    start
}

fn grapheme_previous_char_boundary(text: &str, target: usize) -> usize {
    let target = grapheme_floor_char_boundary(text, target);
    let mut previous = 0usize;
    let mut end = 0usize;
    for grapheme in text.graphemes(true) {
        end = end.saturating_add(grapheme.chars().count());
        if end >= target {
            return previous;
        }
        previous = end;
    }
    previous
}

fn grapheme_next_char_boundary(text: &str, target: usize) -> usize {
    let target = target.min(text.chars().count());
    let mut end = 0usize;
    for grapheme in text.graphemes(true) {
        end = end.saturating_add(grapheme.chars().count());
        if end > target {
            return end;
        }
    }
    end
}

/// The input line editor. Storage and public offsets remain Unicode-scalar indices for wire/API
/// compatibility, while every cursor/edit boundary is snapped to an extended grapheme cluster.
#[derive(Debug, Default)]
pub struct Editor {
    buf: Vec<char>,
    cursor: usize,
    history: Vec<String>,
    /// `Some(i)` while browsing history (index into `history`); `None` when editing the live line.
    hist_pos: Option<usize>,
    /// The live line stashed when the user starts browsing history, restored on browsing past the end.
    stash: Option<String>,
    /// The most recent explicitly recoverable clear. Independent from history's live-line stash;
    /// bounded so repeated clears cannot accumulate an unbounded side buffer.
    recently_cleared: Option<String>,
    /// Bounded, already-sniffed image chips attached to the current draft. The payloads are
    /// deliberately not copied into text history or the recoverable-text slot; only the in-line
    /// `[Image #N]` anchor that says where each one belongs is draft text.
    attachments: ImageAttachments,
    /// Bounded, already-contained file chips on the same draft, under the same rule: file text
    /// never enters text history or the recoverable-text slot.
    files: FileAttachments,
    /// Pasted blocks held aside for this draft. Unlike the two chip collections these are
    /// referenced *in-band*, by a tag inside `buf`, because a pasted block has a position in the
    /// sentence being written; `take_submit` expands the tags back into the submitted text.
    pastes: PastedTexts,
    /// The order all chip collections were filled in, so "remove the last chip" removes the
    /// chip the operator last saw appear rather than the last chip of whichever kind we asked
    /// first. One entry per live attachment; both collections and this log are cleared together.
    chip_order: Vec<ChipKind>,
    /// State for repeated Ctrl-R searches. The query is the text that was present before the first
    /// search; `before` makes every subsequent press continue toward older entries.
    reverse_search: Option<ReverseSearch>,
    /// Monotonic dirty marker consumed by the persistence adapter. It deliberately counts text
    /// mutations rather than wall time so tests and replay remain deterministic.
    persistence_revision: u64,
    /// Bounded, filesystem-free classification of the leading draft token. The TUI reads this
    /// cached value on every paint/key route; only final Enter admission resolves an ambiguous
    /// single-segment absolute path against disk.
    draft_shape: DraftShape,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DraftShape {
    #[default]
    Prose,
    Shell,
    PathLike,
    Slash {
        immediate_while_running: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChipKind {
    Image(u32),
    File(u32),
    Paste(u32),
}

/// One composer chip in the exact order it was attached. Payloads stay borrowed and never enter
/// terminal text; the renderer uses this projection solely for one-row identity/metadata lines.
pub enum DraftChip<'a> {
    Image(&'a ImageAttachment),
    File(&'a FileAttachment),
    Paste(&'a crate::paste_input::PastedText),
}

#[derive(Debug)]
struct ReverseSearch {
    query: String,
    before: usize,
}

impl Editor {
    pub fn new() -> Self {
        Editor::default()
    }

    /// The current text (may contain '\n' for multi-line input).
    pub fn text(&self) -> String {
        self.buf.iter().collect()
    }

    /// Cursor position as a char index into `text()`.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn draft_shape(&self) -> DraftShape {
        self.draft_shape
    }

    pub fn has_submission(&self) -> bool {
        !self.buf.is_empty() || self.chip_count() > 0
    }

    /// Total chips on the draft — what the composer draws and reserves one line for.
    pub fn chip_count(&self) -> usize {
        self.chip_order.len()
    }

    pub fn chips(&self) -> Vec<DraftChip<'_>> {
        self.chip_order
            .iter()
            .filter_map(|kind| match kind {
                ChipKind::Image(id) => self.attachments.get(*id).map(DraftChip::Image),
                ChipKind::File(id) => self.files.get(*id).map(DraftChip::File),
                ChipKind::Paste(id) => self.pastes.get(*id).map(DraftChip::Paste),
            })
            .collect()
    }

    pub fn attachments(&self) -> &ImageAttachments {
        &self.attachments
    }

    pub fn files(&self) -> &FileAttachments {
        &self.files
    }

    /// The pasted blocks this draft holds — the authority every tag is resolved against.
    pub fn pastes(&self) -> &PastedTexts {
        &self.pastes
    }

    /// Hold one pasted block aside and leave a tag in its place at the cursor.
    ///
    /// Line endings are normalised before the composer's own sanitiser runs, so a CR that is a
    /// line ending survives as `\n` while a CR in the middle of a line is dropped like any other
    /// control character. After this call the stored bytes are final: [`Self::take_submit`] emits
    /// them verbatim.
    pub fn capture_paste(&mut self, raw: &str) -> Result<PasteCapture, PasteInputError> {
        let sanitised = sanitize_foreign_text(&crate::paste_input::normalize_newlines(raw));
        let (capture, tag) = {
            let stored = self.pastes.store(sanitised)?;
            (
                PasteCapture {
                    id: stored.id(),
                    lines: stored.lines(),
                    bytes: stored.bytes(),
                },
                stored.tag(),
            )
        };
        if !self.chip_order.contains(&ChipKind::Paste(capture.id)) {
            self.chip_order.push(ChipKind::Paste(capture.id));
        }
        // The tag is text this module generated, so it needs no sanitising — but it goes through
        // `insert` for the cursor, history-navigation and persistence bookkeeping every other
        // insertion gets.
        for character in tag.chars() {
            self.insert(character);
        }
        Ok(capture)
    }

    #[cfg(test)]
    pub fn attach_image_path(&mut self, path: &Path) -> Result<&ImageAttachment, ImageInputError> {
        let id = self.attachments.attach_path(path)?.id();
        self.admit_image(id);
        Ok(self
            .attachments
            .get(id)
            .expect("an image was just attached under this id"))
    }

    /// Book-keeping shared by every way an image arrives: it joins the chip order, and it gets an
    /// in-line anchor at the cursor.
    ///
    /// The anchor is inserted automatically rather than on a second gesture, for the same reason a
    /// captured paste leaves its tag behind automatically: the common case is drag-then-keep-typing,
    /// and a position the operator has to ask for is a position nobody ever asks for. It is also the
    /// cheap direction to be wrong in — one backspace takes the anchor away and leaves the image
    /// attached exactly as it was before anchors existed, whereas an anchor that must be requested
    /// cannot be discovered at all.
    fn admit_image(&mut self, id: u32) {
        self.chip_order.push(ChipKind::Image(id));
        // Generated text, so it needs no sanitising — but it goes through `insert` for the cursor,
        // history-navigation and persistence bookkeeping every other insertion gets.
        for character in crate::paste_input::image_anchor(id).chars() {
            self.insert(character);
        }
    }

    /// Cut every anchor naming `id` out of the draft, keeping the cursor where the operator left it.
    ///
    /// Runs back to front so each byte range still describes the buffer it was measured against —
    /// the same discipline `paste_input::expand` follows, and for the same reason.
    fn remove_tag_occurrences(&mut self, kind: crate::paste_input::TagKind, id: u32) {
        let text = self.text();
        let doomed: Vec<std::ops::Range<usize>> = crate::paste_input::find_tags(&text)
            .into_iter()
            .filter(|found| found.kind == kind && found.id == id)
            .map(|found| found.byte_range)
            .collect();
        for range in doomed.iter().rev() {
            let start = text[..range.start].chars().count();
            let end = text[..range.end].chars().count();
            self.buf.drain(start..end);
            self.cursor = if self.cursor >= end {
                self.cursor - (end - start)
            } else {
                self.cursor.min(start)
            };
        }
        if !doomed.is_empty() {
            self.leave_navigation();
            self.mark_persistence_change();
        }
    }

    /// Attach one workspace file. Containment, bounds and sanitisation all live in
    /// [`crate::file_input`]; the editor only owns the draft state and the chip order.
    #[cfg(test)]
    pub fn attach_file_path(
        &mut self,
        workspace: &Path,
        path: &Path,
    ) -> Result<&FileAttachment, FileInputError> {
        let id = self.files.attach_path(workspace, path)?.id();
        self.admit_file(id);
        Ok(self.files.get(id).expect("a file was just attached"))
    }

    /// Attach a complete integration-produced context document. The file-input store owns the
    /// common limits, digest and SQ bytes; the editor contributes only draft ordering.
    pub fn attach_context(
        &mut self,
        kind: ContextKind,
        display_label: &str,
        text: String,
    ) -> Result<&FileAttachment, FileInputError> {
        let id = self.files.attach_generated(kind, display_label, text)?.id();
        self.admit_file(id);
        Ok(self.files.get(id).expect("a context was just attached"))
    }

    pub(crate) fn admit_prepared_file(
        &mut self,
        prepared: PreparedFile,
    ) -> Result<&FileAttachment, FileInputError> {
        let id = self.files.admit_prepared(prepared)?.id();
        self.admit_file(id);
        Ok(self
            .files
            .get(id)
            .expect("a prepared file was just attached"))
    }

    fn admit_file(&mut self, id: u32) {
        self.chip_order.push(ChipKind::File(id));
        for character in crate::paste_input::file_anchor(id).chars() {
            self.insert(character);
        }
    }

    /// Remove one text context chip by its visible one-based index. This is deliberately separate
    /// from Alt-Backspace's global "newest chip" gesture: `/context delete N` stays stable even
    /// when image chips are interleaved with text contexts.
    pub fn remove_context(&mut self, one_based: usize) -> bool {
        let Some(index) = one_based.checked_sub(1) else {
            return false;
        };
        let Some(id) = self.files.as_slice().get(index).map(FileAttachment::id) else {
            return false;
        };
        self.files.remove(index);
        self.chip_order.retain(|kind| *kind != ChipKind::File(id));
        self.remove_tag_occurrences(crate::paste_input::TagKind::File, id);
        true
    }

    /// Drop every next-turn text context and every generated tag naming it. This is the frontend
    /// half of `/context refresh`: the next submission must rebuild context from current sources,
    /// never silently retain an earlier file/diff/LSP snapshot.
    pub fn clear_contexts(&mut self) -> usize {
        let ids = self
            .files
            .as_slice()
            .iter()
            .map(FileAttachment::id)
            .collect::<Vec<_>>();
        let removed = ids.len();
        self.files.clear();
        self.chip_order
            .retain(|kind| !matches!(kind, ChipKind::File(_)));
        for id in ids {
            self.remove_tag_occurrences(crate::paste_input::TagKind::File, id);
        }
        removed
    }

    #[cfg(test)]
    pub fn attach_image_bytes(
        &mut self,
        display_label: &str,
        bytes: &[u8],
    ) -> Result<&ImageAttachment, ImageInputError> {
        let id = self.attachments.attach_bytes(display_label, bytes)?.id();
        self.admit_image(id);
        Ok(self
            .attachments
            .get(id)
            .expect("an image was just attached under this id"))
    }

    /// Admit an image whose filesystem/decode/base64 work already completed in the bounded TUI
    /// attachment actor. This method is deliberately in-memory-only so the render/input thread can
    /// call it without inheriting any blocking work.
    pub(crate) fn admit_prepared_image(
        &mut self,
        prepared: PreparedImage,
    ) -> Result<&ImageAttachment, ImageInputError> {
        let id = self.attachments.admit_prepared(prepared)?.id();
        self.admit_image(id);
        Ok(self
            .attachments
            .get(id)
            .expect("a prepared image was just attached under this id"))
    }

    /// Remove the most recently added chip of any kind.
    ///
    /// Removing an image chip is the operator saying "this image is not part of my prompt", so its
    /// anchors go with it: an anchor for an image nobody is sending points at nothing, and leaving
    /// it would put "attachment no longer available" into a prompt the operator deliberately tidied.
    /// Deleting either view removes the same attachment: chips and live tags cannot drift apart.
    pub fn remove_last_attachment(&mut self) -> bool {
        match self.chip_order.pop() {
            Some(ChipKind::Image(id)) => {
                let Some(index) = self
                    .attachments
                    .as_slice()
                    .iter()
                    .position(|attachment| attachment.id() == id)
                else {
                    return false;
                };
                self.attachments.remove(index);
                self.remove_tag_occurrences(crate::paste_input::TagKind::Image, id);
                true
            }
            Some(ChipKind::File(id)) => {
                let Some(index) = self
                    .files
                    .as_slice()
                    .iter()
                    .position(|attachment| attachment.id() == id)
                else {
                    return false;
                };
                self.files.remove(index);
                self.remove_tag_occurrences(crate::paste_input::TagKind::File, id);
                true
            }
            Some(ChipKind::Paste(id)) => {
                let removed = self.pastes.remove(id);
                self.remove_tag_occurrences(crate::paste_input::TagKind::PastedText, id);
                removed
            }
            None => false,
        }
    }

    /// Cursor position as a (row, col) within the possibly multi-line buffer — for rendering.
    pub fn cursor_row_col(&self) -> (usize, usize) {
        let mut row = 0;
        let mut col = 0;
        for &c in &self.buf[..self.cursor] {
            if c == '\n' {
                row += 1;
                col = 0;
            } else {
                col += 1;
            }
        }
        (row, col)
    }

    // ---- insertion -------------------------------------------------------------------------

    pub fn insert(&mut self, c: char) {
        self.buf.insert(self.cursor, c);
        self.cursor += 1;
        // Inserting a joiner/combining scalar can merge the following scalar into the same visible
        // glyph. A terminal cursor cannot sit inside that glyph, so advance to its trailing edge.
        self.cursor = grapheme_ceil_char_boundary(&self.text(), self.cursor);
        self.leave_navigation();
        self.mark_persistence_change();
    }

    pub fn insert_str(&mut self, s: &str) {
        // Strip literal control/escape bytes from pasted or completed text (the 乱码 bug): a raw ESC,
        // CR, backspace, bell, or a zero-width bidi/format control would corrupt the buffer's column
        // math and overlap on redraw. Keep only newlines and tabs among the control range; drop the
        // rest. Char-based so a multibyte char is never split.
        let sanitized = sanitize_foreign_text(s);
        if sanitized.is_empty() {
            return;
        }
        let inserted = sanitized.chars().collect::<Vec<_>>();
        let inserted_len = inserted.len();
        self.buf.splice(self.cursor..self.cursor, inserted);
        self.cursor = self.cursor.saturating_add(inserted_len);
        self.cursor = grapheme_ceil_char_boundary(&self.text(), self.cursor);
        self.leave_navigation();
        self.mark_persistence_change();
    }

    /// Insert a literal newline (multi-line input, e.g. Shift+Enter).
    pub fn newline(&mut self) {
        self.insert('\n');
    }

    // ---- deletion --------------------------------------------------------------------------

    /// Expand a text deletion to whole tag boundaries, then reconcile every tag-backed chip.
    /// No editor gesture is allowed to leave half a tag or a chip whose reference disappeared.
    fn delete_range_synchronized(&mut self, a: usize, b: usize) {
        let (mut lo, mut hi) = if a <= b { (a, b) } else { (b, a) };
        hi = hi.min(self.buf.len());
        lo = lo.min(hi);
        let text = self.text();
        lo = grapheme_floor_char_boundary(&text, lo);
        hi = grapheme_ceil_char_boundary(&text, hi);
        if lo == hi {
            return;
        }
        let tag_ranges = crate::paste_input::find_tags(&text)
            .into_iter()
            .filter(|found| match found.kind {
                crate::paste_input::TagKind::Image => self.attachments.holds_image(found.id),
                crate::paste_input::TagKind::PastedText => self.pastes.get(found.id).is_some(),
                crate::paste_input::TagKind::File => self.files.get(found.id).is_some(),
            })
            .map(|found| {
                (
                    text[..found.byte_range.start].chars().count(),
                    text[..found.byte_range.end].chars().count(),
                )
            })
            .collect::<Vec<_>>();
        // Expanding to one tag can make the range touch another; iterate to a fixed point so every
        // tag the gesture intersects is removed atomically.
        loop {
            let before = (lo, hi);
            for &(start, end) in &tag_ranges {
                if lo < end && hi > start {
                    lo = lo.min(start);
                    hi = hi.max(end);
                }
            }
            if before == (lo, hi) {
                break;
            }
        }
        self.buf.drain(lo..hi);
        self.cursor = lo;
        self.reconcile_tagged_chips();
        self.leave_navigation();
        self.mark_persistence_change();
    }

    /// Bidirectional draft invariant: a tag-backed chip exists iff at least one complete live tag
    /// still names it.
    fn reconcile_tagged_chips(&mut self) {
        let tags = crate::paste_input::find_tags(&self.text());
        let detached_images = self
            .attachments
            .as_slice()
            .iter()
            .map(ImageAttachment::id)
            .filter(|id| {
                !tags
                    .iter()
                    .any(|tag| tag.kind == crate::paste_input::TagKind::Image && tag.id == *id)
            })
            .collect::<Vec<_>>();
        for id in detached_images {
            if let Some(index) = self
                .attachments
                .as_slice()
                .iter()
                .position(|attachment| attachment.id() == id)
            {
                self.attachments.remove(index);
            }
            self.chip_order.retain(|kind| *kind != ChipKind::Image(id));
        }
        let detached_pastes = self
            .pastes
            .as_slice()
            .iter()
            .map(crate::paste_input::PastedText::id)
            .filter(|id| {
                !tags
                    .iter()
                    .any(|tag| tag.kind == crate::paste_input::TagKind::PastedText && tag.id == *id)
            })
            .collect::<Vec<_>>();
        for id in detached_pastes {
            self.pastes.remove(id);
            self.chip_order.retain(|kind| *kind != ChipKind::Paste(id));
        }
        let detached_files = self
            .files
            .as_slice()
            .iter()
            .map(FileAttachment::id)
            .filter(|id| {
                !tags
                    .iter()
                    .any(|tag| tag.kind == crate::paste_input::TagKind::File && tag.id == *id)
            })
            .collect::<Vec<_>>();
        for id in detached_files {
            if let Some(index) = self
                .files
                .as_slice()
                .iter()
                .position(|attachment| attachment.id() == id)
            {
                self.files.remove(index);
            }
            self.chip_order.retain(|kind| *kind != ChipKind::File(id));
        }
    }

    pub fn backspace(&mut self) {
        // A tag or an anchor is one thing on the screen, so it is one thing to erase. Without this,
        // the first backspace eats the closing bracket and turns a live reference into prose that no
        // longer resolves — the same reason the leading agent anchors its delete pattern to the
        // end of the placeholder rather than to a character.
        if let Some((range, id, kind)) = crate::paste_input::tag_ending_at(
            &self.buf,
            self.cursor,
            &self.pastes,
            &self.attachments,
            &self.files,
        ) {
            let _ = (id, kind); // identity is reconciled from the post-delete complete tag set.
            self.delete_range_synchronized(range.start, range.end);
            return;
        }
        if self.cursor > 0 {
            let start = grapheme_previous_char_boundary(&self.text(), self.cursor);
            self.delete_range_synchronized(start, self.cursor);
        }
    }

    /// Forward delete (Delete key).
    pub fn delete(&mut self) {
        if self.cursor < self.buf.len() {
            let end = grapheme_next_char_boundary(&self.text(), self.cursor);
            self.delete_range_synchronized(self.cursor, end);
        }
    }

    /// The text between two char indices, in either order.
    ///
    /// Takes the pair unordered because a visual selection's anchor may sit on either side of the
    /// cursor, and making the caller normalise it is how an off-by-one becomes a silent truncation.
    pub fn span(&self, a: usize, b: usize) -> String {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let text = self.text();
        let hi = grapheme_ceil_char_boundary(&text, hi.min(self.buf.len()));
        let lo = grapheme_floor_char_boundary(&text, lo.min(hi));
        self.buf[lo..hi].iter().collect()
    }

    /// Remove the text between two char indices and leave the cursor at the start of the removed
    /// span, which is where Vim leaves it after a visual delete.
    pub fn delete_span(&mut self, a: usize, b: usize) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let hi = hi.min(self.buf.len());
        let lo = lo.min(hi);
        if lo == hi {
            return;
        }
        self.delete_range_synchronized(lo, hi);
    }

    /// Ctrl-W: delete the word before the cursor (skip trailing non-word chars, then a word run).
    pub fn delete_word_before(&mut self) {
        let i = self.word_boundary_left();
        if i != self.cursor {
            self.delete_range_synchronized(i, self.cursor);
        }
    }

    /// Ctrl-U: delete from the start of the line to the cursor.
    pub fn kill_to_start(&mut self) {
        if self.cursor != 0 {
            self.delete_range_synchronized(0, self.cursor);
        }
    }

    /// Ctrl-K: delete from the cursor to the end of the line.
    pub fn kill_to_end(&mut self) {
        if self.cursor != self.buf.len() {
            self.delete_range_synchronized(self.cursor, self.buf.len());
        }
    }

    // ---- cursor movement -------------------------------------------------------------------

    pub fn left(&mut self) {
        self.cursor = grapheme_previous_char_boundary(&self.text(), self.cursor);
        self.reverse_search = None;
    }
    pub fn right(&mut self) {
        self.cursor = grapheme_next_char_boundary(&self.text(), self.cursor);
        self.reverse_search = None;
    }
    pub fn home(&mut self) {
        self.cursor = 0;
        self.reverse_search = None;
    }
    pub fn end(&mut self) {
        self.cursor = self.buf.len();
        self.reverse_search = None;
    }

    /// Place the cursor at an explicit character boundary.
    ///
    /// Mouse hit-testing lives in the terminal adapter, which converts a screen cell back into a
    /// character index before calling this method. Clamp here as the final invariant so a stale
    /// layout (for example, a resize arriving beside a click) can never manufacture an invalid
    /// slice boundary.
    pub fn set_cursor(&mut self, char_index: usize) {
        self.cursor = grapheme_floor_char_boundary(&self.text(), char_index.min(self.buf.len()));
        self.leave_navigation();
    }

    /// A "word" char for word-motion: alphanumeric or `_`. Punctuation is a boundary (standard
    /// readline) so Alt-B/Alt-F/Ctrl-W stop at `.`/`/`/`-` etc. rather than swallowing them.
    fn is_word(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    fn word_boundary_left(&self) -> usize {
        let mut i = self.cursor;
        while i > 0 && !Self::is_word(self.buf[i - 1]) {
            i -= 1;
        }
        while i > 0 && Self::is_word(self.buf[i - 1]) {
            i -= 1;
        }
        i
    }

    /// Word-left (Alt-←/Alt-B): skip non-word chars then a word run.
    pub fn word_left(&mut self) {
        self.cursor = grapheme_floor_char_boundary(&self.text(), self.word_boundary_left());
        self.reverse_search = None;
    }

    /// Word-right (Alt-→/Alt-F): skip non-word chars then a word run.
    pub fn word_right(&mut self) {
        let n = self.buf.len();
        let mut i = self.cursor;
        while i < n && !Self::is_word(self.buf[i]) {
            i += 1;
        }
        while i < n && Self::is_word(self.buf[i]) {
            i += 1;
        }
        self.cursor = grapheme_ceil_char_boundary(&self.text(), i);
        self.reverse_search = None;
    }

    // ---- history ---------------------------------------------------------------------------

    /// ↑: recall the previous history entry (stashing the live line the first time).
    pub fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let next = match self.hist_pos {
            None => {
                self.stash = Some(self.text());
                self.history.len() - 1
            }
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.set_from_history(next);
        self.reverse_search = None;
        self.mark_persistence_change();
    }

    /// ↓: move forward in history; past the newest entry restores the stashed live line.
    pub fn history_next(&mut self) {
        match self.hist_pos {
            None => {}
            Some(i) if i + 1 < self.history.len() => {
                self.set_from_history(i + 1);
                self.mark_persistence_change();
            }
            Some(_) => {
                // past the newest -> restore the stash and leave history mode
                let s = self.stash.take().unwrap_or_default();
                self.set_text(&s);
                self.hist_pos = None;
                self.mark_persistence_change();
            }
        }
        self.reverse_search = None;
    }

    /// Ctrl-R: search toward older entries using the text present at the first press as a literal
    /// substring query. An empty query walks every entry newest-first. A miss leaves the current
    /// buffer untouched and returns `false` so the frontend can give unobtrusive feedback.
    pub fn reverse_search_previous(&mut self) -> bool {
        let (query, before) = self
            .reverse_search
            .as_ref()
            .map(|search| (search.query.clone(), search.before))
            .unwrap_or_else(|| (self.text(), self.history.len()));
        let Some(index) = self.history[..before]
            .iter()
            .rposition(|entry| entry.contains(&query))
        else {
            return false;
        };
        let entry = self.history[index].clone();
        self.set_text(&entry);
        self.hist_pos = Some(index);
        self.reverse_search = Some(ReverseSearch {
            query,
            before: index,
        });
        self.mark_persistence_change();
        true
    }

    fn set_from_history(&mut self, i: usize) {
        let s = self.history[i].clone();
        self.set_text(&s);
        self.hist_pos = Some(i);
    }

    fn set_text(&mut self, s: &str) {
        self.buf = s.chars().collect();
        self.cursor = self.buf.len();
        self.reconcile_tagged_chips();
    }

    fn clear_current(&mut self) {
        let text_changed = !self.buf.is_empty();
        self.buf.clear();
        self.cursor = 0;
        self.hist_pos = None;
        self.stash = None;
        self.attachments.clear();
        self.files.clear();
        self.chip_order.clear();
        // Pasted blocks are draft state, cleared with the draft that referenced them. A tag that
        // outlives its draft — in a restored line, or typed from memory — is answered by the
        // visible "content no longer available" marker, never by a later paste's bytes.
        self.pastes.clear();
        self.reverse_search = None;
        if text_changed {
            self.mark_persistence_change();
        }
    }

    /// Clear the input (e.g. /clear or Ctrl-C on an empty-ish line) without touching history.
    /// Ordinary clears intentionally discard any recoverable draft.
    pub fn clear(&mut self) {
        self.recently_cleared = None;
        self.clear_current();
    }

    /// Clear the current non-empty input while retaining one bounded draft for explicit recovery.
    /// Drafts larger than 64 KiB in UTF-8 are still cleared but are deliberately not retained.
    /// Calling this on an already-empty editor leaves the existing recovery slot intact.
    pub fn clear_recoverable(&mut self) {
        if !self.buf.is_empty() {
            let fits = self
                .buf
                .iter()
                .try_fold(0_usize, |bytes, c| {
                    bytes.checked_add(c.len_utf8()).filter(|next| {
                        *next
                            <= iteron_tunables::param_integer(
                                "cli.editor.max_recoverable_draft_bytes",
                                MAX_RECOVERABLE_DRAFT_BYTES,
                            )
                    })
                })
                .is_some();
            self.recently_cleared = fits.then(|| self.text());
        }
        self.clear_current();
    }

    /// Restore and consume the most recently recoverable clear, but never overwrite current input.
    pub fn restore_recently_cleared(&mut self) -> bool {
        if !self.buf.is_empty() {
            return false;
        }
        let Some(draft) = self.recently_cleared.take() else {
            return false;
        };
        self.set_text(&draft);
        self.hist_pos = None;
        self.stash = None;
        self.reverse_search = None;
        self.mark_persistence_change();
        true
    }

    pub fn has_recently_cleared(&self) -> bool {
        self.recently_cleared.is_some()
    }

    /// Whether pressing Enter should submit vs insert a newline. A trailing backslash is a
    /// line-continuation (submit later); it is stripped by `take_submit`.
    pub fn wants_continuation(&self) -> bool {
        self.buf.last() == Some(&'\\')
    }

    /// Take the current line for submission: returns it (backslash-continuations joined, paste tags
    /// expanded, image anchors resolved), pushes a non-empty, non-duplicate entry to history, and
    /// clears the buffer.
    ///
    /// A live image anchor survives into the returned text on purpose — it is the marker the image
    /// segments' order answers, and it is therefore part of what was sent, so it is also part of
    /// what history recalls. Recalling such a line and sending it again degrades the anchor to the
    /// visible "attachment no longer available" form, which is the truth: that draft's images went
    /// with that draft.
    /// Exactly the text [`Self::take_submit`] would return, and nothing else: no history entry, no
    /// clear, no persistence tick.
    ///
    /// A caller that must decide whether a submission is admissible BEFORE consuming the draft needs
    /// the expanded bytes to decide on — the raw buffer is a different length, and a check against
    /// it would admit a submission the real one rejects. Peeking is how a rejected queue attempt
    /// leaves the draft, its pasted blocks and its chips exactly where the operator left them.
    pub fn submission_text(&self) -> String {
        // Join backslash-newline continuations into spaces-free logical lines: a trailing `\` before
        // a newline (or at end) is removed.
        let raw: String = self.buf.iter().collect();
        let joined = raw.replace("\\\n", "\n"); // keep explicit newlines; only the marker is dropped
        // Expansion is last, on the joined line, so a pasted block that happens to end in `\` is
        // submitted as the bytes it is rather than as a continuation marker. What leaves here is
        // the real text: the tag is a composer affordance and must not outlive the composer, in
        // the submission or in the history the operator recalls with ↑.
        crate::paste_input::expand(
            joined.trim_end_matches('\\'),
            &self.pastes,
            &self.attachments,
            &self.files,
        )
    }

    pub fn take_submit(&mut self) -> String {
        let out = self.submission_text();
        let trimmed = out.trim();
        if !trimmed.is_empty() && self.history.last().map(|h| h.as_str()) != Some(out.as_str()) {
            self.history.push(out.clone());
        }
        self.clear();
        out
    }

    /// Adopt already-scrubbed, bounded state from the persistence adapter. A restored draft never
    /// carries attachments, pasted blocks, recovery state, or navigation state across process
    /// boundaries — a tag that survives in the restored text resolves to the visible
    /// "content no longer available" marker rather than to whatever this process pastes next.
    pub fn restore_persisted(&mut self, history: Vec<String>, draft: Option<String>) {
        self.history = history;
        self.buf = draft.unwrap_or_default().chars().collect();
        self.cursor = self.buf.len();
        self.hist_pos = None;
        self.stash = None;
        self.recently_cleared = None;
        self.attachments.clear();
        self.files.clear();
        self.chip_order.clear();
        self.pastes.clear();
        self.reverse_search = None;
        self.persistence_revision = 0;
        self.refresh_draft_shape();
        // All stores promise that an id names a moment, and keep that promise with a counter
        // that a restart destroys. The restored text is the only surviving evidence of the previous
        // process's ids, so step the counters past every id it names: without this, the first paste
        // or screenshot of a fresh process would answer a stale placeholder with unrelated content.
        let restored = self.text();
        for found in crate::paste_input::find_tags(&restored) {
            match found.kind {
                crate::paste_input::TagKind::PastedText => self.pastes.reserve_id(found.id),
                crate::paste_input::TagKind::Image => self.attachments.reserve_id(found.id),
                crate::paste_input::TagKind::File => self.files.reserve_id(found.id),
            }
        }
    }

    /// Replace composer text after a trusted external-editor round trip. Every tag-backed chip
    /// survives only when the returned text still names it, under the same invariant as keyboard
    /// deletion.
    pub fn replace_text(&mut self, text: &str) {
        self.buf.clear();
        self.cursor = 0;
        self.leave_navigation();
        self.buf.extend(sanitize_foreign_text(text).chars());
        self.cursor = self.buf.len();
        self.reconcile_tagged_chips();
        self.mark_persistence_change();
    }

    /// Text-only snapshot. Image bytes and paths never enter prompt history.
    pub fn persistence_state(&self) -> crate::prompt_history::State {
        crate::prompt_history::State::new(
            self.history.clone(),
            (!self.buf.is_empty()).then(|| self.text()),
        )
    }

    pub fn persistence_revision(&self) -> u64 {
        self.persistence_revision
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    fn leave_navigation(&mut self) {
        self.hist_pos = None;
        self.stash = None;
        self.reverse_search = None;
    }

    fn mark_persistence_change(&mut self) {
        self.persistence_revision = self.persistence_revision.wrapping_add(1);
        self.refresh_draft_shape();
    }

    fn refresh_draft_shape(&mut self) {
        // The command/path discriminator itself refuses tokens past 4 KiB. Mirror that ceiling so
        // one key in a MiB draft never causes a full-buffer scan merely to refresh footer intent.
        let prefix = self
            .buf
            .iter()
            .copied()
            .skip_while(|character| character.is_whitespace())
            .take(4 * 1024 + 1)
            .collect::<String>();
        let trimmed = prefix.trim_start();
        if trimmed.starts_with('!') {
            self.draft_shape = DraftShape::Shell;
            return;
        }
        let Some(command) = crate::commands::slash_command_body(trimmed, &|_| false) else {
            self.draft_shape = if trimmed.starts_with('/') {
                DraftShape::PathLike
            } else {
                DraftShape::Prose
            };
            return;
        };
        let immediate_while_running = crate::commands::dispatch(command).is_ok_and(|routed| {
            matches!(
                routed.route,
                crate::commands::DispatchRoute::InProcess(
                    crate::commands::SlashCommand::Mcp | crate::commands::SlashCommand::Status
                )
            )
        });
        self.draft_shape = DraftShape::Slash {
            immediate_while_running,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed(s: &str) -> Editor {
        let mut e = Editor::new();
        e.insert_str(s);
        e
    }

    /// The smallest byte string that sniffs as a real image, so these tests exercise the attachment
    /// path rather than a stub.
    const GIF: &[u8] = b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;";

    #[test]
    fn insert_and_cursor() {
        let e = ed("hello");
        assert_eq!(e.text(), "hello");
        assert_eq!(e.cursor(), 5);
    }

    #[test]
    fn paste_strips_control_and_escape_chars_but_keeps_newline_and_multibyte() {
        // A paste carrying a raw ESC, a bell, a backspace, a CR, and a zero-width space must land as
        // clean text — no raw control bytes to corrupt column math (the 乱码 regression). Newlines,
        // tabs, CJK, and emoji survive intact and the cursor counts CHARS, not bytes.
        let mut e = Editor::new();
        e.insert_str("a\x1b\x07\x08\r\nb\u{200b}写\t🎉");
        assert_eq!(
            e.text(),
            "a\nb写\t🎉",
            "control/escape/zero-width stripped, content kept"
        );
        // cursor is a char index over the sanitized text (6 chars: a \n b 写 \t 🎉)
        assert_eq!(e.cursor(), 6);
        assert!(!e.text().contains('\x1b'), "no raw ESC survived");
        assert!(
            !e.text().contains('\u{200b}'),
            "no zero-width char survived"
        );
    }

    #[test]
    fn cursor_movement_and_insert_in_middle() {
        let mut e = ed("helo");
        e.left(); // cursor at 3 (before 'o')... "hel|o"
        e.insert('l'); // "hell|o"
        assert_eq!(e.text(), "hello");
    }

    #[test]
    fn explicit_cursor_placement_clamps_and_leaves_history_browsing() {
        let mut e = ed("abc");
        e.set_cursor(1);
        e.insert('X');
        assert_eq!(e.text(), "aXbc");
        e.set_cursor(usize::MAX);
        assert_eq!(e.cursor(), e.text().chars().count());

        e.take_submit();
        e.insert_str("draft");
        e.history_prev();
        e.set_cursor(0);
        e.insert('!');
        e.history_prev();
        assert_eq!(
            e.text(),
            "aXbc",
            "editing after a mouse-style placement exits history browsing"
        );
    }

    #[test]
    fn home_end_and_word_moves() {
        let mut e = ed("the quick brown");
        e.home();
        assert_eq!(e.cursor(), 0);
        e.word_right(); // -> after "the"
        assert_eq!(e.cursor(), 3);
        e.word_right(); // -> after " quick"
        assert_eq!(e.cursor(), 9);
        e.end();
        assert_eq!(e.cursor(), 15);
        e.word_left(); // -> before "brown"
        assert_eq!(e.cursor(), 10);
    }

    #[test]
    fn backspace_delete_and_kills() {
        let mut e = ed("hello world");
        e.delete_word_before(); // removes "world"
        assert_eq!(e.text(), "hello ");
        let mut e2 = ed("hello world");
        e2.home();
        e2.kill_to_end();
        assert_eq!(e2.text(), "");
        let mut e3 = ed("hello world");
        e3.kill_to_start();
        assert_eq!(e3.text(), "");
        let mut e4 = ed("abc");
        e4.home();
        e4.delete(); // forward-delete 'a'
        assert_eq!(e4.text(), "bc");
    }

    #[test]
    fn multibyte_cursor_is_correct() {
        let mut e = ed("héllo"); // é is one char
        e.home();
        e.right();
        e.right(); // cursor after 'é'
        e.insert('X');
        assert_eq!(e.text(), "héXllo");
    }

    #[test]
    fn cursor_and_deletion_never_split_extended_graphemes() {
        let family = "👨‍👩‍👧‍👦";
        let flag = "🇺🇳";
        let plane = "✈️";
        let mut e = ed(&format!("A{family}{flag}{plane}东京"));

        // The compatibility API still accepts scalar offsets, but an offset in the middle of a
        // ZWJ family snaps to its leading edge instead of exposing an impossible terminal cursor.
        e.set_cursor(3);
        assert_eq!(e.cursor(), 1);
        e.right();
        assert_eq!(e.cursor(), 1 + family.chars().count());
        e.delete();
        assert_eq!(e.text(), format!("A{family}{plane}东京"));
        e.backspace();
        assert_eq!(e.text(), format!("A{plane}东京"));

        e.end();
        e.left();
        assert_eq!(e.span(e.cursor(), usize::MAX), "京");
        e.left();
        assert_eq!(e.span(e.cursor(), usize::MAX), "东京");
    }

    #[test]
    fn foreign_text_preserves_joiners_variation_selectors_and_flags() {
        let source = "👨‍👩‍👧‍👦 🇺🇳 ✈️";
        let e = ed(source);
        assert_eq!(e.text(), source);
        assert_eq!(e.cursor(), source.chars().count());
    }

    #[test]
    fn attachment_chips_are_bounded_draft_state_not_text_history() {
        let mut editor = ed("describe");
        editor.attach_image_bytes("clipboard", GIF).unwrap();
        assert!(editor.has_submission());
        assert_eq!(editor.attachments().len(), 1);
        assert_eq!(
            editor.text(),
            "describe[Image #1]",
            "the draft carries the anchor; the payload and the file name stay on the chip"
        );
        assert!(!editor.text().contains("GIF89a"));

        assert!(editor.remove_last_attachment());
        assert!(editor.attachments().is_empty());
        assert_eq!(
            editor.text(),
            "describe",
            "removing the chip takes its anchor with it"
        );
        editor.attach_image_bytes("clipboard", GIF).unwrap();
        assert_eq!(editor.take_submit(), "describe[Image #2]");
        assert!(
            editor.attachments().is_empty(),
            "a submitted attachment cannot leak into the next draft"
        );
        editor.history_prev();
        assert_eq!(editor.text(), "describe[Image #2]");
        assert!(editor.attachments().is_empty());
    }

    #[test]
    fn file_chips_are_draft_state_and_removal_follows_the_order_they_appeared() {
        let root = std::env::temp_dir().join(format!("core-editor-chips-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("test workspace");
        std::fs::write(root.join("a.txt"), "alpha").expect("fixture");
        std::fs::write(root.join("b.txt"), "beta").expect("fixture");

        let mut editor = ed("review");
        editor
            .attach_file_path(&root, Path::new("a.txt"))
            .expect("a plain workspace file");
        editor
            .attach_image_bytes("clipboard", GIF)
            .expect("a canonical GIF");
        editor
            .attach_file_path(&root, Path::new("b.txt"))
            .expect("a second workspace file");
        assert_eq!(editor.chip_count(), 3);
        assert_eq!(
            editor.text(),
            "review[File #1][Image #1][File #2]",
            "every chip has one in-line identity tag, while no payload enters the buffer"
        );

        // Newest first, across both kinds: the operator removes what they last saw appear.
        assert!(editor.remove_last_attachment());
        assert_eq!(editor.files().len(), 1);
        assert_eq!(editor.attachments().len(), 1);
        assert!(editor.remove_last_attachment());
        assert_eq!(editor.files().len(), 1);
        assert!(editor.attachments().is_empty());
        assert!(editor.remove_last_attachment());
        assert_eq!(editor.chip_count(), 0);
        assert!(!editor.remove_last_attachment());

        // A submitted draft carries nothing forward. History retains only the visible identity tag,
        // never file contents, and cannot reattach the prior payload.
        editor
            .attach_file_path(&root, Path::new("a.txt"))
            .expect("re-attach");
        assert!(editor.has_submission());
        assert_eq!(editor.take_submit(), "review[File #3]");
        assert!(editor.files().is_empty());
        editor.history_prev();
        assert_eq!(editor.text(), "review[File #3]");
        assert!(editor.files().is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn context_delete_targets_the_visible_text_chip_index() {
        let mut editor = ed("inspect");
        editor
            .attach_context(ContextKind::Diff, "first", "diff one".into())
            .unwrap();
        editor.attach_image_bytes("screen", GIF).unwrap();
        editor
            .attach_context(ContextKind::Lsp, "second", "lsp two".into())
            .unwrap();

        assert!(editor.remove_context(1));
        assert_eq!(editor.files().len(), 1);
        assert_eq!(editor.files().as_slice()[0].kind(), ContextKind::Lsp);
        assert_eq!(editor.attachments().len(), 1);
        assert!(!editor.remove_context(2));
        assert!(
            editor.remove_last_attachment(),
            "global newest is the LSP chip"
        );
        assert!(
            editor.remove_last_attachment(),
            "image remains after both text chips"
        );
        assert_eq!(editor.chip_count(), 0);
    }

    #[test]
    fn deleting_any_text_attachment_tag_removes_its_chip_and_payload() {
        let root = std::env::temp_dir().join(format!(
            "core-editor-text-tag-delete-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("test workspace");
        std::fs::write(root.join("a.txt"), "alpha").expect("fixture");

        let mut file = Editor::new();
        file.attach_file_path(&root, Path::new("a.txt")).unwrap();
        assert_eq!(file.text(), "[File #1]");
        file.backspace();
        assert!(file.text().is_empty());
        assert!(file.files().is_empty());
        assert_eq!(file.chip_count(), 0);

        for kind in [ContextKind::Diff, ContextKind::Ide, ContextKind::Lsp] {
            let mut editor = Editor::new();
            editor
                .attach_context(kind, kind.label(), format!("{kind:?} context"))
                .unwrap();
            assert_eq!(editor.text(), "[File #1]");
            editor.backspace();
            assert!(editor.text().is_empty(), "{kind:?}");
            assert!(editor.files().is_empty(), "{kind:?}");
            assert_eq!(editor.chip_count(), 0, "{kind:?}");
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn history_up_down_with_stash() {
        let mut e = Editor::new();
        e.insert_str("first");
        assert_eq!(e.take_submit(), "first");
        e.insert_str("second");
        assert_eq!(e.take_submit(), "second");
        // start typing a live line, then browse
        e.insert_str("draft");
        e.history_prev(); // -> "second"
        assert_eq!(e.text(), "second");
        e.history_prev(); // -> "first"
        assert_eq!(e.text(), "first");
        e.history_prev(); // clamp at oldest
        assert_eq!(e.text(), "first");
        e.history_next(); // -> "second"
        assert_eq!(e.text(), "second");
        e.history_next(); // -> restore the stashed "draft"
        assert_eq!(e.text(), "draft");
    }

    #[test]
    fn history_dedups_consecutive_and_skips_empty() {
        let mut e = Editor::new();
        e.insert_str("cmd");
        e.take_submit();
        e.insert_str("cmd"); // duplicate
        e.take_submit();
        e.insert_str("   "); // whitespace only
        e.take_submit();
        // only one history entry
        e.history_prev();
        assert_eq!(e.text(), "cmd");
        e.history_prev();
        assert_eq!(e.text(), "cmd"); // no second/empty entry
    }

    #[test]
    fn reverse_search_is_literal_multiline_cjk_and_repeats_toward_older_entries() {
        let mut e = Editor::new();
        e.insert_str("first 写\nline");
        assert_eq!(e.take_submit(), "first 写\nline");
        e.insert_str("second");
        assert_eq!(e.take_submit(), "second");
        e.insert_str("newest 写 result");
        assert_eq!(e.take_submit(), "newest 写 result");

        e.insert_str("写");
        assert!(e.reverse_search_previous());
        assert_eq!(e.text(), "newest 写 result");
        assert!(e.reverse_search_previous());
        assert_eq!(e.text(), "first 写\nline");
        assert!(!e.reverse_search_previous());
        assert_eq!(e.text(), "first 写\nline", "a miss keeps the visible match");
    }

    #[test]
    fn restored_history_and_text_draft_are_searchable_without_attachments() {
        let mut e = Editor::new();
        e.restore_persisted(
            vec!["older".into(), "跨重启 prompt".into()],
            Some("多行 draft\n第二行".into()),
        );
        assert_eq!(e.text(), "多行 draft\n第二行");
        assert!(e.attachments().is_empty());
        assert_eq!(e.persistence_revision(), 0);

        e.clear();
        e.insert_str("跨重启");
        assert!(e.reverse_search_previous());
        assert_eq!(e.text(), "跨重启 prompt");
        assert!(e.persistence_revision() > 0);

        let state = e.persistence_state();
        assert_eq!(state.history, vec!["older", "跨重启 prompt"]);
        assert_eq!(state.draft.as_deref(), Some("跨重启 prompt"));
    }

    #[test]
    fn up_before_history_hydration_is_repeatable_and_preserves_the_live_draft() {
        let mut editor = Editor::new();
        editor.insert_str("typed before history is ready");
        let revision = editor.persistence_revision();
        for _ in 0..8 {
            editor.history_prev();
            assert_eq!(editor.text(), "typed before history is ready");
            assert_eq!(editor.persistence_revision(), revision);
        }

        // Mirror the TUI's late-hydration transaction: install history, then restore newer live
        // input. The earlier Up presses must not leave a stale browse cursor or consume an entry.
        let live = editor.text();
        editor.restore_persisted(vec!["recorded prompt".into()], Some("old draft".into()));
        editor.replace_text(&live);
        editor.history_prev();
        assert_eq!(editor.text(), "recorded prompt");
        editor.history_next();
        assert_eq!(editor.text(), "typed before history is ready");
    }

    #[test]
    fn multiline_newline_and_continuation() {
        let mut e = Editor::new();
        e.insert_str("line one");
        e.newline();
        e.insert_str("line two");
        assert!(e.text().contains('\n'));
        let (row, _col) = e.cursor_row_col();
        assert_eq!(row, 1);
        // trailing backslash requests continuation
        let mut e2 = ed("more\\");
        assert!(e2.wants_continuation());
        assert_eq!(e2.take_submit(), "more");
    }

    #[test]
    fn recoverable_clear_restores_unicode_multiline_once() {
        let draft = "第一行\nemoji 🎉\ne\u{301}";
        let mut e = ed(draft);

        e.clear_recoverable();
        assert!(e.is_empty());
        assert!(e.has_recently_cleared());
        e.insert_str("do not overwrite");
        assert!(!e.restore_recently_cleared());
        assert_eq!(e.text(), "do not overwrite");
        assert!(e.has_recently_cleared());
        e.kill_to_start();
        assert!(e.restore_recently_cleared());
        assert_eq!(e.text(), draft);
        assert!(!e.has_recently_cleared());
        assert!(!e.restore_recently_cleared(), "recovery is consumed once");
    }

    #[test]
    fn oversized_utf8_draft_is_cleared_without_retention() {
        let oversized = "界".repeat(MAX_RECOVERABLE_DRAFT_BYTES / "界".len() + 1);
        assert!(oversized.len() > MAX_RECOVERABLE_DRAFT_BYTES);
        let mut e = ed("previous small draft");
        e.clear_recoverable();
        assert!(e.has_recently_cleared());
        e.insert_str(&oversized);

        e.clear_recoverable();
        assert!(e.is_empty());
        assert!(!e.has_recently_cleared());
        assert!(!e.restore_recently_cleared());
    }

    #[test]
    fn submitting_or_ordinary_clear_discards_recovery() {
        let mut e = ed("old draft");
        e.clear_recoverable();
        e.insert_str("send exactly once");
        assert_eq!(e.take_submit(), "send exactly once");
        assert!(!e.has_recently_cleared());
        assert!(!e.restore_recently_cleared());

        e.insert_str("another draft");
        e.clear_recoverable();
        assert!(e.has_recently_cleared());
        e.clear();
        assert!(!e.has_recently_cleared());
    }

    #[test]
    fn recovery_and_history_live_line_stash_remain_independent() {
        let mut e = Editor::new();
        e.insert_str("first");
        e.take_submit();
        e.insert_str("second");
        e.take_submit();
        e.insert_str("草稿\nline two");
        e.clear_recoverable();

        e.history_prev();
        assert_eq!(e.text(), "second");
        e.history_next();
        assert!(
            e.is_empty(),
            "history restores its own empty live-line stash"
        );
        assert!(
            e.has_recently_cleared(),
            "history does not consume recovery"
        );
        assert!(e.restore_recently_cleared());
        assert_eq!(e.text(), "草稿\nline two");

        e.history_prev();
        assert_eq!(e.text(), "second");
        e.history_next();
        assert_eq!(e.text(), "草稿\nline two");
    }

    #[test]
    fn word_motion_stops_at_punctuation() {
        let mut e = ed("foo.bar");
        e.word_left(); // from end, stop before "bar" (past '.')
        assert_eq!(e.cursor(), 4);
        e.word_left(); // stop before "foo"
        assert_eq!(e.cursor(), 0);
        let mut e2 = ed("src/main.rs");
        e2.home();
        e2.word_right(); // over "src"
        assert_eq!(e2.cursor(), 3);
        let mut e3 = ed("del-this");
        e3.delete_word_before(); // Ctrl-W deletes "this" only (punctuation boundary)
        assert_eq!(e3.text(), "del-");
    }

    #[test]
    fn editing_exits_history_browsing() {
        let mut e = Editor::new();
        e.insert_str("aaa");
        e.take_submit();
        e.insert_str("bbb");
        e.take_submit();
        e.history_prev(); // "bbb"
        e.insert('X'); // editing -> live line "bbbX"
        e.history_prev(); // starts fresh browse from newest, stashing "bbbX"
        assert_eq!(e.text(), "bbb");
        e.history_next();
        assert_eq!(e.text(), "bbbX");
    }

    /// A visual selection's anchor can sit on either side of the cursor, so both primitives take
    /// their bounds unordered. Making the caller normalise them is how a backwards selection
    /// silently deletes nothing, or deletes the wrong span.
    #[test]
    fn a_span_reads_and_deletes_the_same_text_in_either_direction() {
        for (a, b) in [(2usize, 6usize), (6, 2)] {
            let mut e = Editor::new();
            e.insert_str("hello world");
            assert_eq!(e.span(a, b), "llo ", "span({a},{b})");
            e.delete_span(a, b);
            assert_eq!(e.text(), "heworld");
            assert_eq!(
                e.cursor(),
                2,
                "the cursor lands at the start of the removed span"
            );
        }
    }

    #[test]
    fn an_empty_or_out_of_range_span_is_a_no_op_rather_than_a_panic() {
        let mut e = Editor::new();
        e.insert_str("abc");
        assert_eq!(e.span(1, 1), "");
        e.delete_span(1, 1);
        assert_eq!(
            e.text(),
            "abc",
            "an empty selection must not consume a character"
        );
        // A stale anchor past the end is reachable when the buffer shrank under a live selection.
        assert_eq!(e.span(2, 99), "c");
        e.delete_span(2, 99);
        assert_eq!(e.text(), "ab");
        e.delete_span(99, 99);
        assert_eq!(e.text(), "ab");
    }

    #[test]
    fn deleting_a_selection_is_recorded_as_a_change_for_persistence() {
        let mut e = Editor::new();
        e.insert_str("hello");
        let before = e.persistence_revision();
        e.delete_span(0, 2);
        assert_ne!(
            e.persistence_revision(),
            before,
            "a visual delete must not be invisible to draft persistence"
        );
    }

    // ---- pasted-text tags ------------------------------------------------------------------

    /// A block big enough that `paste_input::should_capture` holds it aside.
    fn big_paste() -> String {
        (0..40)
            .map(|line| format!("line {line} of a log nobody wants in their composer"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_large_paste_becomes_one_tag_and_submits_as_the_original_bytes() {
        let pasted = big_paste();
        let mut e = Editor::new();
        e.insert_str("why does this fail? ");
        let capture = e.capture_paste(&pasted).expect("a bounded paste");

        assert_eq!(
            e.text(),
            "why does this fail? [Pasted text #1 +39 lines]",
            "the composer carries a reference, not 40 lines"
        );
        assert_eq!(capture.lines, 39);
        assert_eq!(capture.bytes, pasted.len());

        let submitted = e.take_submit();
        assert_eq!(
            submitted,
            format!("why does this fail? {pasted}"),
            "what the model receives is the pasted bytes, in place"
        );
        assert!(e.text().is_empty());
        assert!(
            e.pastes().is_empty(),
            "the draft's blocks go with the draft"
        );
    }

    #[test]
    fn a_tag_can_be_typed_around_and_still_expands_in_place() {
        let pasted = big_paste();
        let mut e = Editor::new();
        e.capture_paste(&pasted).expect("a bounded paste");
        e.home();
        e.insert_str("read ");
        e.end();
        e.insert_str(" please");
        assert_eq!(e.take_submit(), format!("read {pasted} please"));
    }

    #[test]
    fn two_pastes_keep_their_own_identity() {
        let first = format!("FIRST\n{}", big_paste());
        let second = format!("SECOND\n{}", big_paste());
        let mut e = Editor::new();
        e.capture_paste(&first).expect("first");
        e.insert_str(" then ");
        e.capture_paste(&second).expect("second");
        assert_eq!(
            e.text(),
            format!("[Pasted text #1 +40 lines] then [Pasted text #2 +40 lines]",)
        );
        assert_eq!(e.take_submit(), format!("{first} then {second}"));
    }

    #[test]
    fn backspace_removes_a_whole_tag_and_frees_its_block() {
        let mut e = Editor::new();
        e.insert_str("keep ");
        e.capture_paste(&big_paste()).expect("a bounded paste");
        assert_eq!(e.pastes().len(), 1);

        e.backspace();
        assert_eq!(
            e.text(),
            "keep ",
            "one backspace erases the reference whole, not its closing bracket"
        );
        assert!(e.pastes().is_empty(), "the block goes with its last tag");
        assert_eq!(e.chip_count(), 0, "the held-paste chip goes with its tag");

        // Ordinary text still deletes one character at a time.
        e.backspace();
        assert_eq!(e.text(), "keep");
    }

    #[test]
    fn backspace_in_the_middle_of_a_live_tag_removes_the_tag_and_chip_atomically() {
        let mut e = Editor::new();
        e.capture_paste(&big_paste()).expect("a bounded paste");
        e.left();
        e.backspace();
        assert!(e.text().is_empty());
        assert!(e.pastes().is_empty());
        assert_eq!(e.chip_count(), 0);
    }

    #[test]
    fn a_hand_typed_tag_never_expands_into_another_paste() {
        let secret = format!("SECRET-BODY\n{}", big_paste());
        let mut e = Editor::new();
        e.capture_paste(&secret).expect("a bounded paste");
        assert_eq!(e.take_submit(), secret);

        // The id is gone with the draft that owned it. Typing its tag back must not resurrect it.
        e.insert_str("give me [Pasted text #1]");
        let submitted = e.take_submit();
        assert!(!submitted.contains("SECRET-BODY"), "{submitted}");
        assert_eq!(
            submitted,
            "give me [Pasted text #1 — content no longer available]"
        );
    }

    #[test]
    fn an_oversized_paste_is_refused_whole_and_changes_nothing() {
        let mut e = Editor::new();
        e.insert_str("context: ");
        let oversized = "x".repeat(crate::paste_input::MAX_PASTED_TEXT_BYTES + 1);
        let error = e.capture_paste(&oversized).expect_err("over the bound");
        assert_eq!(
            error.kind(),
            crate::paste_input::PasteInputErrorKind::TooLarge
        );
        assert_eq!(
            e.text(),
            "context: ",
            "a refused paste leaves neither text nor a tag behind"
        );
        assert!(e.pastes().is_empty());
    }

    #[test]
    fn a_captured_paste_is_sanitised_once_and_keeps_its_line_endings() {
        let mut e = Editor::new();
        let raw = format!("a\r\nb\x1b[31mc\rd\u{200b}e\n{}", big_paste());
        e.capture_paste(&raw).expect("a bounded paste");
        let submitted = e.take_submit();
        assert!(
            submitted.starts_with("a\nb[31mc\nde\n"),
            "CRLF and a lone CR are both line endings; ESC and the zero-width space are not: {:?}",
            &submitted[..24]
        );
        assert!(
            !submitted.contains('\u{1b}') && !submitted.contains('\u{200b}'),
            "a control byte must not survive into the terminal or the turn"
        );
    }

    // ---- image anchors, on the same rails ---------------------------------------------------

    #[test]
    fn an_attached_image_anchors_where_the_cursor_is() {
        let mut e = ed("compare this with that");
        e.set_cursor(12); // "compare this| with that"
        e.attach_image_bytes("shot.png", GIF)
            .expect("a canonical GIF");
        assert_eq!(
            e.text(),
            "compare this[Image #1] with that",
            "an image appended silently to the end cannot say where in the argument it belongs"
        );
        assert_eq!(
            e.cursor(),
            22,
            "the operator keeps typing after the anchor, not before it"
        );
        assert_eq!(e.attachments().len(), 1);
        assert_eq!(e.attachments().as_slice()[0].display_name(), "shot.png");
    }

    #[test]
    fn deleting_an_anchor_deletes_its_image_chip_too() {
        let mut e = ed("look at ");
        e.attach_image_bytes("shot.png", GIF)
            .expect("a canonical GIF");
        assert_eq!(e.text(), "look at [Image #1]");

        e.backspace();
        assert_eq!(
            e.text(),
            "look at ",
            "one backspace erases the anchor whole, not its closing bracket"
        );
        assert_eq!(e.attachments().len(), 0);
        assert_eq!(e.chip_count(), 0);
        assert!(
            e.has_submission(),
            "the remaining prose is still a submission"
        );
        assert_eq!(e.take_submit(), "look at ");

        // And ordinary text still deletes one character at a time.
        let mut e = ed("keep");
        e.backspace();
        assert_eq!(e.text(), "kee");
    }

    #[test]
    fn a_selection_touching_part_of_an_image_tag_removes_the_whole_tag_and_chip() {
        let mut e = ed("look at ");
        e.attach_image_bytes("shot.png", GIF)
            .expect("a canonical GIF");
        e.delete_span(10, 12);
        assert_eq!(e.text(), "look at ");
        assert!(e.attachments().is_empty());
        assert_eq!(e.chip_count(), 0);
    }

    #[test]
    fn deleting_the_chip_takes_its_anchor_and_leaves_every_other_anchor_alone() {
        let mut e = ed("first ");
        e.attach_image_bytes("a.png", GIF).expect("a canonical GIF");
        e.insert_str(" then ");
        e.attach_image_bytes("b.png", GIF).expect("a canonical GIF");
        assert_eq!(e.text(), "first [Image #1] then [Image #2]");
        e.home();

        // Alt+backspace removes the newest chip wherever the cursor happens to be.
        assert!(e.remove_last_attachment());
        assert_eq!(
            e.text(),
            "first [Image #1] then ",
            "an anchor for an image nobody is sending points at nothing"
        );
        assert_eq!(e.attachments().len(), 1);
        assert_eq!(
            e.cursor(),
            0,
            "a removal far from the cursor does not move it"
        );
        assert_eq!(e.take_submit(), "first [Image #1] then ");
    }

    #[test]
    fn two_images_keep_distinct_identities_and_the_sentence_orders_them() {
        let mut e = Editor::new();
        e.attach_image_bytes("left.png", GIF)
            .expect("a canonical GIF");
        e.insert_str(" vs ");
        e.attach_image_bytes("right.png", GIF)
            .expect("a canonical GIF");
        assert_eq!(e.text(), "[Image #1] vs [Image #2]");
        let names: Vec<&str> = e
            .attachments()
            .as_slice()
            .iter()
            .map(|attachment| attachment.display_name())
            .collect();
        assert_eq!(
            names,
            vec!["left.png", "right.png"],
            "the file name is how an operator tells two screenshots apart"
        );

        // Moving one anchor is the whole point: the submission order follows the sentence.
        assert_eq!(
            crate::paste_input::anchored_image_ids(&e.text(), e.attachments()),
            vec![1, 2]
        );
        e.home();
        e.insert_str("[Image #2] beats ");
        assert_eq!(
            crate::paste_input::anchored_image_ids(&e.text(), e.attachments()),
            vec![2, 1],
            "an anchor the draft can answer is honoured wherever the operator typed it"
        );
    }

    #[test]
    fn a_hand_typed_anchor_conjures_no_attachment() {
        let mut e = Editor::new();
        e.insert_str("describe [Image #7]");
        assert!(e.attachments().is_empty());
        // Not a deletable unit either: no store answers #7, so it is prose and erases as prose.
        e.backspace();
        assert_eq!(e.text(), "describe [Image #7");
        e.insert(']');

        assert_eq!(
            e.take_submit(),
            "describe [Image #7 — attachment no longer available]",
            "a reference the draft cannot answer degrades visibly rather than reading as live"
        );

        // And an id that a LATER image happens to reuse cannot be answered by it either.
        let mut e = Editor::new();
        e.attach_image_bytes("real.png", GIF)
            .expect("a canonical GIF");
        assert!(e.remove_last_attachment());
        e.insert_str("[Image #1]");
        assert!(
            e.take_submit().contains("no longer available"),
            "ids name a moment; a detached image does not answer for its old number"
        );
    }

    #[test]
    fn a_restored_draft_cannot_have_its_anchors_answered_by_this_process() {
        let mut e = Editor::new();
        e.restore_persisted(Vec::new(), Some("look at [Image #1]".into()));
        assert!(e.attachments().is_empty());
        e.attach_image_bytes("unrelated.png", GIF)
            .expect("a canonical GIF");
        let submitted = e.take_submit();
        assert!(
            submitted.starts_with("look at [Image #1 — attachment no longer available]"),
            "{submitted}"
        );
        assert!(
            submitted.ends_with("[Image #2]"),
            "the image attached in this process gets its own id: {submitted}"
        );
    }

    #[test]
    fn a_paste_tag_and_an_image_anchor_coexist_in_one_sentence() {
        let mut e = Editor::new();
        e.insert_str("compare this screenshot ");
        e.attach_image_bytes("shot.png", GIF)
            .expect("a canonical GIF");
        e.insert_str(" with this log ");
        let log = big_paste();
        e.capture_paste(&log).expect("a bounded paste");
        assert_eq!(
            e.text(),
            "compare this screenshot [Image #1] with this log [Pasted text #1 +39 lines]"
        );
        assert_eq!(
            e.take_submit(),
            format!("compare this screenshot [Image #1] with this log {log}"),
            "the anchor stays as a position marker; the paste becomes its bytes"
        );
    }

    #[test]
    fn a_small_paste_is_not_worth_a_tag() {
        assert!(!crate::paste_input::should_capture("a\nb"));
        let mut e = Editor::new();
        e.insert_str("a\nb");
        assert_eq!(e.text(), "a\nb");
        assert!(e.pastes().is_empty());
    }
}
