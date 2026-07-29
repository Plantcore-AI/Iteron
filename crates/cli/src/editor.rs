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

use crate::image_input::{ImageAttachment, ImageAttachments, ImageInputError};
use std::path::Path;

/// A cleared draft is a convenience, not another unbounded transcript. Count source UTF-8 bytes
/// so the retained allocation has a hard, portable ceiling while the editor remains char-based.
const MAX_RECOVERABLE_DRAFT_BYTES: usize = 64 * 1024;

/// True if `c` is a control/format char that must be stripped from pasted input (everything except
/// the newline/tab handled by the caller): the C0/C1 control ranges, DEL, and the zero-width
/// bidi/format controls that corrupt column math and cause overlapping/garbled redraw (乱码).
fn is_stripped_control(c: char) -> bool {
    let u = c as u32;
    matches!(u,
        0x00..=0x1F           // C0 controls incl. ESC (0x1B), CR (0x0D), BEL, BS
        | 0x7F                // DEL
        | 0x80..=0x9F         // C1 controls
        | 0x200B..=0x200F     // zero-width space / joiners / bidi marks
        | 0x202A..=0x202E     // bidi embedding/override
        | 0x2060..=0x2064     // word joiner / invisible operators
        | 0xFEFF              // BOM / zero-width no-break space
    )
}

/// The input line editor. Buffer is `Vec<char>` so cursor math is correct on multibyte input.
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
    /// Bounded, already-sniffed image chips attached to the current draft. They are deliberately
    /// not copied into text history or the recoverable-text slot.
    attachments: ImageAttachments,
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

    pub fn has_submission(&self) -> bool {
        !self.buf.is_empty() || !self.attachments.is_empty()
    }

    pub fn attachments(&self) -> &ImageAttachments {
        &self.attachments
    }

    pub fn attach_image_path(&mut self, path: &Path) -> Result<&ImageAttachment, ImageInputError> {
        self.attachments.attach_path(path)
    }

    pub fn attach_image_bytes(
        &mut self,
        display_label: &str,
        bytes: &[u8],
    ) -> Result<&ImageAttachment, ImageInputError> {
        self.attachments.attach_bytes(display_label, bytes)
    }

    pub fn remove_last_attachment(&mut self) -> bool {
        self.attachments
            .len()
            .checked_sub(1)
            .and_then(|index| self.attachments.remove(index))
            .is_some()
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
        self.hist_pos = None; // editing leaves history-browsing mode
    }

    pub fn insert_str(&mut self, s: &str) {
        // Strip literal control/escape bytes from pasted or completed text (the 乱码 bug): a raw ESC,
        // CR, backspace, bell, or a zero-width bidi/format control would corrupt the buffer's column
        // math and overlap on redraw. Keep only newlines and tabs among the control range; drop the
        // rest. Char-based so a multibyte char is never split.
        for c in s.chars() {
            if c == '\n' || c == '\t' || !is_stripped_control(c) {
                self.insert(c);
            }
        }
    }

    /// Insert a literal newline (multi-line input, e.g. Shift+Enter).
    pub fn newline(&mut self) {
        self.insert('\n');
    }

    // ---- deletion --------------------------------------------------------------------------

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            self.buf.remove(self.cursor);
            self.hist_pos = None;
        }
    }

    /// Forward delete (Delete key).
    pub fn delete(&mut self) {
        if self.cursor < self.buf.len() {
            self.buf.remove(self.cursor);
            self.hist_pos = None;
        }
    }

    /// Ctrl-W: delete the word before the cursor (skip trailing non-word chars, then a word run).
    pub fn delete_word_before(&mut self) {
        let i = self.word_boundary_left();
        self.buf.drain(i..self.cursor);
        self.cursor = i;
        self.hist_pos = None;
    }

    /// Ctrl-U: delete from the start of the line to the cursor.
    pub fn kill_to_start(&mut self) {
        self.buf.drain(0..self.cursor);
        self.cursor = 0;
        self.hist_pos = None;
    }

    /// Ctrl-K: delete from the cursor to the end of the line.
    pub fn kill_to_end(&mut self) {
        self.buf.drain(self.cursor..);
        self.hist_pos = None;
    }

    // ---- cursor movement -------------------------------------------------------------------

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }
    pub fn right(&mut self) {
        if self.cursor < self.buf.len() {
            self.cursor += 1;
        }
    }
    pub fn home(&mut self) {
        self.cursor = 0;
    }
    pub fn end(&mut self) {
        self.cursor = self.buf.len();
    }

    /// Place the cursor at an explicit character boundary.
    ///
    /// Mouse hit-testing lives in the terminal adapter, which converts a screen cell back into a
    /// character index before calling this method. Clamp here as the final invariant so a stale
    /// layout (for example, a resize arriving beside a click) can never manufacture an invalid
    /// slice boundary.
    pub fn set_cursor(&mut self, char_index: usize) {
        self.cursor = char_index.min(self.buf.len());
        self.hist_pos = None;
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
        self.cursor = self.word_boundary_left();
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
        self.cursor = i;
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
    }

    /// ↓: move forward in history; past the newest entry restores the stashed live line.
    pub fn history_next(&mut self) {
        match self.hist_pos {
            None => {}
            Some(i) if i + 1 < self.history.len() => self.set_from_history(i + 1),
            Some(_) => {
                // past the newest -> restore the stash and leave history mode
                let s = self.stash.take().unwrap_or_default();
                self.set_text(&s);
                self.hist_pos = None;
            }
        }
    }

    fn set_from_history(&mut self, i: usize) {
        let s = self.history[i].clone();
        self.set_text(&s);
        self.hist_pos = Some(i);
    }

    fn set_text(&mut self, s: &str) {
        self.buf = s.chars().collect();
        self.cursor = self.buf.len();
    }

    fn clear_current(&mut self) {
        self.buf.clear();
        self.cursor = 0;
        self.hist_pos = None;
        self.stash = None;
        self.attachments.clear();
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
                    bytes
                        .checked_add(c.len_utf8())
                        .filter(|next| *next <= MAX_RECOVERABLE_DRAFT_BYTES)
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

    /// Take the current line for submission: returns it (backslash-continuations joined), pushes a
    /// non-empty, non-duplicate entry to history, and clears the buffer.
    pub fn take_submit(&mut self) -> String {
        // Join backslash-newline continuations into spaces-free logical lines: a trailing `\` before
        // a newline (or at end) is removed.
        let raw: String = self.buf.iter().collect();
        let joined = raw.replace("\\\n", "\n"); // keep explicit newlines; only the marker is dropped
        let out = joined.trim_end_matches('\\').to_string();
        let trimmed = out.trim();
        if !trimmed.is_empty() && self.history.last().map(|h| h.as_str()) != Some(out.as_str()) {
            self.history.push(out.clone());
        }
        self.clear();
        out
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

    #[test]
    fn insert_and_cursor() {
        let e = ed("hello");
        assert_eq!(e.text(), "hello");
        assert_eq!(e.cursor(), 5);
    }

    #[test]
    fn paste_strips_control_and_escape_chars_but_keeps_newline_and_multibyte() {
        // A paste carrying a raw ESC, a bell, a backspace, a CR, and a zero-width joiner must land as
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
    fn attachment_chips_are_bounded_draft_state_not_text_history() {
        let mut editor = ed("describe");
        editor
            .attach_image_bytes(
                "clipboard",
                b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;",
            )
            .unwrap();
        assert!(editor.has_submission());
        assert_eq!(editor.attachments().len(), 1);
        assert_eq!(editor.text(), "describe");

        assert!(editor.remove_last_attachment());
        assert!(editor.attachments().is_empty());
        editor
            .attach_image_bytes(
                "clipboard",
                b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;",
            )
            .unwrap();
        assert_eq!(editor.take_submit(), "describe");
        assert!(
            editor.attachments().is_empty(),
            "a submitted attachment cannot leak into the next draft"
        );
        editor.history_prev();
        assert_eq!(editor.text(), "describe");
        assert!(editor.attachments().is_empty());
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
}
