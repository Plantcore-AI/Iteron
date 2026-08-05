//! Bounded, frontend-side capture of a large paste as one compact composer tag.
//!
//! This is the third member of the attachment family whose image half lives in
//! [`crate::image_input`] and whose file half lives in [`crate::file_input`], and it is built on
//! the same three rules: bounds are refusals, nothing unsanitised reaches the terminal, and the
//! composer shows a *reference* while the submission carries the payload.
//!
//! It differs from those two in exactly one way, and the difference is deliberate. A file chip is
//! carried out-of-band, in its own protocol field, so the draft text never mentions it. A pasted
//! block is *text going where text goes*, so it must keep its position in the sentence the
//! operator is writing — "here is the log <block>, why does it fail?" is not the same prompt as
//! that log appended at the end. So a paste is represented in-band by a tag inside the draft, and
//! the tag is expanded back to the original bytes at submission.
//!
//! # Image anchors ride the same rails
//!
//! An image has the same positional problem and half the same answer, so it gets the same grammar
//! rather than a second one. `[Image #N]` is scanned by this module's scanner, deleted by this
//! module's end-anchored delete rule, and resolved against the draft's image store exactly as
//! `[Pasted text #N]` is resolved against [`PastedTexts`].
//!
//! It is *half* the same answer because an image is two things on the screen, not one:
//!
//! - the **chip** (`▧ #1 shot.png · 75 B`) is the image's identity and the authority on whether it
//!   is sent. It carries the file name and byte count, which is the only way an operator tells two
//!   screenshots apart, and nothing here may take that away.
//! - the **anchor** (`[Image #1]`) is the authority on *where* in the argument the image belongs,
//!   and nothing else. It is not expanded into bytes — image payloads travel in their own protocol
//!   segments, and [`core_protocol::input::ContentSegments`] is frozen at exactly one text segment
//!   — so the anchor survives into the submitted text as the marker the segment order answers.
//!
//! That split is what decides the two questions an operator will ask. Deleting the *anchor* leaves
//! the image attached and still sent, appended after the anchored ones, which is precisely the
//! behaviour images had before anchors existed; the chip still says so on the screen. Deleting the
//! *chip* (alt+backspace) detaches the image and takes its anchors out of the draft with it,
//! because an anchor for an image that is not being sent is a reference to nothing.
//!
//! Four properties are load-bearing.
//!
//! 1. **The tag is a reference, and the store is the authority.** Tag text is not evidence.
//!    A tag whose id the store does not hold expands to a visible
//!    `[Pasted text #N — content no longer available]`, never to some other paste's content and
//!    never to silence. That is what makes a hand-typed lookalike harmless: it can name an id,
//!    but it cannot conjure an entry. An image anchor is held to the same standard by the same
//!    rule: a hand-typed `[Image #7]` degrades to `[Image #7 — attachment no longer available]`
//!    and attaches nothing.
//! 2. **Bounds are refusals.** A paste over the per-paste or aggregate bound is refused whole,
//!    with the operator told how big it was. Nothing is silently shortened: half a stack trace
//!    reads as a whole one, and answering confidently from half a log is worse than not
//!    answering.
//! 3. **Admission sanitises once, expansion copies verbatim.** Line endings are normalised and
//!    terminal-hostile control/format characters are stripped by the composer's own sanitiser
//!    ([`crate::editor::sanitize_foreign_text`]) at the moment of capture — there is no second
//!    rule here. After that the stored bytes are what expansion emits, byte for byte, so what the
//!    model receives is what the store holds.
//! 4. **Pasted bytes are inert until submission.** Expansion is the *last* step of building a
//!    submission, after `@file(...)`/`@image` mentions have been parsed and cut out of the draft.
//!    Untrusted pasted text therefore cannot name a file mention and make the composer read it.

use std::fmt;
use std::ops::Range;

/// Per-paste ceiling, mirroring [`core_protocol::input::MAX_FILE_TEXT_BYTES`]: one pasted block is
/// bounded exactly like one attached file, because it is the same kind of thing to a turn.
pub const MAX_PASTED_TEXT_BYTES: usize = core_protocol::input::MAX_FILE_TEXT_BYTES;

/// Aggregate ceiling over every live paste on one draft, mirroring
/// [`core_protocol::input::MAX_TOTAL_FILE_TEXT_BYTES`]. It is deliberately below
/// [`core_protocol::task::MAX_TASK_TEXT_BYTES`], so pastes alone can never build a submission the
/// task contract must reject.
pub const MAX_TOTAL_PASTED_TEXT_BYTES: usize = core_protocol::input::MAX_TOTAL_FILE_TEXT_BYTES;

/// How many distinct pasted blocks one draft may hold.
pub const MAX_PASTED_TEXTS: usize = 16;

/// A paste at or below this size is ordinary typing: it lands inline where the operator can see
/// and edit it. Above it, the draft would stop being readable, which is the whole complaint.
const MAX_INLINE_PASTE_BYTES: usize = 800;

/// …and so is a paste that spans more than this many line breaks, however short it is: a 40-line
/// paste of 10-character lines buries the composer just as effectively as one long line.
const MAX_INLINE_PASTE_LINES: usize = 3;

/// The fixed opening of every pasted-text tag. Parsing anchors on this, so it is written once.
const TAG_PREFIX: &str = "[Pasted text #";

/// The fixed opening of every image anchor. The same bracketed `#id` shape as the paste tag, read
/// by the same scanner and deleted by the same rule: a second grammar would be a second set of
/// off-by-one bugs, and the operator would have to learn two delete keys for one idea.
const IMAGE_PREFIX: &str = "[Image #";

/// Which of the two placeholders a match is. They share a scanner but not a resolution rule: a
/// paste tag is replaced by the bytes it stands for, an image anchor stays where it is and is
/// answered by the order of the image segments beside the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagKind {
    PastedText,
    Image,
}

impl TagKind {
    const fn prefix(self) -> &'static str {
        match self {
            Self::PastedText => TAG_PREFIX,
            Self::Image => IMAGE_PREFIX,
        }
    }
}

/// The only thing the placeholder rules need to know about a draft's image store: whether it still
/// holds an id. Keeping the requirement this narrow is what lets this module own the anchor grammar
/// without depending on [`crate::image_input`] — the dependency points one way, as it does for the
/// composer.
pub trait ImageAnchors {
    fn holds_image(&self, id: u32) -> bool;
}

/// A draft with no images at all. Callers that provably have none (and tests about paste tags) say
/// so with `&()` rather than constructing an empty store.
impl ImageAnchors for () {
    fn holds_image(&self, _id: u32) -> bool {
        false
    }
}

/// The draft's image store is the authority behind every `[Image #N]` anchor, exactly as
/// [`PastedTexts`] is the authority behind every `[Pasted text #N]` tag. A hand-typed anchor can
/// name an id; only this answers one.
///
/// The impl lives here rather than beside the type because `crates/cli/src/image_input.rs` is also
/// compiled standalone, as a module of `crates/cli/tests/image_input.rs`, and so cannot name
/// anything else in this crate.
impl ImageAnchors for crate::image_input::ImageAttachments {
    fn holds_image(&self, id: u32) -> bool {
        self.get(id).is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasteInputErrorKind {
    TooLarge,
    TooMany,
    AggregateTooLarge,
}

/// A refused paste, carrying the size that was refused so the operator learns the fact rather than
/// only the verdict.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PasteInputError {
    kind: PasteInputErrorKind,
    bytes: usize,
}

impl PasteInputError {
    #[cfg(test)]
    pub const fn kind(&self) -> PasteInputErrorKind {
        self.kind
    }
}

impl fmt::Display for PasteInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            PasteInputErrorKind::TooLarge => write!(
                formatter,
                "pasted block is {} bytes, over the {MAX_PASTED_TEXT_BYTES}-byte per-paste limit",
                self.bytes
            ),
            PasteInputErrorKind::TooMany => write!(
                formatter,
                "this draft already holds {MAX_PASTED_TEXTS} pasted blocks"
            ),
            PasteInputErrorKind::AggregateTooLarge => write!(
                formatter,
                "pasted block is {} bytes and the draft may hold {MAX_TOTAL_PASTED_TEXT_BYTES} bytes of pasted text in total",
                self.bytes
            ),
        }
    }
}

impl fmt::Debug for PasteInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for PasteInputError {}

/// One admitted pasted block: the tag identity the composer shows and the bytes the submission
/// will carry.
#[derive(Clone, PartialEq, Eq)]
pub struct PastedText {
    id: u32,
    content: String,
    /// Line breaks in the stored content — what the tag announces. Zero means one line.
    lines: usize,
    /// Content fingerprint. Its only job is identity: a re-paste of the same block is the same
    /// block, and gets the same id instead of a second copy of the same bytes.
    digest: u64,
}

impl PastedText {
    pub const fn id(&self) -> u32 {
        self.id
    }

    pub const fn lines(&self) -> usize {
        self.lines
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn bytes(&self) -> usize {
        self.content.len()
    }

    /// The tag that stands for this block in the composer.
    pub fn tag(&self) -> String {
        tag(self.id, self.lines)
    }
}

/// Content-free: a pasted block is operator data and must not reach a log line.
impl fmt::Debug for PastedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PastedText")
            .field("id", &self.id)
            .field("lines", &self.lines)
            .field("bytes", &self.bytes())
            .finish()
    }
}

/// The bounded set of pasted blocks held aside for one draft.
///
/// `next_id` is monotonic for the life of the editor and is *not* reset when the set is cleared:
/// ids name a moment, so a tag left over in a restored draft can never be answered by a later,
/// unrelated paste that happened to reuse the number.
#[derive(Clone, Debug, Default)]
pub struct PastedTexts {
    items: Vec<PastedText>,
    next_id: u32,
    total_bytes: usize,
}

impl PastedTexts {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[cfg(test)]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn get(&self, id: u32) -> Option<&PastedText> {
        self.items.iter().find(|item| item.id == id)
    }

    /// Admit one pasted block, already sanitised by the caller.
    ///
    /// Identical content is the same block: re-pasting returns the existing entry rather than
    /// spending a second slot and a second copy on bytes the draft already holds.
    pub fn store(&mut self, sanitised: String) -> Result<&PastedText, PasteInputError> {
        let bytes = sanitised.len();
        if bytes > MAX_PASTED_TEXT_BYTES {
            return Err(PasteInputError {
                kind: PasteInputErrorKind::TooLarge,
                bytes,
            });
        }
        let digest = digest_of(&sanitised);
        if let Some(index) = self
            .items
            .iter()
            .position(|item| item.digest == digest && item.content == sanitised)
        {
            return Ok(&self.items[index]);
        }
        if self.items.len() >= MAX_PASTED_TEXTS {
            return Err(PasteInputError {
                kind: PasteInputErrorKind::TooMany,
                bytes,
            });
        }
        let total = self.total_bytes.saturating_add(bytes);
        if total > MAX_TOTAL_PASTED_TEXT_BYTES {
            return Err(PasteInputError {
                kind: PasteInputErrorKind::AggregateTooLarge,
                bytes,
            });
        }
        let id = self.next_id.wrapping_add(1);
        self.next_id = id;
        self.total_bytes = total;
        self.items.push(PastedText {
            id,
            lines: count_lines(&sanitised),
            digest,
            content: sanitised,
        });
        Ok(self.items.last().expect("a block was just appended"))
    }

    /// Drop one block by id, freeing its share of the aggregate bound.
    pub fn remove(&mut self, id: u32) -> bool {
        let Some(index) = self.items.iter().position(|item| item.id == id) else {
            return false;
        };
        let item = self.items.remove(index);
        self.total_bytes = self.total_bytes.saturating_sub(item.content.len());
        true
    }

    /// Forget every block. `next_id` deliberately keeps counting: see the type's note.
    pub fn clear(&mut self) {
        self.items.clear();
        self.total_bytes = 0;
    }

    /// Guarantee that no id this store mints from now on is `id` or below.
    ///
    /// "An id names a moment" is a claim about a monotonic counter, and a counter cannot survive a
    /// restart. A restored draft carries tags from a *previous* process whose counter is gone, so
    /// the property is re-established from the only evidence left — the ids the text names.
    pub fn reserve_id(&mut self, id: u32) {
        self.next_id = self.next_id.max(id);
    }
}

/// FNV-1a. A fingerprint for "is this the same block I already hold", not a security primitive —
/// nothing is authorised by it, so a fast, dependency-free hash is the honest choice.
fn digest_of(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Line breaks in `text`, counting `\r\n`, `\r` and `\n` alike — the same count the operator sees
/// announced on the tag.
pub fn count_lines(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut lines = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                lines += 1;
                index += usize::from(bytes.get(index + 1) == Some(&b'\n')) + 1;
            }
            b'\n' => {
                lines += 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    lines
}

/// Reduce every line ending to `\n` *before* sanitising.
///
/// The composer's sanitiser strips `\r` as a control character, which is right for a stray CR in
/// the middle of a line and wrong for a CR that is a line ending: dropping it would silently join
/// two lines of a pasted log. Deciding that here keeps the sanitiser one rule instead of two.
pub fn normalize_newlines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(character);
        }
    }
    out
}

/// Whether a paste is big enough to be worth holding aside.
///
/// Below the thresholds a paste is ordinary typing and stays inline, because a tag the operator
/// cannot read is worse than three lines they can.
pub fn should_capture(text: &str) -> bool {
    text.len() > MAX_INLINE_PASTE_BYTES || count_lines(text) > MAX_INLINE_PASTE_LINES
}

/// The tag for `id`, announcing its size the way the operator will read it back.
pub fn tag(id: u32, lines: usize) -> String {
    if lines == 0 {
        format!("{TAG_PREFIX}{id}]")
    } else {
        format!("{TAG_PREFIX}{id} +{lines} lines]")
    }
}

/// What a tag becomes when the store cannot answer it. Visible degradation, never silence: a
/// prompt that quietly lost a log is a prompt whose answer cannot be trusted.
pub fn missing_tag(id: u32) -> String {
    format!("{TAG_PREFIX}{id} — content no longer available]")
}

/// The in-line anchor that says *where* image `id` belongs in the sentence.
pub fn image_anchor(id: u32) -> String {
    format!("{IMAGE_PREFIX}{id}]")
}

/// What an anchor becomes when the draft no longer holds that image — the image half of
/// [`missing_tag`], and for the same reason: a prompt that points at an attachment nobody sent
/// must say so rather than read as though the attachment were there.
pub fn missing_image_anchor(id: u32) -> String {
    format!("{IMAGE_PREFIX}{id} — attachment no longer available]")
}

/// One placeholder found in draft text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagMatch {
    pub byte_range: Range<usize>,
    pub id: u32,
    pub kind: TagKind,
}

/// Every well-formed placeholder in `text`, in order, of either kind.
///
/// Only the exact shapes this module emits are recognised — `[Pasted text #N]`,
/// `[Pasted text #N +M lines]` and `[Image #N]`. Anything else inside brackets is prose and is left
/// alone. Neither prefix is a substring of the other, so one left-to-right scan that takes whichever
/// prefix comes first cannot mis-attribute a match.
pub fn find_tags(text: &str) -> Vec<TagMatch> {
    let mut found = Vec::new();
    let mut from = 0;
    while from < text.len() {
        let next = [TagKind::PastedText, TagKind::Image]
            .into_iter()
            .filter_map(|kind| {
                text[from..]
                    .find(kind.prefix())
                    .map(|offset| (from + offset, kind))
            })
            .min_by_key(|(start, _)| *start);
        let Some((start, kind)) = next else {
            break;
        };
        let after_prefix = start + kind.prefix().len();
        match parse_tag_body(&text[after_prefix..], kind) {
            Some((id, body_len)) => {
                let end = after_prefix + body_len;
                found.push(TagMatch {
                    byte_range: start..end,
                    id,
                    kind,
                });
                from = end;
            }
            // Not a tag: step past this prefix so an unterminated `[Pasted text #` cannot stall.
            None => from = after_prefix,
        }
    }
    found
}

/// The live image ids named by `text`, in the order their anchors appear and without repeats.
///
/// This is what makes an anchor mean something to the reader on the other end: the submission leads
/// with exactly these images, in exactly this order, so for as far as the list goes "the Nth image
/// beside this text is the Nth one the text points at" is true, and anything the text never named
/// follows behind them. An anchor the store cannot answer names nothing and is skipped here; it has
/// already been rewritten to the visible missing form by [`expand`].
pub fn anchored_image_ids(text: &str, images: &impl ImageAnchors) -> Vec<u32> {
    let mut ordered: Vec<u32> = Vec::new();
    for found in find_tags(text) {
        if found.kind == TagKind::Image
            && images.holds_image(found.id)
            && !ordered.contains(&found.id)
        {
            ordered.push(found.id);
        }
    }
    ordered
}

/// Parse the body after a placeholder's prefix, returning the id and how many bytes were consumed
/// up to and including the `]`.
///
/// `<digits>]` is legal for both kinds. The ` +<digits> lines]` suffix announces a paste's size and
/// is legal only there — an image's size lives on its chip, where the file name is.
fn parse_tag_body(rest: &str, kind: TagKind) -> Option<(u32, usize)> {
    let bytes = rest.as_bytes();
    let mut index = 0;
    let mut id: u32 = 0;
    let mut digits = 0;
    while let Some(byte) = bytes.get(index).filter(|byte| byte.is_ascii_digit()) {
        id = id.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
        digits += 1;
        index += 1;
    }
    if digits == 0 {
        return None;
    }
    if bytes.get(index) == Some(&b']') {
        return Some((id, index + 1));
    }
    if kind == TagKind::Image {
        return None;
    }
    // The ` +<digits> lines]` suffix.
    if bytes.get(index) != Some(&b' ') || bytes.get(index + 1) != Some(&b'+') {
        return None;
    }
    index += 2;
    let mut count_digits = 0;
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        count_digits += 1;
        index += 1;
    }
    if count_digits == 0 {
        return None;
    }
    let suffix = " lines]";
    if rest.len() < index + suffix.len() || &rest[index..index + suffix.len()] != suffix {
        return None;
    }
    Some((id, index + suffix.len()))
}

/// Resolve every placeholder in `text` against the stores that are authoritative for it.
///
/// A paste tag becomes the bytes it stands for. An image anchor that the draft still holds is left
/// exactly as it is — it is a position marker, and the image itself rides beside the text in its own
/// protocol segment — while an anchor for an image the draft no longer holds degrades visibly, the
/// same way an unknown paste id does.
///
/// Rewriting runs from the LAST match backwards so that every range still describes the string it
/// was measured against: a forward pass would have to re-measure after the first substitution, and
/// the version of that loop which forgets to is the one that silently splices a prompt together
/// out of the wrong bytes.
pub fn expand(text: &str, store: &PastedTexts, images: &impl ImageAnchors) -> String {
    let matches = find_tags(text);
    if matches.is_empty() {
        return text.to_owned();
    }
    let mut out = text.to_owned();
    for found in matches.iter().rev() {
        let replacement = match found.kind {
            TagKind::PastedText => match store.get(found.id) {
                Some(block) => block.content().to_owned(),
                None => missing_tag(found.id),
            },
            TagKind::Image => {
                if images.holds_image(found.id) {
                    continue;
                }
                missing_image_anchor(found.id)
            }
        };
        out.replace_range(found.byte_range.clone(), &replacement);
    }
    out
}

/// The placeholder that ends exactly at char index `end` of `chars`, if any: what lets one
/// backspace remove a whole tag or anchor instead of eating its closing bracket.
///
/// Char-indexed because that is the editor buffer's own coordinate system. Only a placeholder one
/// of the stores can answer is treated as one unit — placeholder-ness is a property of the stores,
/// not of the string, so prose that merely looks like one keeps behaving like the prose it is.
pub fn tag_ending_at(
    chars: &[char],
    end: usize,
    store: &PastedTexts,
    images: &impl ImageAnchors,
) -> Option<(Range<usize>, u32, TagKind)> {
    if end == 0 || end > chars.len() || chars[end - 1] != ']' {
        return None;
    }
    let start = chars[..end - 1].iter().rposition(|c| *c == '[')?;
    let candidate: String = chars[start..end].iter().collect();
    let found = find_tags(&candidate);
    let first = found.first()?;
    if first.byte_range.start != 0 || first.byte_range.end != candidate.len() {
        return None;
    }
    let live = match first.kind {
        TagKind::PastedText => store.get(first.id).is_some(),
        TagKind::Image => images.holds_image(first.id),
    };
    live.then_some((start..end, first.id, first.kind))
}

/// What one admitted paste tells the operator: which block it became and how big it was. Copyable
/// and content-free, so the frontend can report it without holding a borrow on the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasteCapture {
    pub id: u32,
    pub lines: usize,
    pub bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_of(blocks: &[&str]) -> PastedTexts {
        let mut store = PastedTexts::default();
        for block in blocks {
            store.store((*block).to_owned()).expect("a small block");
        }
        store
    }

    /// The ids a draft's image store would answer, without a decoder or a file in sight: these
    /// tests are about the grammar, and the grammar only ever asks "do you hold this id".
    struct Held(&'static [u32]);

    impl ImageAnchors for Held {
        fn holds_image(&self, id: u32) -> bool {
            self.0.contains(&id)
        }
    }

    #[test]
    fn line_count_matches_the_announced_shape() {
        assert_eq!(count_lines(""), 0);
        assert_eq!(count_lines("one line"), 0);
        assert_eq!(count_lines("a\nb"), 1);
        assert_eq!(count_lines("a\r\nb"), 1, "CRLF is one break, not two");
        assert_eq!(count_lines("a\rb"), 1, "a lone CR is a break too");
        assert_eq!(count_lines("a\n"), 1);
    }

    #[test]
    fn tag_grammar_round_trips() {
        assert_eq!(tag(1, 0), "[Pasted text #1]");
        assert_eq!(tag(12, 340), "[Pasted text #12 +340 lines]");
        for text in ["[Pasted text #1]", "[Pasted text #12 +340 lines]"] {
            let found = find_tags(text);
            assert_eq!(found.len(), 1, "{text}");
            assert_eq!(found[0].byte_range, 0..text.len(), "{text}");
        }
        assert_eq!(find_tags("[Pasted text #1] and [Pasted text #2]").len(), 2);
    }

    #[test]
    fn near_misses_are_prose_not_tags() {
        for text in [
            "[Pasted text #]",
            "[Pasted text #1",
            "[Pasted text #1 lines]",
            "[Pasted text #1 +]",
            "[Pasted text #1 + lines]",
            "[Pasted text #1 +2 line]",
            "[pasted text #1]",
            "[Image #]",
            "[Image #1",
            "[image #1]",
            "[Images #1]",
            // The line-count suffix announces a paste's size. An image's size is on its chip.
            "[Image #1 +2 lines]",
        ] {
            assert!(find_tags(text).is_empty(), "{text} must not parse as a tag");
        }
    }

    #[test]
    fn both_placeholders_share_one_scanner_and_stay_distinguishable() {
        assert_eq!(image_anchor(3), "[Image #3]");
        let text = format!("compare {} with {} please", image_anchor(3), tag(4, 200));
        let found = find_tags(&text);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].kind, TagKind::Image);
        assert_eq!(found[0].id, 3);
        assert_eq!(found[1].kind, TagKind::PastedText);
        assert_eq!(found[1].id, 4);
        // Ranges are still measured against the string they will be applied to.
        assert_eq!(&text[found[0].byte_range.clone()], "[Image #3]");
        assert_eq!(
            &text[found[1].byte_range.clone()],
            "[Pasted text #4 +200 lines]"
        );
    }

    #[test]
    fn a_live_anchor_survives_expansion_and_a_dead_one_degrades_visibly() {
        let store = store_of(&["LOG-BODY"]);
        let drafted = format!(
            "{} and {} and {}",
            image_anchor(1),
            image_anchor(7),
            tag(1, 0)
        );
        assert_eq!(
            expand(&drafted, &store, &Held(&[1])),
            "[Image #1] and [Image #7 — attachment no longer available] and LOG-BODY",
            "an anchor is a position marker, not a payload; an unheld one names nothing"
        );
    }

    #[test]
    fn anchor_order_is_what_the_submitted_image_order_answers() {
        let text = format!(
            "{} then {} then {} again then {}",
            image_anchor(2),
            image_anchor(1),
            image_anchor(2),
            image_anchor(9)
        );
        assert_eq!(
            anchored_image_ids(&text, &Held(&[1, 2])),
            vec![2, 1],
            "first appearance wins, repeats add nothing, an unheld id names nothing"
        );
        assert!(anchored_image_ids("no anchors here", &Held(&[1])).is_empty());
    }

    #[test]
    fn an_unterminated_prefix_cannot_stall_the_scan() {
        let text = "[Pasted text #x [Pasted text #4 +2 lines] tail";
        let found = find_tags(text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, 4);
    }

    #[test]
    fn store_bounds_are_refusals_not_truncations() {
        let mut store = PastedTexts::default();
        let oversized = "x".repeat(MAX_PASTED_TEXT_BYTES + 1);
        let error = store
            .store(oversized)
            .expect_err("over the per-paste bound");
        assert_eq!(error.kind(), PasteInputErrorKind::TooLarge);
        assert!(store.is_empty(), "a refused paste leaves nothing behind");
        assert_eq!(store.total_bytes(), 0);

        // Aggregate: fill to the ceiling with distinct blocks, then refuse the next one whole.
        let mut store = PastedTexts::default();
        let block = MAX_TOTAL_PASTED_TEXT_BYTES / 2;
        store.store("a".repeat(block)).expect("first half");
        store.store("b".repeat(block)).expect("second half");
        let error = store
            .store("c".repeat(64))
            .expect_err("over the aggregate bound");
        assert_eq!(error.kind(), PasteInputErrorKind::AggregateTooLarge);
        assert_eq!(store.len(), 2);
        assert_eq!(store.total_bytes(), 2 * block);
    }

    #[test]
    fn a_full_draft_refuses_another_block() {
        let mut store = PastedTexts::default();
        for index in 0..MAX_PASTED_TEXTS {
            store.store(format!("block {index}")).expect("small block");
        }
        let error = store.store("one more".to_owned()).expect_err("full");
        assert_eq!(error.kind(), PasteInputErrorKind::TooMany);
        assert_eq!(store.len(), MAX_PASTED_TEXTS);
    }

    #[test]
    fn identical_content_is_the_same_block_and_distinct_content_is_not() {
        let mut store = PastedTexts::default();
        let first = store.store("same".to_owned()).expect("stored").id();
        let again = store.store("same".to_owned()).expect("stored").id();
        let other = store.store("different".to_owned()).expect("stored").id();
        assert_eq!(first, again, "a re-paste is the block already held");
        assert_ne!(first, other);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn expansion_rewrites_from_the_last_tag_backwards() {
        let store = store_of(&["FIRST-BODY", "SECOND-BODY-THAT-IS-MUCH-LONGER"]);
        let drafted = format!("before {} middle {} after", tag(1, 0), tag(2, 0));
        assert_eq!(
            expand(&drafted, &store, &()),
            "before FIRST-BODY middle SECOND-BODY-THAT-IS-MUCH-LONGER after",
            "each range must still describe the string it was measured against"
        );
    }

    #[test]
    fn an_unknown_id_degrades_visibly_instead_of_borrowing_content() {
        let store = store_of(&["MINE"]);
        let expanded = expand("typed [Pasted text #9] by hand", &store, &());
        assert_eq!(
            expanded,
            "typed [Pasted text #9 — content no longer available] by hand"
        );
        assert!(!expanded.contains("MINE"));
    }

    #[test]
    fn only_a_stored_tag_is_one_deletable_unit() {
        let store = store_of(&["body"]);
        let live: Vec<char> = format!("look {}", tag(1, 0)).chars().collect();
        assert_eq!(
            tag_ending_at(&live, live.len(), &store, &()),
            Some((5..live.len(), 1, TagKind::PastedText))
        );
        assert_eq!(
            tag_ending_at(&live, live.len() - 1, &store, &()),
            None,
            "the cursor must be past the closing bracket"
        );

        let typed: Vec<char> = "look [Pasted text #7]".chars().collect();
        assert_eq!(
            tag_ending_at(&typed, typed.len(), &store, &()),
            None,
            "an id the store cannot answer is prose"
        );
        let prose: Vec<char> = "look [see notes]".chars().collect();
        assert_eq!(tag_ending_at(&prose, prose.len(), &store, &()), None);
    }

    #[test]
    fn an_anchor_is_one_deletable_unit_on_the_same_terms() {
        let store = PastedTexts::default();
        let live: Vec<char> = format!("look at {}", image_anchor(1)).chars().collect();
        assert_eq!(
            tag_ending_at(&live, live.len(), &store, &Held(&[1])),
            Some((8..live.len(), 1, TagKind::Image))
        );
        assert_eq!(
            tag_ending_at(&live, live.len(), &store, &Held(&[])),
            None,
            "an anchor for an image the draft does not hold is prose, and deletes as prose"
        );
    }

    #[test]
    fn normalising_line_endings_precedes_stripping_controls() {
        assert_eq!(normalize_newlines("a\r\nb\rc\nd"), "a\nb\nc\nd");
    }

    #[test]
    fn capture_threshold_leaves_ordinary_typing_inline() {
        assert!(!should_capture("a short paste"));
        assert!(!should_capture("one\ntwo\nthree\nfour"));
        assert!(should_capture("one\ntwo\nthree\nfour\nfive"));
        assert!(should_capture(&"x".repeat(MAX_INLINE_PASTE_BYTES + 1)));
    }

    #[test]
    fn a_removed_block_frees_its_share_of_the_bound() {
        let mut store = store_of(&["aaaa", "bb"]);
        assert_eq!(store.total_bytes(), 6);
        assert!(store.remove(1));
        assert_eq!(store.total_bytes(), 2);
        assert!(!store.remove(1), "removing twice is not a second refund");
        assert!(store.get(2).is_some());
    }

    #[test]
    fn ids_are_not_reused_after_a_clear() {
        let mut store = PastedTexts::default();
        let first = store.store("a".to_owned()).expect("stored").id();
        store.clear();
        let second = store.store("b".to_owned()).expect("stored").id();
        assert_ne!(
            first, second,
            "a stale tag must not be answered by a later, unrelated paste"
        );
    }
}
