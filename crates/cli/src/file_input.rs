//! Bounded, frontend-side loading of explicitly named workspace files as first-class chips.
//!
//! This is the file half of the attachment path whose image half lives in [`crate::image_input`],
//! and it is deliberately built out of that module's parts rather than beside them: the same
//! single-flight bounded reader, the same terminal-safe display names, the same "refuse, never
//! shorten" rule when something does not fit.
//!
//! Three properties are load-bearing.
//!
//! 1. **A chip names exactly what a tool call could have named.** Every path is resolved by
//!    [`iteron_tools::resolve_in_root`], the same function `read_file` routes through, so the
//!    composer and the tool can never disagree about which bytes a path means. Since 2026-08-05
//!    that function addresses the host rather than confining to the workspace, and this module
//!    follows it rather than keeping a second, stricter rule of its own.
//! 2. **Bounds are refusals.** A file over the per-file or aggregate bound produces an error the
//!    operator sees; it is never attached in part. A half-attached file reads as a complete one to
//!    a model, and answering confidently from half a file is worse than not answering.
//! 3. **Nothing unsanitised reaches the terminal.** Chip labels are
//!    [`crate::image_input::SafeDisplayName`]; workspace-relative paths are proven free of control
//!    and bidi-format characters by `iteron_protocol`'s own validation before they can be built.

use crate::image_input::{ImageInputErrorKind, SafeDisplayName, read_path_capped};
use iteron_protocol::input::{
    FileContent, MAX_FILE_TEXT_BYTES, MAX_INPUT_FILES, MAX_TOTAL_FILE_TEXT_BYTES,
};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

/// Longest `@file(...)` reference this parser will look at before giving up on the token.
const MAX_PATH_INPUT_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileInputErrorKind {
    InvalidLimits,
    InvalidReference,
    OutsideWorkspace,
    TooManyMentions,
    TooManyAttachments,
    AlreadyAttached,
    OpenFailed,
    ReadFailed,
    ReaderBusy,
    ReadTimedOut,
    FileTooLarge,
    AggregateTooLarge,
    NotText,
}

/// Provenance class for text carried by a context chip. All four variants become the same bounded
/// provider-neutral `FileContent` on the SQ, but retaining the class lets the composer state what
/// the bytes mean instead of flattening a diff or language-server answer into a pretend file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextKind {
    File,
    Diff,
    Ide,
    Lsp,
}

impl ContextKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Diff => "diff",
            Self::Ide => "IDE",
            Self::Lsp => "LSP",
        }
    }

    pub const fn glyph(self) -> &'static str {
        match self {
            Self::File => "▤",
            Self::Diff => "±",
            Self::Ide => "⌖",
            Self::Lsp => "λ",
        }
    }

    const fn path_component(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Diff => "diff",
            Self::Ide => "ide",
            Self::Lsp => "lsp",
        }
    }
}

impl FileInputErrorKind {
    /// Translate a shared-reader outcome. Only the outcomes that describe *reading a path* are
    /// mapped; anything image-specific has no meaning here and would be a caller bug, so it lands
    /// on the generic read failure rather than inventing a file-shaped story for it.
    fn from_read(kind: ImageInputErrorKind) -> Self {
        match kind {
            ImageInputErrorKind::OpenFailed => Self::OpenFailed,
            ImageInputErrorKind::ReaderBusy => Self::ReaderBusy,
            ImageInputErrorKind::ReadTimedOut => Self::ReadTimedOut,
            _ => Self::ReadFailed,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FileInputError {
    kind: FileInputErrorKind,
    name: Option<SafeDisplayName>,
}

impl FileInputError {
    fn unnamed(kind: FileInputErrorKind) -> Self {
        Self { kind, name: None }
    }

    fn named(kind: FileInputErrorKind, name: SafeDisplayName) -> Self {
        Self {
            kind,
            name: Some(name),
        }
    }

    #[cfg(test)]
    pub const fn kind(&self) -> FileInputErrorKind {
        self.kind
    }
}

impl fmt::Display for FileInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            FileInputErrorKind::InvalidLimits => "invalid file attachment limits",
            FileInputErrorKind::InvalidReference => "invalid local file reference",
            FileInputErrorKind::OutsideWorkspace => "could not resolve file path",
            FileInputErrorKind::TooManyMentions => "too many file mentions",
            FileInputErrorKind::TooManyAttachments => "too many file attachments",
            FileInputErrorKind::AlreadyAttached => "file is already attached",
            FileInputErrorKind::OpenFailed => "could not open file",
            FileInputErrorKind::ReadFailed => "could not read file",
            FileInputErrorKind::ReaderBusy => "another attachment read is still in progress",
            FileInputErrorKind::ReadTimedOut => "file read timed out",
            FileInputErrorKind::FileTooLarge => "file exceeds the per-file limit",
            FileInputErrorKind::AggregateTooLarge => "files exceed the aggregate limit",
            FileInputErrorKind::NotText => "file is not UTF-8 text",
        };
        formatter.write_str(message)?;
        if let Some(name) = &self.name {
            write!(formatter, ": {name}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for FileInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for FileInputError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileLoadLimits {
    max_attachments: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
}

impl FileLoadLimits {
    #[allow(
        dead_code,
        reason = "kept as a lower-limit test seam while production uses the protocol maxima"
    )]
    pub fn new(
        max_attachments: usize,
        max_file_bytes: usize,
        max_total_bytes: usize,
    ) -> Result<Self, FileInputError> {
        if max_attachments == 0
            || max_attachments > MAX_INPUT_FILES
            || max_file_bytes == 0
            || max_file_bytes > MAX_FILE_TEXT_BYTES
            || max_total_bytes == 0
            || max_total_bytes > MAX_TOTAL_FILE_TEXT_BYTES
        {
            return Err(FileInputError::unnamed(FileInputErrorKind::InvalidLimits));
        }
        Ok(Self {
            max_attachments,
            max_file_bytes,
            max_total_bytes,
        })
    }
}

impl Default for FileLoadLimits {
    fn default() -> Self {
        Self {
            max_attachments: MAX_INPUT_FILES,
            max_file_bytes: MAX_FILE_TEXT_BYTES,
            max_total_bytes: MAX_TOTAL_FILE_TEXT_BYTES,
        }
    }
}

/// One admitted file chip: a terminal-safe label for the composer and the validated payload the
/// submission will carry.
#[derive(Clone, PartialEq, Eq)]
pub struct FileAttachment {
    id: u32,
    kind: ContextKind,
    display_name: SafeDisplayName,
    content: FileContent,
    digest: String,
}

impl FileAttachment {
    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn kind(&self) -> ContextKind {
        self.kind
    }

    pub fn display_name(&self) -> &str {
        self.display_name.as_str()
    }

    /// The workspace-relative path this chip resolved to. Safe to print: `iteron_protocol` refused
    /// it otherwise.
    pub fn relative_path(&self) -> &str {
        &self.content.path
    }

    pub fn text_bytes(&self) -> usize {
        self.content.text.len()
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Exact bytes that `to_file_contents` will submit. Callers may render a bounded preview, but
    /// the digest and byte count always describe this complete string rather than the preview.
    pub fn text(&self) -> &str {
        &self.content.text
    }
}

impl fmt::Debug for FileAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileAttachment")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("display_name", &self.display_name())
            .field("relative_path", &self.relative_path())
            .field("text_bytes", &self.text_bytes())
            .field("digest", &self.digest)
            .finish()
    }
}

/// The bounded set of file chips on one draft.
#[derive(Clone)]
pub struct FileAttachments {
    limits: FileLoadLimits,
    items: Vec<FileAttachment>,
    /// Monotonic for the editor lifetime. An id names one attachment moment and is never reused.
    next_id: u32,
    text_bytes: usize,
}

impl FileAttachments {
    pub fn new(limits: FileLoadLimits) -> Self {
        Self {
            limits,
            items: Vec::new(),
            next_id: 0,
            text_bytes: 0,
        }
    }

    pub fn as_slice(&self) -> &[FileAttachment] {
        &self.items
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn get(&self, id: u32) -> Option<&FileAttachment> {
        self.items.iter().find(|item| item.id == id)
    }

    #[cfg(test)]
    pub fn text_bytes(&self) -> usize {
        self.text_bytes
    }

    /// Attach one workspace file named by the operator.
    ///
    /// `requested` may be absolute or workspace-relative; either way the authority on whether it
    /// may be read is [`iteron_tools::resolve_in_root`], not this function. Everything before that
    /// call only reduces the path to the relative form that call expects, and refuses shapes that
    /// have no relative form at all.
    pub fn attach_path(
        &mut self,
        workspace: &Path,
        requested: &Path,
    ) -> Result<&FileAttachment, FileInputError> {
        self.attach_typed_path(ContextKind::File, workspace, requested)
    }

    /// Snapshot an operator-named text document under an IDE/LSP provenance class. This is the
    /// filesystem handoff used by editor integrations: Core reads and freezes the document now,
    /// then submits those exact bytes even if the integration's scratch file changes later.
    pub fn attach_typed_path(
        &mut self,
        kind: ContextKind,
        workspace: &Path,
        requested: &Path,
    ) -> Result<&FileAttachment, FileInputError> {
        let name = SafeDisplayName::from_path(requested);
        if self.items.len() >= self.limits.max_attachments {
            return Err(FileInputError::named(
                FileInputErrorKind::TooManyAttachments,
                name,
            ));
        }
        let relative = workspace_relative(workspace, requested)
            .map_err(|kind| FileInputError::named(kind, name.clone()))?;
        if self
            .items
            .iter()
            .any(|item| item.relative_path() == relative)
        {
            return Err(FileInputError::named(
                FileInputErrorKind::AlreadyAttached,
                name,
            ));
        }
        // The same resolution `read_file` performs, for the same reason it always was: the chip
        // must attach exactly what the tool would read. It is no longer a containment check.
        let resolved = iteron_tools::resolve_in_root(workspace, &relative).map_err(|_| {
            FileInputError::named(FileInputErrorKind::OutsideWorkspace, name.clone())
        })?;

        let remaining = self.limits.max_total_bytes.saturating_sub(self.text_bytes);
        if remaining == 0 {
            return Err(FileInputError::named(
                FileInputErrorKind::AggregateTooLarge,
                name,
            ));
        }
        let read_limit = self.limits.max_file_bytes.min(remaining);
        // The reader stops one byte past the limit, so "too large" is a fact we can state without
        // ever holding the whole file.
        let bytes = read_path_capped(&resolved, read_limit).map_err(|kind| {
            FileInputError::named(FileInputErrorKind::from_read(kind), name.clone())
        })?;
        if bytes.len() > read_limit {
            let kind = if remaining < self.limits.max_file_bytes {
                FileInputErrorKind::AggregateTooLarge
            } else {
                FileInputErrorKind::FileTooLarge
            };
            return Err(FileInputError::named(kind, name));
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| FileInputError::named(FileInputErrorKind::NotText, name.clone()))?;
        // An embedded NUL is valid UTF-8 and is still not a file anyone reads. `FileContent::new`
        // refuses it either way — this only decides which of two true sentences the operator sees,
        // so the message says "not text" rather than "invalid reference".
        if text.contains('\0') {
            return Err(FileInputError::named(FileInputErrorKind::NotText, name));
        }
        // The protocol re-checks the path shape and the text. A failure here is a reference this
        // contract cannot represent — a name carrying a bidi override, say — not a read failure.
        let content = FileContent::new(relative, text).map_err(|_| {
            FileInputError::named(FileInputErrorKind::InvalidReference, name.clone())
        })?;

        self.admit(kind, name, content)
    }

    /// Attach bytes supplied by a trusted local integration (Git review, IDE selection, or LSP
    /// result). The synthetic path is content-addressed, terminal-safe provenance; the bytes are
    /// still admitted through `FileContent` and the same per-item/aggregate limits as real files.
    pub fn attach_generated(
        &mut self,
        kind: ContextKind,
        display_label: &str,
        text: String,
    ) -> Result<&FileAttachment, FileInputError> {
        if kind == ContextKind::File {
            return Err(FileInputError::unnamed(
                FileInputErrorKind::InvalidReference,
            ));
        }
        let name = SafeDisplayName::from_label(display_label);
        if self.items.len() >= self.limits.max_attachments {
            return Err(FileInputError::named(
                FileInputErrorKind::TooManyAttachments,
                name,
            ));
        }
        if text.len() > self.limits.max_file_bytes {
            return Err(FileInputError::named(
                FileInputErrorKind::FileTooLarge,
                name,
            ));
        }
        if text.len() > self.limits.max_total_bytes.saturating_sub(self.text_bytes) {
            return Err(FileInputError::named(
                FileInputErrorKind::AggregateTooLarge,
                name,
            ));
        }
        if text.contains('\0') {
            return Err(FileInputError::named(FileInputErrorKind::NotText, name));
        }
        let digest = digest_text(&text);
        let path = format!(".core-context/{}/{}.txt", kind.path_component(), digest);
        let content = FileContent::new(path, text).map_err(|_| {
            FileInputError::named(FileInputErrorKind::InvalidReference, name.clone())
        })?;
        self.admit(kind, name, content)
    }

    fn admit(
        &mut self,
        kind: ContextKind,
        name: SafeDisplayName,
        content: FileContent,
    ) -> Result<&FileAttachment, FileInputError> {
        if self
            .items
            .iter()
            .any(|item| item.relative_path() == content.path)
        {
            return Err(FileInputError::named(
                FileInputErrorKind::AlreadyAttached,
                name,
            ));
        }
        self.text_bytes = self
            .text_bytes
            .checked_add(content.text.len())
            .ok_or_else(|| {
                FileInputError::named(FileInputErrorKind::AggregateTooLarge, name.clone())
            })?;
        let digest = digest_text(&content.text);
        let id = self.next_id.checked_add(1).ok_or_else(|| {
            FileInputError::named(FileInputErrorKind::TooManyAttachments, name.clone())
        })?;
        self.next_id = id;
        self.items.push(FileAttachment {
            id,
            kind,
            display_name: name,
            content,
            digest,
        });
        Ok(self.items.last().expect("an attachment was just appended"))
    }

    pub fn remove(&mut self, index: usize) -> Option<FileAttachment> {
        if index >= self.items.len() {
            return None;
        }
        let item = self.items.remove(index);
        self.text_bytes = self.text_bytes.saturating_sub(item.content.text.len());
        Some(item)
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.text_bytes = 0;
    }

    /// Keep future ids distinct from placeholders restored from an earlier process.
    pub fn reserve_id(&mut self, id: u32) {
        self.next_id = self.next_id.max(id);
    }

    pub fn to_file_contents(&self) -> Vec<FileContent> {
        self.items.iter().map(|item| item.content.clone()).collect()
    }
}

fn digest_text(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

impl Default for FileAttachments {
    fn default() -> Self {
        Self::new(FileLoadLimits::default())
    }
}

impl fmt::Debug for FileAttachments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileAttachments")
            .field("limits", &self.limits)
            .field("items", &self.items)
            .field("text_bytes", &self.text_bytes)
            .finish()
    }
}

/// Reduce an operator-named path to the form `resolve_in_root` speaks.
///
/// This never was the containment check, and since 2026-08-05 there is no containment check to be
/// mistaken for: `resolve_in_root` addresses the host. What survives here is presentation — a file
/// under the workspace keeps its short relative name, because that is what the chip and the
/// already-attached comparison display, while anything else keeps its absolute path. The only
/// refusals left are shapes with no usable form at all: a path that does not resolve, and a
/// component that is not UTF-8.
fn workspace_relative(workspace: &Path, requested: &Path) -> Result<String, FileInputErrorKind> {
    // `join` on an absolute `requested` yields `requested`, so this one expression covers a
    // relative name, a `..` climb, and a fully qualified host path alike.
    let resolved = workspace
        .join(requested)
        .canonicalize()
        .map_err(|_| FileInputErrorKind::OpenFailed)?;
    let display = match workspace
        .canonicalize()
        .ok()
        .and_then(|root| resolved.strip_prefix(root).ok().map(Path::to_path_buf))
    {
        Some(relative) => relative,
        None => resolved,
    };

    let mut text = String::new();
    for component in display.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or(FileInputErrorKind::InvalidReference)?;
                if !text.is_empty() && !text.ends_with('/') {
                    text.push('/');
                }
                text.push_str(part);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                // Cannot occur: `display` is either canonical or a prefix-stripped canonical path.
                return Err(FileInputErrorKind::InvalidReference);
            }
            Component::RootDir => text.push('/'),
            Component::Prefix(part) => {
                text.push_str(
                    part.as_os_str()
                        .to_str()
                        .ok_or(FileInputErrorKind::InvalidReference)?,
                );
            }
        }
    }
    if text.is_empty() {
        return Err(FileInputErrorKind::InvalidReference);
    }
    Ok(text)
}

/// One `@file(...)` reference found in composer text.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileMention {
    pub byte_range: Range<usize>,
    path: PathBuf,
}

impl FileMention {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Parse explicit `@file(<path>)` references.
///
/// Only the parenthesised form is recognised. The image parser also accepts bare path tokens
/// because an image path is self-identifying by extension; a file path is not, and a heuristic
/// that attached whatever looked like a path would turn an ordinary sentence into a filesystem
/// read.
pub fn parse_file_mentions(input: &str) -> Result<Vec<FileMention>, FileInputError> {
    if input.len() > iteron_protocol::task::MAX_TASK_TEXT_BYTES {
        return Err(FileInputError::unnamed(
            FileInputErrorKind::InvalidReference,
        ));
    }
    let mut mentions = Vec::new();
    for (start, _) in input.match_indices('@') {
        if !mention_boundary(input, start) {
            continue;
        }
        let Some(inner) = input[start + 1..].strip_prefix("file(") else {
            continue;
        };
        let Some(close) = inner
            .as_bytes()
            .iter()
            .take(MAX_PATH_INPUT_BYTES + 1)
            .position(|byte| *byte == b')')
        else {
            return Err(FileInputError::unnamed(
                FileInputErrorKind::InvalidReference,
            ));
        };
        let candidate = inner[..close].trim();
        if candidate.is_empty() {
            continue;
        }
        if candidate.starts_with('-')
            || candidate.starts_with("~/")
            || candidate.contains("://")
            || candidate.chars().any(char::is_control)
        {
            return Err(FileInputError::unnamed(
                FileInputErrorKind::InvalidReference,
            ));
        }
        mentions.push(FileMention {
            byte_range: start..start + 1 + "file(".len() + close + 1,
            path: PathBuf::from(candidate),
        });
        if mentions.len() > MAX_INPUT_FILES {
            return Err(FileInputError::unnamed(FileInputErrorKind::TooManyMentions));
        }
    }
    Ok(mentions)
}

/// Recognise a whole-input paste that is a drag-and-dropped workspace file.
///
/// Deliberately narrow: only an absolute path already inside `workspace`. A terminal drag-drop
/// produces exactly that, and everything else a person pastes — a sentence, a relative filename, a
/// path elsewhere on the disk — stays text. Widening this to "anything that resolves" would mean a
/// pasted word like `README` silently became a filesystem read instead of a word.
pub fn parse_dropped_file_path(workspace: &Path, pasted: &str) -> Option<PathBuf> {
    let trimmed = pasted.trim();
    let unquoted = trimmed
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
        .or_else(|| {
            trimmed
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .unwrap_or(trimmed);
    if unquoted.is_empty()
        || unquoted.len() > MAX_PATH_INPUT_BYTES
        || unquoted.contains("://")
        || unquoted.chars().any(char::is_control)
    {
        return None;
    }
    let path = Path::new(unquoted);
    if !path.is_absolute() {
        return None;
    }
    // Lexical, and only a gate on "did the operator mean a chip". Whether the path may actually be
    // read is still decided by `FileAttachments::attach_path`.
    path.starts_with(workspace).then(|| path.to_path_buf())
}

fn mention_boundary(input: &str, at: usize) -> bool {
    input[..at]
        .chars()
        .next_back()
        .is_none_or(|character| character.is_whitespace() || "([{'\"".contains(character))
}

/// Bytes of framing this renderer adds per file, excluding the path.
///
/// Kept next to the renderer and asserted against
/// [`iteron_protocol::input::FILE_ATTACHMENT_FRAMING_BYTES`] so the admission bound and the thing it
/// bounds cannot drift.
const RENDER_FRAMING_BYTES: usize =
    "<attached-file path=\"".len() + "\">\n".len() + "\n</attached-file>\n\n".len();

/// Compose the durable submission text for one file-carrying turn.
///
/// Files come first and the operator's instruction last, because the instruction is what the model
/// must still be holding when it starts to answer. The delimiters are framing for a reader, not a
/// security boundary: file text is workspace-trust content either way, and it grants no authority
/// by being quoted here.
pub fn render_attached_files(text: &str, files: &[FileContent]) -> String {
    let mut rendered = String::with_capacity(
        text.len()
            + files
                .iter()
                .map(|file| file.path.len() + file.text.len() + RENDER_FRAMING_BYTES)
                .sum::<usize>(),
    );
    for file in files {
        rendered.push_str("<attached-file path=\"");
        rendered.push_str(&file.path);
        rendered.push_str("\">\n");
        rendered.push_str(&file.text);
        rendered.push_str("\n</attached-file>\n\n");
    }
    rendered.push_str(text);
    rendered
}

/// The renderer must fit inside the per-file framing the protocol charges for it.
///
/// A `const` assertion rather than a test: both sides are compile-time constants, so a runtime
/// `assert!` over them is optimised out and proves nothing. This one fails the build.
const _: () = assert!(
    RENDER_FRAMING_BYTES <= iteron_protocol::input::FILE_ATTACHMENT_FRAMING_BYTES,
    "the renderer must fit inside the per-file framing the protocol charges"
);

#[cfg(test)]
mod tests {
    use super::{
        ContextKind, FileAttachments, FileInputErrorKind, FileLoadLimits, parse_file_mentions,
        render_attached_files,
    };
    use iteron_protocol::input::{
        FILE_ATTACHMENT_FRAMING_BYTES, FileContent, MAX_FILE_TEXT_BYTES, validate_file_submission,
    };
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static NONCE: AtomicU32 = AtomicU32::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "core-file-chip-{label}-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, contents: impl AsRef<[u8]>) -> PathBuf {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("fixture parent");
            }
            std::fs::write(&path, contents).expect("fixture");
            path
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_admitted_chip_carries_a_relative_path_a_safe_label_and_the_whole_file() {
        let root = TestRoot::new("admit");
        root.write("src/main.rs", "fn main() {}\n");
        let mut files = FileAttachments::default();

        let attached = files
            .attach_path(root.path(), Path::new("src/main.rs"))
            .expect("a plain workspace file");
        assert_eq!(attached.relative_path(), "src/main.rs");
        assert_eq!(attached.display_name(), "main.rs");
        assert_eq!(files.to_file_contents()[0].text, "fn main() {}\n");
        assert_eq!(files.text_bytes(), "fn main() {}\n".len());

        // The same file named absolutely is the same chip, and a chip list never holds it twice.
        let absolute = root.path().join("src/main.rs");
        assert_eq!(
            files
                .attach_path(root.path(), &absolute)
                .expect_err("already attached")
                .kind(),
            FileInputErrorKind::AlreadyAttached
        );

        assert!(validate_file_submission("review", &[], &files.to_file_contents()).is_ok());
    }

    #[test]
    fn a_path_outside_the_workspace_attaches_by_every_route_into_it() {
        // Retained inverted (owner-directed 2026-08-05). The chip must attach exactly what
        // `read_file` would read, and `read_file` now reads the host — so every route that used to
        // refuse must now succeed, or the composer and the tool disagree about the same path.
        let root = TestRoot::new("escape");
        let outside = TestRoot::new("escape-outside");
        outside.write("secret.txt", "SECRET");
        root.write("inside.txt", "ok");

        let absolute = outside.path().join("secret.txt");
        // The same file named two ways: a `..` climb out of the workspace, and a fully qualified
        // host path. The relative form is built from the real fixture directory rather than a
        // literal, because these roots carry a pid/sequence suffix.
        let outside_name = outside
            .path()
            .file_name()
            .expect("fixture root has a name")
            .to_string_lossy()
            .into_owned();
        let mut attached = 0usize;
        for reference in [
            PathBuf::from(format!("../{outside_name}/secret.txt")),
            absolute.clone(),
        ] {
            let mut files = FileAttachments::default();
            files
                .attach_path(root.path(), &reference)
                .unwrap_or_else(|error| panic!("{reference:?} must attach: {error:?}"));
            assert_eq!(files.len(), 1, "{reference:?}");
            attached += 1;
        }
        assert_eq!(attached, 2);

        // A symlink that lives inside the workspace and points out of it resolves through to its
        // target, for the same reason: this is `resolve_in_root`, and it follows links now.
        #[cfg(unix)]
        {
            let mut files = FileAttachments::default();
            std::os::unix::fs::symlink(outside.path(), root.path().join("escape"))
                .expect("symlink fixture");
            files
                .attach_path(root.path(), Path::new("escape/secret.txt"))
                .expect("a symlink out of the workspace resolves to its target");
            assert_eq!(files.len(), 1);
        }
        let mut files = FileAttachments::default();

        // And the ordinary case is unchanged: a file under the workspace still attaches.
        assert!(
            files
                .attach_path(root.path(), Path::new("inside.txt"))
                .is_ok()
        );
    }

    #[test]
    fn a_file_too_large_to_carry_is_refused_rather_than_truncated() {
        let root = TestRoot::new("too-large");
        root.write("big.txt", "x".repeat(64));
        root.write("small.txt", "x".repeat(8));
        let limits = FileLoadLimits::new(4, 32, 64).expect("test limits");
        let mut files = FileAttachments::new(limits);

        assert_eq!(
            files
                .attach_path(root.path(), Path::new("big.txt"))
                .expect_err("over the per-file bound")
                .kind(),
            FileInputErrorKind::FileTooLarge
        );
        assert!(
            files.is_empty(),
            "refusal means nothing was carried, not that a prefix was"
        );
        assert_eq!(files.text_bytes(), 0);

        assert!(
            files
                .attach_path(root.path(), Path::new("small.txt"))
                .is_ok()
        );
        assert_eq!(files.text_bytes(), 8);
    }

    #[test]
    fn the_aggregate_bound_is_charged_across_chips_and_refuses_the_one_that_overflows() {
        let root = TestRoot::new("aggregate");
        for index in 0..3 {
            root.write(&format!("f{index}.txt"), "x".repeat(24));
        }
        let limits = FileLoadLimits::new(8, 32, 48).expect("test limits");
        let mut files = FileAttachments::new(limits);

        assert!(files.attach_path(root.path(), Path::new("f0.txt")).is_ok());
        assert!(files.attach_path(root.path(), Path::new("f1.txt")).is_ok());
        assert_eq!(files.text_bytes(), 48);
        assert_eq!(
            files
                .attach_path(root.path(), Path::new("f2.txt"))
                .expect_err("the aggregate bound is full")
                .kind(),
            FileInputErrorKind::AggregateTooLarge
        );
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn a_chip_list_refuses_more_files_than_the_declared_maximum() {
        let root = TestRoot::new("count");
        for index in 0..3 {
            root.write(&format!("f{index}.txt"), "x");
        }
        let mut files = FileAttachments::new(FileLoadLimits::new(2, 32, 64).expect("test limits"));
        assert!(files.attach_path(root.path(), Path::new("f0.txt")).is_ok());
        assert!(files.attach_path(root.path(), Path::new("f1.txt")).is_ok());
        assert_eq!(
            files
                .attach_path(root.path(), Path::new("f2.txt"))
                .expect_err("over the chip count")
                .kind(),
            FileInputErrorKind::TooManyAttachments
        );
    }

    #[test]
    fn a_file_that_is_not_utf8_text_is_refused_because_a_chip_is_something_to_read() {
        let root = TestRoot::new("binary");
        root.write("blob.bin", [0x7f, b'E', b'L', b'F', 0xff, 0xfe, 0x00]);
        let mut files = FileAttachments::default();
        assert_eq!(
            files
                .attach_path(root.path(), Path::new("blob.bin"))
                .expect_err("not text")
                .kind(),
            FileInputErrorKind::NotText
        );

        // Valid UTF-8 carrying a NUL is refused by the protocol's own text rule, on the same terms.
        root.write("nul.txt", "before\0after");
        assert_eq!(
            files
                .attach_path(root.path(), Path::new("nul.txt"))
                .expect_err("not text")
                .kind(),
            FileInputErrorKind::NotText
        );
    }

    #[test]
    fn a_hostile_name_is_refused_and_its_refusal_message_is_still_sanitised() {
        let root = TestRoot::new("label");
        // A right-to-left override in a filename reorders everything after it on a terminal line,
        // so the reference is refused outright rather than carried as a path.
        root.write("re\u{202e}gnp.txt", "ok");
        let mut files = FileAttachments::default();
        let error = files
            .attach_path(root.path(), Path::new("re\u{202e}gnp.txt"))
            .expect_err("a name that cannot be printed safely is not a valid reference");
        assert_eq!(error.kind(), FileInputErrorKind::InvalidReference);

        // The refusal itself is rendered into the composer, so the name inside it went through
        // the same sanitiser the chip label uses.
        let message = error.to_string();
        assert!(!message.contains('\u{202e}'), "{message:?}");
        assert!(message.contains('\u{fffd}'), "{message:?}");

        // An ordinary long name is truncated for display only; the chip still carries the file.
        let long = format!("{}.txt", "n".repeat(120));
        root.write(&long, "ok");
        let attached = files
            .attach_path(root.path(), Path::new(&long))
            .expect("a long but printable name is a readable file");
        assert!(
            attached.display_name().chars().count() <= 81,
            "{attached:?}"
        );
        assert!(attached.display_name().ends_with('\u{2026}'));
        assert_eq!(attached.relative_path(), long);
    }

    #[test]
    fn only_the_explicit_mention_form_is_a_file_reference() {
        let mentions = parse_file_mentions("compare @file(src/main.rs) with @file(docs/a.md)")
            .expect("two mentions");
        assert_eq!(mentions.len(), 2);
        assert_eq!(mentions[0].path(), Path::new("src/main.rs"));
        assert_eq!(mentions[1].path(), Path::new("docs/a.md"));

        // An ordinary sentence naming a path is text, not a filesystem read.
        assert!(
            parse_file_mentions("look at src/main.rs please")
                .unwrap()
                .is_empty()
        );
        assert!(
            parse_file_mentions("mail me@file.example")
                .unwrap()
                .is_empty()
        );
        assert!(parse_file_mentions("@file(https://example.com/x)").is_err());
        assert!(parse_file_mentions("@file(~/.ssh/id_rsa)").is_err());
        assert!(parse_file_mentions("@file(unclosed").is_err());
    }

    #[test]
    fn only_an_absolute_path_already_inside_the_workspace_reads_as_a_dropped_chip() {
        let root = TestRoot::new("drop");
        let inside = root.path().join("src/main.rs");
        assert_eq!(
            super::parse_dropped_file_path(root.path(), &format!("  {}  ", inside.display())),
            Some(inside.clone())
        );
        assert_eq!(
            super::parse_dropped_file_path(root.path(), &format!("'{}'", inside.display())),
            Some(inside)
        );
        for text in [
            "README",
            "src/main.rs",
            "look at this",
            "/etc/passwd",
            "https://example.com/x",
            "",
        ] {
            assert_eq!(
                super::parse_dropped_file_path(root.path(), text),
                None,
                "{text:?} is text, not a dropped file"
            );
        }
    }

    #[test]
    fn the_rendered_submission_never_exceeds_what_admission_charged_for_it() {
        let files = vec![
            FileContent::new("src/main.rs", "fn main() {}\n").unwrap(),
            FileContent::new("docs/a.md", "# title\n").unwrap(),
        ];
        let text = "review both";
        assert!(validate_file_submission(text, &[], &files).is_ok());

        let rendered = render_attached_files(text, &files);
        let charged = text.len()
            + files
                .iter()
                .map(|file| file.path.len() + file.text.len() + FILE_ATTACHMENT_FRAMING_BYTES)
                .sum::<usize>();
        assert!(rendered.len() <= charged, "{} > {charged}", rendered.len());
        assert!(rendered.contains("src/main.rs"));
        assert!(rendered.contains("fn main() {}"));
        assert!(
            rendered.ends_with(text),
            "the operator's instruction is the last thing the model reads"
        );

        // The bound holds at the extreme too, not just for small fixtures.
        let largest =
            vec![FileContent::new("a".repeat(1024), "x".repeat(MAX_FILE_TEXT_BYTES)).unwrap()];
        let rendered = render_attached_files("", &largest);
        assert!(rendered.len() <= 1024 + MAX_FILE_TEXT_BYTES + FILE_ATTACHMENT_FRAMING_BYTES);
    }

    #[test]
    fn generated_context_retains_type_order_complete_bytes_and_digest() {
        let mut files = FileAttachments::default();
        files
            .attach_generated(ContextKind::Diff, "working tree", "- old\n+ new\n".into())
            .unwrap();
        files
            .attach_generated(ContextKind::Lsp, "definition", "{\"line\":42}\n".into())
            .unwrap();

        assert_eq!(files.as_slice()[0].kind(), ContextKind::Diff);
        assert_eq!(files.as_slice()[1].kind(), ContextKind::Lsp);
        assert_eq!(files.as_slice()[0].text(), "- old\n+ new\n");
        assert_eq!(files.as_slice()[0].digest().len(), 64);
        assert!(
            files.as_slice()[0]
                .relative_path()
                .starts_with(".core-context/diff/")
        );
        assert_eq!(files.to_file_contents()[1].text, "{\"line\":42}\n");

        assert!(
            files
                .attach_generated(ContextKind::Diff, "duplicate", "- old\n+ new\n".into())
                .is_err(),
            "content-addressed duplicate context is one chip"
        );
    }
}
