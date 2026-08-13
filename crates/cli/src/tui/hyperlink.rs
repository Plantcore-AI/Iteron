//! Conservative OSC 8 admission and final-buffer rendering.
//!
//! Markdown/layout code carries only validated targets and display-cell regions. Escape bytes are
//! introduced here, after wrapping and scrolling, so they can never participate in width math.

use crate::render::HyperlinkRegion;
use ratatui::buffer::{Buffer, CellDiffOption};
use ratatui::layout::Rect;
use std::num::NonZeroU16;
use std::path::{Component, Path, PathBuf};
use url::Url;

const MAX_ENV_VALUE_BYTES: usize = 128;
const MAX_TARGET_BYTES: usize = 2 * 1024;
const MAX_LINKS_PER_FRAME: usize = 512;
const MAX_LINK_CELLS_PER_FRAME: usize = 16 * 1024;
const MAX_OSC_BYTES_PER_FRAME: usize = 256 * 1024;
/// Escape bytes an OSC 8 chunk spends on its own delimiters: the opening `ESC ] 8 ; ;` and closing
/// `ESC ] 8 ; ;` are five bytes each, and each is terminated by a one-byte BEL.
const OSC8_DELIMITER_BYTES: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Capability {
    PlainText,
    Osc8,
}

/// Session-stable terminal capability and the workspace boundary for local-file links.
#[derive(Debug, Clone)]
pub(crate) struct Policy {
    capability: Capability,
    workspace: Option<PathBuf>,
}

impl Policy {
    pub fn detect(workspace: &Path) -> Self {
        Self::new(detect_capability(), workspace)
    }

    pub fn disabled() -> Self {
        Self {
            capability: Capability::PlainText,
            workspace: None,
        }
    }

    pub(crate) fn new(capability: Capability, workspace: &Path) -> Self {
        Self {
            capability,
            workspace: workspace.canonicalize().ok(),
        }
    }

    pub fn supports_osc8(&self) -> bool {
        self.capability == Capability::Osc8
    }

    /// Admit only bounded HTTP(S) URLs without embedded credentials, or existing local files whose
    /// canonical path remains inside the session workspace. The returned target is normalized.
    pub fn admit_target(&self, raw: &str) -> Option<String> {
        if !self.supports_osc8()
            || raw.is_empty()
            || raw.len()
                > iteron_tunables::param_integer(
                    "cli.tui.hyperlink.max_target_bytes",
                    MAX_TARGET_BYTES,
                )
            || raw.chars().any(char::is_control)
        {
            return None;
        }
        if let Ok(url) = Url::parse(raw) {
            return match url.scheme() {
                "http" | "https"
                    if url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none() =>
                {
                    bounded_url(url)
                }
                "file" => self.admit_file_url(url),
                _ => None,
            };
        }
        self.admit_relative_file(raw)
    }

    fn admit_file_url(&self, url: Url) -> Option<String> {
        let path = url.to_file_path().ok()?;
        let canonical = self.confined_canonical(&path)?;
        let mut normalized = Url::from_file_path(canonical).ok()?;
        normalized.set_fragment(url.fragment());
        bounded_url(normalized)
    }

    fn admit_relative_file(&self, raw: &str) -> Option<String> {
        let (path_text, fragment) = raw
            .split_once('#')
            .map_or((raw, None), |(path, fragment)| (path, Some(fragment)));
        let path = Path::new(path_text);
        if path.is_absolute()
            || path_text.is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::CurDir | Component::Normal(_)))
        {
            return None;
        }
        let workspace = self.workspace.as_ref()?;
        let canonical = self.confined_canonical(&workspace.join(path))?;
        let mut normalized = Url::from_file_path(canonical).ok()?;
        normalized.set_fragment(fragment.filter(|fragment| !fragment.is_empty()));
        bounded_url(normalized)
    }

    fn confined_canonical(&self, path: &Path) -> Option<PathBuf> {
        let workspace = self.workspace.as_ref()?;
        let canonical = path.canonicalize().ok()?;
        canonical.starts_with(workspace).then_some(canonical)
    }
}

fn bounded_url(url: Url) -> Option<String> {
    let target = String::from(url);
    (target.len()
        <= iteron_tunables::param_integer("cli.tui.hyperlink.max_target_bytes", MAX_TARGET_BYTES)
        && !target.chars().any(char::is_control))
    .then_some(target)
}

fn detect_capability() -> Capability {
    detect_with(|name| {
        let value = std::env::var(name).ok()?;
        (value.len()
            <= iteron_tunables::param_integer(
                "cli.tui.hyperlink.max_env_value_bytes",
                MAX_ENV_VALUE_BYTES,
            ))
        .then_some(value)
    })
}

fn detect_with(mut get: impl FnMut(&str) -> Option<String>) -> Capability {
    let term = get("TERM").unwrap_or_default();
    if term == "dumb" || get("TMUX").is_some() || get("STY").is_some() {
        return Capability::PlainText;
    }

    let term_program = get("TERM_PROGRAM").unwrap_or_default().to_ascii_lowercase();
    let known_program = matches!(
        term_program.as_str(),
        "iterm.app" | "wezterm" | "vscode" | "ghostty" | "hyper"
    );
    let known_term = matches!(
        term.as_str(),
        "xterm-kitty" | "xterm-ghostty" | "wezterm" | "foot" | "foot-extra"
    );
    let vte = get("VTE_VERSION")
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|version| version >= 5_000);
    let konsole = get("KONSOLE_VERSION")
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|version| version >= 180_400);
    let explicit_runtime_signal = [
        "WT_SESSION",
        "KITTY_WINDOW_ID",
        "WEZTERM_PANE",
        "GHOSTTY_RESOURCES_DIR",
    ]
    .into_iter()
    .any(|name| get(name).is_some_and(|value| !value.is_empty()));

    if known_program || known_term || vte || konsole || explicit_runtime_signal {
        Capability::Osc8
    } else {
        Capability::PlainText
    }
}

/// Replace visible cells in admitted regions with self-contained OSC 8 chunks. Each chunk declares
/// its exact terminal width so Ratatui's buffer diff does not count the control bytes as visible
/// columns. Chunks occupy at most two display cells and close independently, so clipping or a
/// partial redraw cannot leak hyperlink state into neighboring terminal output.
pub(crate) fn apply_to_buffer(
    buffer: &mut Buffer,
    area: Rect,
    scroll: u16,
    regions: &[HyperlinkRegion],
    policy: &Policy,
) {
    apply_to_buffer_with_chunk_width(buffer, area, scroll, regions, policy, 2);
}

fn apply_to_buffer_with_chunk_width(
    buffer: &mut Buffer,
    area: Rect,
    scroll: u16,
    regions: &[HyperlinkRegion],
    policy: &Policy,
    chunk_width_limit: u16,
) {
    if !policy.supports_osc8() || area.is_empty() {
        return;
    }
    let mut linked_cells = 0usize;
    let mut osc_bytes = 0usize;
    // The renderer appends regions in row order. Binary-searching to the viewport prevents old,
    // off-screen links from consuming the per-frame admission limit in a long transcript.
    let top = usize::from(scroll);
    let bottom = top.saturating_add(usize::from(area.height));
    let first_visible = regions.partition_point(|region| region.row < top);
    'regions: for region in regions[first_visible..]
        .iter()
        .take_while(|region| region.row < bottom)
        .take(iteron_tunables::param_integer(
            "cli.tui.hyperlink.max_links_per_frame",
            MAX_LINKS_PER_FRAME,
        ))
    {
        let Ok(view_row) = u16::try_from(region.row.saturating_sub(top)) else {
            continue;
        };
        let Some(target) = policy.admit_target(&region.target) else {
            continue;
        };
        let mut column = region.col.min(area.width);
        let end = region.col.saturating_add(region.width).min(area.width);
        while column < end
            && linked_cells
                < iteron_tunables::param_integer(
                    "cli.tui.hyperlink.max_link_cells_per_frame",
                    MAX_LINK_CELLS_PER_FRAME,
                )
        {
            let x = area.x.saturating_add(column);
            let y = area.y.saturating_add(view_row);
            let mut chunk = String::new();
            let mut chunk_width = 0u16;
            let mut scan = column;
            while scan < end && chunk_width < chunk_width_limit {
                let scan_x = area.x.saturating_add(scan);
                let symbol = buffer[(scan_x, y)].symbol();
                if symbol.is_empty() || symbol.chars().any(char::is_control) {
                    break;
                }
                let symbol_width = symbol
                    .chars()
                    .map(crate::tui::char_width)
                    .fold(0u16, u16::saturating_add)
                    .max(1);
                if chunk_width.saturating_add(symbol_width) > chunk_width_limit {
                    break;
                }
                chunk.push_str(symbol);
                chunk_width = chunk_width.saturating_add(symbol_width);
                scan = scan.saturating_add(symbol_width);
            }
            if chunk.is_empty() {
                column = column.saturating_add(1);
                continue;
            }
            // Two OSC 8 delimiters wrap the target and the visible chunk.
            let encoded_len = target.len().saturating_add(chunk.len()).saturating_add(
                iteron_tunables::param_integer(
                    "cli.tui.hyperlink.osc8_delimiter_bytes",
                    OSC8_DELIMITER_BYTES,
                ),
            );
            if osc_bytes.saturating_add(encoded_len)
                > iteron_tunables::param_integer(
                    "cli.tui.hyperlink.max_osc_bytes_per_frame",
                    MAX_OSC_BYTES_PER_FRAME,
                )
            {
                break 'regions;
            }
            let osc = format!("\u{1b}]8;;{target}\u{7}{chunk}\u{1b}]8;;\u{7}");
            let Some(forced_width) = NonZeroU16::new(chunk_width) else {
                continue;
            };
            buffer[(x, y)]
                .set_symbol(&osc)
                .set_diff_option(CellDiffOption::ForcedWidth(forced_width));
            column = scan;
            linked_cells = linked_cells.saturating_add(usize::from(chunk_width));
            osc_bytes = osc_bytes.saturating_add(encoded_len);
        }
        if linked_cells
            >= iteron_tunables::param_integer(
                "cli.tui.hyperlink.max_link_cells_per_frame",
                MAX_LINK_CELLS_PER_FRAME,
            )
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::{Backend, CrosstermBackend};
    use ratatui::buffer::Buffer;
    use ratatui::style::Style;
    use std::collections::HashMap;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("capture lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn detected(vars: &[(&str, &str)]) -> Capability {
        let vars: HashMap<&str, &str> = vars.iter().copied().collect();
        detect_with(|name| vars.get(name).map(|value| (*value).to_string()))
    }

    fn test_workspace(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("core-osc8-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create OSC 8 test workspace");
        path
    }

    #[test]
    fn capability_is_admitted_only_from_positive_terminal_evidence() {
        assert_eq!(
            detected(&[("TERM", "xterm-256color")]),
            Capability::PlainText
        );
        assert_eq!(
            detected(&[("TERM", "xterm-256color"), ("TERM_PROGRAM", "WezTerm")]),
            Capability::Osc8
        );
        assert_eq!(
            detected(&[("WT_SESSION", "native-windows-terminal")]),
            Capability::Osc8
        );
        assert_eq!(
            detected(&[("TERM", "xterm-kitty"), ("TMUX", "/tmp/tmux")]),
            Capability::PlainText,
            "multiplexer passthrough is not assumed"
        );
        assert_eq!(
            detected(&[("TERM", "xterm-256color"), ("VTE_VERSION", "5000")]),
            Capability::Osc8
        );
    }

    #[test]
    fn targets_are_bounded_normalized_and_workspace_confined() {
        let workspace = test_workspace("targets");
        let local = workspace.join("notes.md");
        std::fs::write(&local, "notes").expect("write local link target");
        let policy = Policy::new(Capability::Osc8, &workspace);

        assert_eq!(
            policy.admit_target("https://example.com/a path"),
            Some("https://example.com/a%20path".into())
        );
        assert!(
            policy
                .admit_target("notes.md#section")
                .is_some_and(|target| target.starts_with("file://") && target.ends_with("#section"))
        );
        assert!(policy.admit_target("javascript:alert(1)").is_none());
        assert!(
            policy
                .admit_target("https://user:pass@example.com")
                .is_none()
        );
        assert!(policy.admit_target("../outside.md").is_none());
        assert!(
            policy
                .admit_target("https://example.com/\u{1b}]8;;bad")
                .is_none()
        );
        assert!(
            policy
                .admit_target(&"x".repeat(MAX_TARGET_BYTES + 1))
                .is_none()
        );

        let _ = std::fs::remove_dir_all(workspace);
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_canonicalize_to_confined_file_urls() {
        let workspace = test_workspace("windows-paths");
        let local = workspace.join("notes with space.md");
        std::fs::write(&local, "notes").expect("write Windows OSC 8 target");
        let policy = Policy::new(Capability::Osc8, &workspace);

        let target = policy
            .admit_target("notes with space.md")
            .expect("admit workspace-relative Windows path");
        let url = Url::parse(&target).expect("normalized target is a URL");
        assert_eq!(url.scheme(), "file");
        assert_eq!(
            url.to_file_path()
                .expect("file URL converts to a Windows path")
                .canonicalize()
                .expect("canonicalize URL path"),
            local.canonicalize().expect("canonicalize fixture path")
        );
        assert!(policy.admit_target(r"C:\outside.txt").is_none());
        assert!(policy.admit_target(r"\\server\share\outside.txt").is_none());
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[cfg(unix)]
    #[test]
    fn local_symlink_escape_is_not_admitted() {
        let workspace = test_workspace("symlink");
        let outside = test_workspace("outside");
        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, "not in workspace").expect("write outside file");
        std::os::unix::fs::symlink(&outside_file, workspace.join("escape.txt"))
            .expect("create escape symlink");
        let policy = Policy::new(Capability::Osc8, &workspace);
        assert!(policy.admit_target("escape.txt").is_none());
        let _ = std::fs::remove_dir_all(workspace);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[test]
    fn mock_backend_emits_exact_osc8_and_preserves_visible_text() {
        let workspace = test_workspace("backend");
        let policy = Policy::new(Capability::Osc8, &workspace);
        let area = Rect::new(0, 0, 8, 1);
        let previous = Buffer::empty(area);
        let mut current = Buffer::empty(area);
        current.set_string(0, 0, "docs", Style::default());
        apply_to_buffer(
            &mut current,
            area,
            0,
            &[HyperlinkRegion {
                row: 0,
                col: 0,
                width: 4,
                target: "https://example.com/docs".into(),
            }],
            &policy,
        );

        let capture = Capture::default();
        let shared = capture.0.clone();
        let mut backend = CrosstermBackend::new(capture);
        backend
            .draw(previous.diff(&current).into_iter())
            .expect("draw mock terminal buffer");
        Write::flush(&mut backend).expect("flush mock terminal buffer");
        let bytes = shared.lock().expect("capture lock").clone();
        let output = String::from_utf8(bytes).expect("terminal output is UTF-8");
        assert!(output.contains("\u{1b}]8;;https://example.com/docs\u{7}do\u{1b}]8;;\u{7}"));
        assert_eq!(
            output
                .matches("\u{1b}]8;;https://example.com/docs\u{7}")
                .count(),
            2
        );

        let mut parser = vt100::Parser::new(1, 8, 0);
        parser.process(output.as_bytes());
        assert!(parser.screen().contents().starts_with("docs"));
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn fallback_and_hostile_regions_never_emit_escape_bytes() {
        let workspace = test_workspace("hostile");
        let area = Rect::new(0, 0, 8, 1);
        let mut buffer = Buffer::empty(area);
        buffer.set_string(0, 0, "docs", Style::default());
        let hostile = HyperlinkRegion {
            row: 0,
            col: 0,
            width: 4,
            target: "https://example.com/\u{1b}]8;;injected".into(),
        };
        apply_to_buffer(
            &mut buffer,
            area,
            0,
            std::slice::from_ref(&hostile),
            &Policy::new(Capability::Osc8, &workspace),
        );
        assert_eq!(buffer[(0, 0)].symbol(), "d");
        apply_to_buffer(
            &mut buffer,
            area,
            0,
            &[HyperlinkRegion {
                target: "https://example.com/docs".into(),
                ..hostile
            }],
            &Policy::disabled(),
        );
        assert!(
            buffer
                .content()
                .iter()
                .all(|cell| !cell.symbol().contains('\u{1b}'))
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn offscreen_history_does_not_consume_visible_link_limit() {
        let workspace = test_workspace("scroll");
        let policy = Policy::new(Capability::Osc8, &workspace);
        let area = Rect::new(0, 0, 4, 1);
        let mut buffer = Buffer::empty(area);
        buffer.set_string(0, 0, "late", Style::default());
        let mut regions: Vec<HyperlinkRegion> = (0..600)
            .map(|row| HyperlinkRegion {
                row,
                col: 0,
                width: 1,
                target: "https://example.com/old".into(),
            })
            .collect();
        regions.push(HyperlinkRegion {
            row: 600,
            col: 0,
            width: 4,
            target: "https://example.com/late".into(),
        });
        apply_to_buffer(&mut buffer, area, 600, &regions, &policy);
        assert!(buffer[(0, 0)].symbol().contains("https://example.com/late"));
        let _ = std::fs::remove_dir_all(workspace);
    }
}
