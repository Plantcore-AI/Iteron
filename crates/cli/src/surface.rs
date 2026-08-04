//! Responsive geometry for the interactive terminal surface.
//!
//! The TUI is deliberately one full-width column. Transcript, composer, contextual help, and the
//! bottom status line share the terminal grid at every width; density changes disclosure, never the
//! usable canvas. This module contains geometry only so transcript/runtime state remains independent
//! from presentation policy.

use ratatui::layout::Rect;

/// Information density selected from the actual content width, not a terminal-name heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Density {
    Compact,
    Standard,
    Wide,
}

impl Density {
    pub fn for_width(width: u16) -> Self {
        match width {
            0..=59 => Self::Compact,
            60..=103 => Self::Standard,
            _ => Self::Wide,
        }
    }
}

/// All persistent regions of one frame. `stage` is the complete terminal frame, not a painted
/// desktop window. Every persistent region shares that full-width grid; transcript content reserves
/// the final column for the scrollbar so overflow can never overwrite evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Surface {
    pub stage: Rect,
    pub transcript: Rect,
    pub scrollbar: Rect,
    pub status: Rect,
    pub lanes: Rect,
    pub composer: Rect,
    pub hint: Rect,
    pub overlay_anchor: Rect,
    pub density: Density,
}

impl Surface {
    /// Width available to transcript text after reserving the scrollbar gutter. A one-cell terminal
    /// keeps its only cell for content; wider terminals have enough room to preserve both surfaces.
    pub fn transcript_content_width(self) -> u16 {
        self.transcript.width.saturating_sub(u16::from(
            self.transcript.width > 1 && self.scrollbar.width > 0,
        ))
    }

    pub fn resolve(
        frame: Rect,
        editor_rows: u16,
        requested_lane_rows: u16,
        show_status: bool,
        blocking_input: bool,
    ) -> Self {
        let stage = content_rect(frame);
        let density = Density::for_width(stage.width);
        let body = stage;

        // Secondary rows disappear in priority order on very short terminals. The transcript always
        // keeps a row; the terminal-native composer receives one border above and below plus up to
        // six editable rows.
        let hint_h = u16::from(body.height >= 6);
        let status_h = u16::from(show_status && body.height >= 4);
        // A blocking decision is the only region allowed to displace the final transcript row. On
        // one/two-line frames, showing the fail-closed action is safer than preserving stale prose.
        let transcript_floor = u16::from(body.height >= 1 && !(blocking_input && body.height <= 2));
        let lane_h = requested_lane_rows.min(2).min(
            body.height
                .saturating_sub(hint_h)
                .saturating_sub(status_h)
                .saturating_sub(transcript_floor)
                .saturating_sub(2),
        );
        let available_for_composer = body
            .height
            .saturating_sub(hint_h)
            .saturating_sub(status_h)
            .saturating_sub(lane_h)
            .saturating_sub(transcript_floor);
        // The native prompt has one frame around its editor body. Geometry never steals the
        // transcript floor or lets a region escape the terminal viewport.
        let desired_composer = editor_rows.clamp(1, 6).saturating_add(2);
        let composer_h = desired_composer.min(available_for_composer);
        let transcript_h = body
            .height
            .saturating_sub(status_h)
            .saturating_sub(lane_h)
            .saturating_sub(composer_h)
            .saturating_sub(hint_h);

        let transcript = Rect::new(body.x, body.y, body.width, transcript_h);
        let scrollbar_x = body.right().saturating_sub(1);
        let scrollbar = Rect::new(
            if stage.width == 0 {
                stage.x
            } else {
                scrollbar_x.min(stage.right().saturating_sub(1))
            },
            transcript.y,
            u16::from(stage.width > 0),
            transcript.height,
        );
        let lanes = Rect::new(body.x, transcript.bottom(), body.width, lane_h);
        let composer = Rect::new(body.x, lanes.bottom(), body.width, composer_h);
        let hint = Rect::new(body.x, composer.bottom(), body.width, hint_h);
        let status = Rect::new(body.x, hint.bottom(), body.width, status_h);

        Self {
            stage,
            transcript,
            scrollbar,
            status,
            lanes,
            composer,
            hint,
            overlay_anchor: composer,
            density,
        }
    }
}

fn content_rect(frame: Rect) -> Rect {
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_terminals_use_the_complete_frame_and_bottom_status_line() {
        let s = Surface::resolve(Rect::new(0, 0, 180, 40), 1, 0, true, false);
        assert_eq!(s.stage, Rect::new(0, 0, 180, 40));
        assert_eq!(s.transcript.width, 180);
        assert_eq!(s.transcript.x, 0);
        assert_eq!(s.scrollbar.x, 179);
        assert_eq!(s.composer.x, s.transcript.x);
        assert_eq!(s.hint.right(), s.transcript.right());
        assert_eq!(s.status.bottom(), s.stage.bottom());
        assert_eq!(s.density, Density::Wide);
    }

    #[test]
    fn standard_terminals_keep_one_full_width_grid() {
        let s = Surface::resolve(Rect::new(5, 2, 80, 24), 2, 1, true, false);
        assert_eq!(s.stage, Rect::new(5, 2, 80, 24));
        assert_eq!(s.transcript.x, 5);
        assert_eq!(s.transcript.width, 80);
        assert_eq!(s.composer.height, 4);
        assert_eq!(s.lanes.height, 1);
        assert_eq!(s.hint.height, 1);
        assert_eq!(s.status.height, 1);
        assert_eq!(s.status.bottom(), 26);
        assert_eq!(s.density, Density::Standard);
    }

    #[test]
    fn density_boundaries_change_disclosure_without_changing_width() {
        assert_eq!(
            Surface::resolve(Rect::new(0, 0, 59, 20), 1, 0, false, false).density,
            Density::Compact
        );
        assert_eq!(
            Surface::resolve(Rect::new(0, 0, 60, 20), 1, 0, false, false).density,
            Density::Standard
        );
        assert_eq!(
            Surface::resolve(Rect::new(0, 0, 103, 20), 1, 0, false, false).density,
            Density::Standard
        );
        assert_eq!(
            Surface::resolve(Rect::new(0, 0, 104, 20), 1, 0, false, false).density,
            Density::Wide
        );
        for frame_width in [59, 60, 103, 104, 120, 160] {
            let surface = Surface::resolve(Rect::new(0, 0, frame_width, 20), 1, 0, false, false);
            assert_eq!(surface.stage.width, frame_width);
            assert_eq!(surface.transcript.width, frame_width);
        }
    }

    #[test]
    fn product_widths_keep_one_full_width_body_grid() {
        for width in [40, 80, 120, 200] {
            let surface = Surface::resolve(Rect::new(0, 0, width, 30), 3, 2, true, false);
            assert_eq!(surface.stage.x, 0, "stage x at {width}");
            assert_eq!(surface.stage.width, width, "stage width at {width}");
            for region in [
                surface.transcript,
                surface.lanes,
                surface.composer,
                surface.hint,
                surface.status,
            ] {
                assert_eq!(region.x, surface.transcript.x, "left grid at {width}");
                assert_eq!(
                    region.right(),
                    surface.transcript.right(),
                    "right grid at {width}"
                );
            }
        }
    }

    #[test]
    fn transcript_content_reserves_the_scrollbar_without_erasing_a_one_cell_view() {
        for (width, content_width) in [(0, 0), (1, 1), (2, 1), (60, 59), (120, 119)] {
            let surface = Surface::resolve(Rect::new(0, 0, width, 20), 1, 0, true, false);
            assert_eq!(surface.transcript_content_width(), content_width);
        }
    }

    #[test]
    fn tiny_terminals_never_escape_the_frame() {
        for width in 0..10 {
            for height in 0..10 {
                let frame = Rect::new(3, 4, width, height);
                let s = Surface::resolve(frame, 6, 2, true, false);
                for area in [
                    s.stage,
                    s.transcript,
                    s.scrollbar,
                    s.status,
                    s.lanes,
                    s.composer,
                    s.hint,
                    s.overlay_anchor,
                ] {
                    assert!(area.x >= frame.x && area.y >= frame.y);
                    assert!(area.right() <= frame.right());
                    assert!(area.bottom() <= frame.bottom());
                }
                assert_eq!(
                    s.transcript.height
                        + s.lanes.height
                        + s.composer.height
                        + s.hint.height
                        + s.status.height,
                    height
                );
            }
        }
    }

    #[test]
    fn blocking_input_owns_the_last_row_on_tiny_frames() {
        for height in [1, 2] {
            let surface = Surface::resolve(Rect::new(0, 0, 20, height), 6, 0, false, true);
            assert_eq!(surface.transcript.height, 0);
            assert_eq!(surface.composer.height, height);
            assert_eq!(surface.composer.bottom(), height);
        }
    }
}
