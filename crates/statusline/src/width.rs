//! How many terminal cells a string occupies, which is not how many bytes or characters it has.
//!
//! A status line shares one row with the prompt, so its budget is a *cell* count. Measuring it in
//! bytes overflows the row for any CJK content -- `中` is three bytes and two cells -- and measuring
//! it in `char`s underflows for the same reason, then breaks again on combining marks, which are
//! characters occupying no cell at all. Both mistakes produce a line that wraps, and a wrapped
//! status line pushes the prompt off-screen on every redraw.
//!
//! This is a deliberate approximation of Unicode East Asian Width, not a full implementation: the
//! wide ranges below cover the scripts and emoji a status line realistically carries. It is
//! documented as approximate rather than presented as authoritative, because the failure it
//! prevents is a wrapped row, not a rendering guarantee.

/// Cells occupied by one scalar value.
///
/// Zero for combining marks: they compose onto the preceding character and advance the cursor by
/// nothing. Counting them as 1 makes every accented or Devanagari string measure too wide, which
/// truncates content that would have fit.
pub fn char_cells(ch: char) -> usize {
    let c = ch as u32;
    // Control characters have no defined width here; callers must have refused or escaped them
    // already (see `safe_text`). Reported as zero so a leaked one cannot inflate the budget.
    if c < 0x20 || c == 0x7F || (0x80..=0x9F).contains(&c) {
        return 0;
    }
    if is_combining(c) {
        return 0;
    }
    if is_wide(c) { 2 } else { 1 }
}

/// Cells occupied by a string.
pub fn str_cells(s: &str) -> usize {
    s.chars().map(char_cells).sum()
}

/// Truncate to at most `cells`, appending an elision marker when anything was dropped.
///
/// The marker's own width is reserved before truncating, so the result never exceeds the budget --
/// the same class of mistake as reserving bytes for a multi-byte marker.
pub fn truncate_to_cells(s: &str, cells: usize) -> String {
    if str_cells(s) <= cells {
        return s.to_owned();
    }
    const ELLIPSIS: char = '…';
    let marker = char_cells(iteron_tunables::param_char(
        "statusline.width.ellipsis",
        ELLIPSIS,
    ));
    let budget = cells.saturating_sub(marker);

    let mut out = String::new();
    let mut used = 0usize;
    for ch in s.chars() {
        let w = char_cells(ch);
        // A wide character that would straddle the boundary is dropped whole. Splitting it is not
        // possible, and rendering half of it is not a thing a terminal can do.
        if used + w > budget {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push(iteron_tunables::param_char(
        "statusline.width.ellipsis",
        ELLIPSIS,
    ));
    out
}

fn is_combining(c: u32) -> bool {
    matches!(c,
        0x0300..=0x036F   // combining diacriticals
        | 0x0483..=0x0489
        | 0x0591..=0x05BD
        | 0x0610..=0x061A
        | 0x064B..=0x065F
        | 0x0670
        | 0x06D6..=0x06DC
        | 0x0900..=0x0903 // Devanagari signs
        | 0x093A..=0x093C
        | 0x0941..=0x094D
        | 0x0E31 | 0x0E34..=0x0E3A | 0x0E47..=0x0E4E // Thai
        | 0x20D0..=0x20F0 // combining marks for symbols
        | 0xFE00..=0xFE0F // variation selectors
        | 0xFE20..=0xFE2F
    )
}

fn is_wide(c: u32) -> bool {
    matches!(c,
        0x1100..=0x115F   // Hangul Jamo initial
        | 0x2E80..=0x303E // CJK radicals, Kangxi, CJK symbols
        | 0x3041..=0x33FF // Hiragana, Katakana, Bopomofo, compatibility
        | 0x3400..=0x4DBF // CJK ext A
        | 0x4E00..=0x9FFF // CJK unified
        | 0xA000..=0xA4CF // Yi
        | 0xAC00..=0xD7A3 // Hangul syllables
        | 0xF900..=0xFAFF // CJK compatibility ideographs
        | 0xFE30..=0xFE6F // CJK compatibility forms
        | 0xFF00..=0xFF60 // fullwidth forms
        | 0xFFE0..=0xFFE6
        // Emoji. Deliberately spans the gaps between blocks rather than listing only Emoticons:
        // `🚀` is U+1F680 (Transport and Map Symbols), which a `1F300..=1F64F` range misses -- and
        // a missed wide character is under-measured, so the row wraps.
        | 0x1F300..=0x1F9FF
        | 0x1FA70..=0x1FAFF
        | 0x20000..=0x3FFFD // CJK ext B+
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cjk_is_two_cells_while_ascii_is_one() {
        // The measurement that byte- and char-counting both get wrong, in opposite directions.
        assert_eq!("中".len(), 3, "three bytes");
        assert_eq!("中".chars().count(), 1, "one char");
        assert_eq!(str_cells("中"), 2, "but two cells");
        assert_eq!(str_cells("ab"), 2);
    }

    #[test]
    fn a_combining_mark_occupies_no_cell() {
        // "é" as e + U+0301 is two chars and one cell. Counting it as two truncates text that fits.
        let decomposed = "e\u{301}";
        assert_eq!(decomposed.chars().count(), 2);
        assert_eq!(str_cells(decomposed), 1);
    }

    #[test]
    fn an_emoji_is_two_cells() {
        assert_eq!(str_cells("🚀"), 2);
    }

    #[test]
    fn a_leaked_control_character_cannot_inflate_the_budget() {
        assert_eq!(str_cells("a\u{1b}b"), 2);
    }

    #[test]
    fn truncation_never_exceeds_the_budget_including_its_marker() {
        for budget in 1..12 {
            let out = truncate_to_cells("中文中文中文中文", budget);
            assert!(
                str_cells(&out) <= budget,
                "budget {budget} produced {} cells: {out:?}",
                str_cells(&out)
            );
        }
    }

    #[test]
    fn a_wide_character_straddling_the_boundary_is_dropped_whole() {
        // Budget 4 = marker (1) + 3 usable; two CJK need 4, so only one fits.
        let out = truncate_to_cells("中中中", 4);
        assert_eq!(out, "中…");
        assert_eq!(str_cells(&out), 3);
    }

    #[test]
    fn a_string_that_fits_is_returned_unchanged_without_a_marker() {
        assert_eq!(truncate_to_cells("main", 10), "main");
        assert_eq!(truncate_to_cells("中文", 4), "中文");
    }

    #[test]
    fn truncation_output_is_always_valid_utf8_on_char_boundaries() {
        let out = truncate_to_cells("héllo 中文 🚀 world", 7);
        assert!(str_cells(&out) <= 7);
        assert!(out.chars().count() > 0);
        // Round-trips: no split scalar.
        assert_eq!(out, String::from_utf8(out.clone().into_bytes()).unwrap());
    }
}
