//! UTF-8-safe truncation helpers. Shared because the code review found the SAME byte-slicing
//! panic at five sites (shell, oracle, kernel, instructions, fs_tools): slicing a `str` at a
//! fixed byte offset panics when the offset lands mid-codepoint, which any non-ASCII tool output
//! (CJK, emoji, accented text) can trigger. These helpers snap to char boundaries, so they never
//! panic.

/// Keep the head and tail of `s`, eliding the middle, bounded to roughly `max` bytes. Both cuts
/// snap to char boundaries. Never panics.
pub fn elide_middle(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let half = max / 2;
    // head: largest boundary <= half
    let mut head = half.min(s.len());
    while head > 0 && !s.is_char_boundary(head) {
        head -= 1;
    }
    // tail: smallest boundary >= len - half
    let mut tail = s.len().saturating_sub(half);
    while tail < s.len() && !s.is_char_boundary(tail) {
        tail += 1;
    }
    let elided = s.len() - head - (s.len() - tail);
    format!(
        "{}\n… ({elided} bytes elided) …\n{}",
        &s[..head],
        &s[tail..]
    )
}

/// Keep the last `max`-ish bytes of `s` (test failures print last), snapping the start to a char
/// boundary. Never panics.
pub fn tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    format!("… (truncated)\n{}", &s[start..])
}

/// Keep the first `max`-ish bytes of `s`, snapping the end down to a char boundary. Never panics.
pub fn head(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… (truncated)", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic_on_multibyte_at_the_cut() {
        // A string of 3-byte CJK chars: every fixed byte offset except multiples of 3 is
        // mid-codepoint. The naive slice would panic; these must not.
        let s = "写".repeat(5000); // 15000 bytes, none of the interesting offsets are boundaries
        let _ = elide_middle(&s, 4001);
        let _ = tail(&s, 4001);
        let _ = head(&s, 4001);
        // and a 4-byte emoji string
        let e = "😀".repeat(3000);
        let _ = elide_middle(&e, 5003);
        let _ = tail(&e, 5003);
    }

    #[test]
    fn short_strings_pass_through() {
        assert_eq!(tail("hi", 100), "hi");
        assert_eq!(head("hi", 100), "hi");
        assert_eq!(elide_middle("hi", 100), "hi");
    }

    #[test]
    fn output_is_valid_utf8_and_bounded() {
        let s = "写".repeat(5000);
        let t = tail(&s, 100);
        assert!(t.is_char_boundary(t.len())); // trivially true but asserts no panic path
        assert!(t.len() < s.len());
    }
}
