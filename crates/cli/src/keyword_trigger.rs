//! Detect an explicit operator request for multi-agent orchestration inside one submitted prompt.
//!
//! This is a lexical gate, not a classifier. It answers exactly one question: did the operator
//! *name* orchestration in the words they just sent? One hit is enough — hits are never counted or
//! weighted, because saying it twice is not a stronger request than saying it once.
//!
//! Deliberately dependency-free: `iteron-cli` does not depend on `regex`, and a four-term matcher
//! is not a reason to add a dependency to a shipped binary.

/// Placeholder written over every character that lives inside a fenced block or an inline code
/// span.
///
/// A control character rather than a space, on purpose: masking with a space would let
/// ``ultra `x` code`` collapse into the literal `ultra code` term and fire on text the operator
/// deliberately wrote as code.
fn mask() -> char {
    '\u{1}'
}

/// ASCII terms. Matched case-insensitively, and only when both sides are word boundaries — where a
/// "word character" is Unicode `[\p{L}\p{N}_]`.
fn ascii_terms() -> [&'static str; 4] {
    [
        "ultracode",
        "ultra code",
        "dynamic workflow",
        "dynamic workflows",
    ]
}

/// CJK terms. Matched as PLAIN SUBSTRINGS, with NO word-boundary test.
///
/// WHY, so that a future reader does not "fix" this into symmetry with [`ascii_terms()`]: `\p{L}`
/// classifies Han characters as word characters. Chinese is not written with spaces, so a Han term
/// is essentially always flanked by more Han — i.e. by word characters — and an ASCII-style
/// boundary rule would reject every real occurrence. Requiring boundaries here would fail 100% of
/// the time, not occasionally. Substring matching is the deliberate, correct rule for these three.
fn cjk_terms() -> [&'static str; 3] {
    ["动态工作流", "工作流编排", "并行编排"]
}

/// Characters that, immediately BEFORE a match, mean the term is part of a path, flag, or
/// identifier rather than a sentence (`--ultracode`, `src/ultracode`).
fn reject_before() -> [char; 3] {
    ['/', '\\', '-']
}

/// Characters that, immediately AFTER a match, mean the same thing (`ultracode/`, `ultracode-v2`),
/// plus `?` — a question about the feature is not a request to use it.
fn reject_after() -> [char; 4] {
    ['/', '\\', '-', '?']
}

/// Returns true when the operator explicitly asked for multi-agent orchestration in this prompt.
///
/// The rules, in the order they are applied:
///
/// 1. If the trimmed input starts with `/`, return false. Slash commands never trigger: they are
///    frontend control, not a request addressed to the model.
/// 2. Any match inside a fenced code block (between ``` markers) or inside inline backticks is
///    ignored. Quoting a term is talking *about* it.
/// 3. [`ascii_terms()`] match case-insensitively and require a word boundary on both sides, where a
///    word character is Unicode `[\p{L}\p{N}_]`. A match is additionally rejected when the
///    preceding character is one of [`reject_before()`], the following character is one of
///    [`reject_after()`], or the match is followed by `.` plus a word character — so `ultracode.ts`
///    is a filename, not a request.
/// 4. [`cjk_terms()`] match as plain substrings, with no boundary test at all (see that constant for
///    why that asymmetry is deliberate).
/// 5. One hit is enough. Nothing is counted or weighted.
pub fn requests_orchestration(input: &str) -> bool {
    let trimmed = input.trim_start();
    if trimmed.starts_with('/') {
        return false;
    }
    // Lower-casing after masking keeps every index in this one string: neighbour lookups below
    // read the same buffer the match came from, so there is no mapping back to the original.
    let haystack = mask_code(trimmed).to_lowercase();
    if cjk_terms().iter().any(|term| haystack.contains(term)) {
        return true;
    }
    ascii_terms().iter().any(|term| {
        haystack
            .match_indices(term)
            .any(|(at, matched)| standalone(&haystack, at, at + matched.len()))
    })
}

/// Blank out every character inside a fenced block or an inline code span, the delimiters included.
///
/// Backtick runs of three or more toggle the fence; runs of one or two toggle an inline span, but
/// only outside a fence (a lone backtick inside a code block is just a character). An unterminated
/// opener masks to end of input, which is the fail-closed direction: an unclosed span is more
/// likely a half-typed quote than prose that meant to trigger a fan-out.
fn mask_code(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut index = 0usize;
    let mut in_fence = false;
    let mut in_inline = false;
    while index < chars.len() {
        if chars[index] == '`' {
            let start = index;
            while index < chars.len() && chars[index] == '`' {
                index += 1;
            }
            let run = index - start;
            if run >= 3 {
                // A fence delimiter also ends any inline span: nothing sane spans both.
                in_inline = false;
                in_fence = !in_fence;
            } else if !in_fence {
                in_inline = !in_inline;
            }
            for _ in 0..run {
                out.push(mask());
            }
            continue;
        }
        out.push(if in_fence || in_inline {
            mask()
        } else {
            chars[index]
        });
        index += 1;
    }
    out
}

/// Is the match at `[start, end)` a standalone word rather than part of a path, flag, filename, or
/// longer identifier?
fn standalone(haystack: &str, start: usize, end: usize) -> bool {
    if let Some(before) = haystack[..start].chars().next_back()
        && (is_word_char(before) || reject_before().contains(&before))
    {
        return false;
    }
    let mut after = haystack[end..].chars();
    match after.next() {
        None => true,
        Some(next) if is_word_char(next) || reject_after().contains(&next) => false,
        // `ultracode.ts` is a file; `use ultracode. Then …` is a sentence.
        Some('.') => !after.next().is_some_and(is_word_char),
        Some(_) => true,
    }
}

/// Unicode `[\p{L}\p{N}_]`, which is what the word-boundary rule is defined against.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::requests_orchestration;

    #[test]
    fn plain_ascii_hit() {
        assert!(requests_orchestration(
            "please use ultracode to split this up"
        ));
        assert!(requests_orchestration("try ultra code on the refactor"));
        assert!(requests_orchestration("run a dynamic workflow for this"));
        assert!(requests_orchestration("dynamic workflows please"));
    }

    #[test]
    fn capitalisation_is_ignored() {
        assert!(requests_orchestration("Ultracode this"));
        assert!(requests_orchestration("ULTRACODE"));
        assert!(requests_orchestration("Dynamic Workflow now"));
    }

    #[test]
    fn inline_backticks_do_not_trigger() {
        assert!(!requests_orchestration("what does `ultracode` mean"));
        assert!(!requests_orchestration("the `dynamic workflow` flag"));
    }

    #[test]
    fn fenced_block_does_not_trigger() {
        assert!(!requests_orchestration(
            "look at this:\n```\nultracode\n```\nwhat is it"
        ));
    }

    #[test]
    fn filename_does_not_trigger() {
        assert!(!requests_orchestration("open ultracode.ts"));
        assert!(!requests_orchestration("read src/ultracode for me"));
        assert!(!requests_orchestration("pass --ultracode to the binary"));
        assert!(!requests_orchestration("is ultracode-v2 ready"));
        assert!(!requests_orchestration("what is ultracode?"));
        assert!(!requests_orchestration("ultracodex is a different thing"));
    }

    #[test]
    fn trailing_sentence_period_still_triggers() {
        assert!(requests_orchestration("use ultracode."));
        assert!(requests_orchestration("use ultracode. Then stop."));
    }

    #[test]
    fn slash_command_never_triggers() {
        assert!(!requests_orchestration("/effort ultracode"));
        assert!(!requests_orchestration("   /ultracode"));
    }

    #[test]
    fn cjk_terms_trigger_as_substrings() {
        assert!(requests_orchestration("帮我用动态工作流拆一下这个任务"));
        assert!(requests_orchestration("这里需要工作流编排"));
        assert!(requests_orchestration("试试并行编排吧"));
    }

    #[test]
    fn cjk_inside_code_still_does_not_trigger() {
        assert!(!requests_orchestration("这个词 `动态工作流` 是什么意思"));
    }

    #[test]
    fn unrelated_prompt_does_not_trigger() {
        assert!(!requests_orchestration("fix the failing test in tui.rs"));
        assert!(!requests_orchestration(""));
        assert!(!requests_orchestration("ultra codes are unrelated"));
    }
}
