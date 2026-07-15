//! A zero-dependency, benign-by-design syntax highlighter (ADR-015 R6).
//!
//! The DISPLAY language set a coding agent renders is unbounded and disjoint from the few it edits,
//! and a MIS-lex is worse than monochrome. So this is NOT seven bespoke lexers: it is ONE generic
//! token scanner driven by a small per-language config (`LangSpec`: comment/string syntax + keyword
//! set). It colors the lexically-universal classes (strings, comments, numbers, keywords, and a
//! Capitalized→Type / ident-before-`(`→Func heuristic); an unknown language falls back to
//! strings/comments/numbers only — no keyword guessing, so it never mis-highlights. State that must
//! cross lines (block-comment depth for nesting langs, Python triple-quote) lives in `LexState` with
//! error recovery: an unterminated single/double string just ends at the line and resets, never
//! propagating a wrong multi-line state.

use crate::theme::{SynClass, Theme};
use ratatui::text::Span;

/// Cross-line lexer state (R6). Bounded: only a small block-comment depth and an optional open
/// triple-quote delimiter.
#[derive(Debug, Clone, Default)]
pub struct LexState {
    block_depth: u16,
    triple: Option<char>,
}

impl LexState {
    pub fn new() -> Self {
        LexState::default()
    }
}

struct LangSpec {
    line_comments: &'static [&'static str],
    block: Option<(&'static str, &'static str)>,
    nest_block: bool,
    strings: &'static [char],
    triple: bool, // python-style triple-quote multiline strings
    keywords: &'static [&'static str],
    types_capitalized: bool,
}

const GENERIC: LangSpec = LangSpec {
    line_comments: &["#", "//"],
    block: Some(("/*", "*/")),
    nest_block: false,
    strings: &['"', '\''],
    triple: false,
    keywords: &[],
    types_capitalized: false,
};

fn spec_for(lang: Option<&str>) -> LangSpec {
    let l = lang.unwrap_or("").trim().to_ascii_lowercase();
    match l.as_str() {
        "rust" | "rs" => LangSpec {
            line_comments: &["//"],
            block: Some(("/*", "*/")),
            nest_block: true,
            strings: &['"'],
            triple: false,
            types_capitalized: true,
            keywords: &[
                "fn",
                "let",
                "mut",
                "pub",
                "struct",
                "enum",
                "impl",
                "trait",
                "for",
                "while",
                "loop",
                "if",
                "else",
                "match",
                "return",
                "use",
                "mod",
                "crate",
                "self",
                "Self",
                "move",
                "ref",
                "as",
                "where",
                "async",
                "await",
                "dyn",
                "const",
                "static",
                "unsafe",
                "break",
                "continue",
                "in",
                "type",
                "default",
                "macro_rules",
            ],
        },
        "ts" | "typescript" | "js" | "javascript" | "tsx" | "jsx" | "mjs" => LangSpec {
            line_comments: &["//"],
            block: Some(("/*", "*/")),
            nest_block: false,
            strings: &['"', '\'', '`'],
            triple: false,
            types_capitalized: true,
            keywords: &[
                "function",
                "const",
                "let",
                "var",
                "if",
                "else",
                "for",
                "while",
                "return",
                "class",
                "extends",
                "new",
                "import",
                "export",
                "from",
                "default",
                "async",
                "await",
                "yield",
                "try",
                "catch",
                "finally",
                "throw",
                "typeof",
                "instanceof",
                "in",
                "of",
                "this",
                "super",
                "interface",
                "type",
                "enum",
                "public",
                "private",
                "protected",
                "readonly",
                "static",
                "void",
                "null",
                "undefined",
                "true",
                "false",
            ],
        },
        "python" | "py" => LangSpec {
            line_comments: &["#"],
            block: None,
            nest_block: false,
            strings: &['"', '\''],
            triple: true,
            types_capitalized: true,
            keywords: &[
                "def", "class", "return", "if", "elif", "else", "for", "while", "import", "from",
                "as", "with", "try", "except", "finally", "raise", "yield", "lambda", "global",
                "nonlocal", "pass", "break", "continue", "in", "is", "not", "and", "or", "None",
                "True", "False", "self", "async", "await",
            ],
        },
        "go" => LangSpec {
            line_comments: &["//"],
            block: Some(("/*", "*/")),
            nest_block: false,
            strings: &['"', '`'],
            triple: false,
            types_capitalized: true,
            keywords: &[
                "func",
                "package",
                "import",
                "var",
                "const",
                "type",
                "struct",
                "interface",
                "map",
                "chan",
                "go",
                "defer",
                "return",
                "if",
                "else",
                "for",
                "range",
                "switch",
                "case",
                "default",
                "break",
                "continue",
                "select",
                "nil",
                "true",
                "false",
            ],
        },
        "c" | "cpp" | "c++" | "h" | "hpp" | "cc" => LangSpec {
            line_comments: &["//"],
            block: Some(("/*", "*/")),
            nest_block: false,
            strings: &['"', '\''],
            triple: false,
            types_capitalized: false,
            keywords: &[
                "int",
                "char",
                "float",
                "double",
                "void",
                "long",
                "short",
                "unsigned",
                "signed",
                "struct",
                "class",
                "enum",
                "union",
                "const",
                "static",
                "return",
                "if",
                "else",
                "for",
                "while",
                "switch",
                "case",
                "default",
                "break",
                "continue",
                "sizeof",
                "typedef",
                "namespace",
                "template",
                "public",
                "private",
                "protected",
                "new",
                "delete",
                "nullptr",
                "true",
                "false",
                "auto",
            ],
        },
        "java" | "kotlin" | "kt" => LangSpec {
            line_comments: &["//"],
            block: Some(("/*", "*/")),
            nest_block: false,
            strings: &['"'],
            triple: false,
            types_capitalized: true,
            keywords: &[
                "public",
                "private",
                "protected",
                "class",
                "interface",
                "extends",
                "implements",
                "static",
                "final",
                "void",
                "int",
                "long",
                "double",
                "float",
                "boolean",
                "char",
                "return",
                "if",
                "else",
                "for",
                "while",
                "switch",
                "case",
                "default",
                "break",
                "continue",
                "new",
                "this",
                "super",
                "try",
                "catch",
                "finally",
                "throw",
                "throws",
                "import",
                "package",
                "fun",
                "val",
                "var",
                "null",
                "true",
                "false",
            ],
        },
        "json" => LangSpec {
            line_comments: &[],
            block: None,
            nest_block: false,
            strings: &['"'],
            triple: false,
            keywords: &["true", "false", "null"],
            types_capitalized: false,
        },
        "toml" | "ini" => LangSpec {
            line_comments: &["#"],
            block: None,
            nest_block: false,
            strings: &['"', '\''],
            triple: false,
            keywords: &["true", "false"],
            types_capitalized: false,
        },
        "yaml" | "yml" => LangSpec {
            line_comments: &["#"],
            block: None,
            nest_block: false,
            strings: &['"', '\''],
            triple: false,
            keywords: &["true", "false", "null"],
            types_capitalized: false,
        },
        "bash" | "sh" | "shell" | "zsh" => LangSpec {
            line_comments: &["#"],
            block: None,
            nest_block: false,
            strings: &['"', '\''],
            triple: false,
            types_capitalized: false,
            keywords: &[
                "if", "then", "else", "elif", "fi", "for", "while", "do", "done", "case", "esac",
                "function", "return", "in", "export", "local", "echo", "cd", "source", "set",
                "unset",
            ],
        },
        "sql" => LangSpec {
            line_comments: &["--"],
            block: Some(("/*", "*/")),
            nest_block: false,
            strings: &['\'', '"'],
            triple: false,
            types_capitalized: false,
            keywords: &[
                "select",
                "from",
                "where",
                "insert",
                "into",
                "values",
                "update",
                "set",
                "delete",
                "create",
                "table",
                "drop",
                "alter",
                "join",
                "left",
                "right",
                "inner",
                "outer",
                "on",
                "group",
                "by",
                "order",
                "having",
                "limit",
                "and",
                "or",
                "not",
                "null",
                "primary",
                "key",
                "foreign",
                "references",
                "index",
                "as",
                "distinct",
                "count",
                "sum",
                "avg",
            ],
        },
        // css/scss/less: `#` is an id-selector / hex color, NOT a comment (the worst GENERIC mis-lex).
        "css" | "scss" | "less" => LangSpec {
            line_comments: &["//"],
            block: Some(("/*", "*/")),
            nest_block: false,
            strings: &['"', '\''],
            triple: false,
            keywords: &[],
            types_capitalized: false,
        },
        // html/xml/svg/vue: comments are <!-- -->, and `#` is never a comment.
        "html" | "xml" | "svg" | "vue" => LangSpec {
            line_comments: &[],
            block: Some(("<!--", "-->")),
            nest_block: false,
            strings: &['"', '\''],
            triple: false,
            keywords: &[],
            types_capitalized: false,
        },
        // swift: `#if`/`#selector` etc. must not grey the line; no `'` string.
        "swift" => LangSpec {
            line_comments: &["//"],
            block: Some(("/*", "*/")),
            nest_block: true,
            strings: &['"'],
            triple: true,
            types_capitalized: true,
            keywords: &[
                "func",
                "let",
                "var",
                "struct",
                "class",
                "enum",
                "protocol",
                "extension",
                "guard",
                "if",
                "else",
                "switch",
                "case",
                "return",
                "import",
                "where",
                "async",
                "await",
                "throws",
                "try",
                "for",
                "in",
                "while",
                "self",
                "nil",
                "true",
                "false",
            ],
        },
        // markdown: `#` is a heading, not a comment — treat as near-plain.
        "markdown" | "md" => LangSpec {
            line_comments: &[],
            block: None,
            nest_block: false,
            strings: &[],
            triple: false,
            keywords: &[],
            types_capitalized: false,
        },
        // dockerfile / make: `#` IS a comment (already the GENERIC default, but pin them so `//` isn't).
        "dockerfile" | "docker" | "make" | "makefile" => LangSpec {
            line_comments: &["#"],
            block: None,
            nest_block: false,
            strings: &['"', '\''],
            triple: false,
            keywords: &[],
            types_capitalized: false,
        },
        _ => GENERIC,
    }
}

/// Highlight one line into styled spans, advancing `st` for multi-line constructs.
pub fn code_spans(
    lang: Option<&str>,
    line: &str,
    st: &mut LexState,
    theme: &Theme,
) -> Vec<Span<'static>> {
    let spec = spec_for(lang);
    let chars: Vec<char> = line.chars().collect();
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut i = 0;
    let n = chars.len();
    let push = |spans: &mut Vec<Span<'static>>, s: &str, class: SynClass, theme: &Theme| {
        if !s.is_empty() {
            spans.push(Span::styled(s.to_string(), theme.syn_style(class)));
        }
    };

    // continuation of a triple-quoted string
    if let Some(q) = st.triple {
        let close = format!("{q}{q}{q}");
        if let Some(pos) = find_sub(&chars, 0, &close) {
            let end = pos + 3;
            push(&mut spans, &collect(&chars, 0, end), SynClass::Str, theme);
            st.triple = None;
            i = end;
        } else {
            push(&mut spans, line, SynClass::Str, theme);
            return spans;
        }
    }
    // continuation of a block comment
    if st.block_depth > 0
        && let Some((_, close)) = spec.block
    {
        i = consume_block_comment(
            &chars,
            i,
            close,
            spec.nest_block,
            &mut st.block_depth,
            &mut spans,
            theme,
        );
        if st.block_depth > 0 {
            return spans;
        }
    }

    while i < n {
        let c = chars[i];
        // whitespace run
        if c.is_whitespace() {
            let start = i;
            while i < n && chars[i].is_whitespace() {
                i += 1;
            }
            spans.push(Span::raw(collect(&chars, start, i)));
            continue;
        }
        // line comment
        if spec
            .line_comments
            .iter()
            .any(|t| starts_with_at(&chars, i, t))
        {
            push(&mut spans, &collect(&chars, i, n), SynClass::Comment, theme);
            break;
        }
        // block comment open
        if let Some((open, close)) = spec.block
            && starts_with_at(&chars, i, open)
        {
            st.block_depth += 1;
            push(&mut spans, open, SynClass::Comment, theme);
            i += open.chars().count();
            i = consume_block_comment(
                &chars,
                i,
                close,
                spec.nest_block,
                &mut st.block_depth,
                &mut spans,
                theme,
            );
            continue;
        }
        // triple-quoted string open
        if spec.triple
            && (c == '"' || c == '\'')
            && starts_with_at(&chars, i, &format!("{c}{c}{c}"))
        {
            let close = format!("{c}{c}{c}");
            if let Some(pos) = find_sub(&chars, i + 3, &close) {
                let end = pos + 3;
                push(&mut spans, &collect(&chars, i, end), SynClass::Str, theme);
                i = end;
            } else {
                push(&mut spans, &collect(&chars, i, n), SynClass::Str, theme);
                st.triple = Some(c);
                i = n;
            }
            continue;
        }
        // string / char literal (single line; error-recovery: unterminated ends at line, resets)
        if spec.strings.contains(&c) {
            let end = scan_string(&chars, i, c);
            push(&mut spans, &collect(&chars, i, end), SynClass::Str, theme);
            i = end;
            continue;
        }
        // number — a real numeric grammar (not a blanket alnum class) so `1..10`, `1.toString()`,
        // `3if` don't get swallowed into one Number token and desync the stream (highlighter audit).
        if c.is_ascii_digit() {
            let start = i;
            // radix prefix
            if c == '0' && i + 1 < n && matches!(chars[i + 1], 'x' | 'X' | 'o' | 'O' | 'b' | 'B') {
                i += 2;
                while i < n && (chars[i].is_ascii_hexdigit() || chars[i] == '_') {
                    i += 1;
                }
            } else {
                while i < n && (chars[i].is_ascii_digit() || chars[i] == '_') {
                    i += 1;
                }
                // a single '.' only when followed by a digit (so `1..10` stops before `..`)
                if i + 1 < n && chars[i] == '.' && chars[i + 1].is_ascii_digit() {
                    i += 1;
                    while i < n && (chars[i].is_ascii_digit() || chars[i] == '_') {
                        i += 1;
                    }
                }
                // exponent
                if i < n && matches!(chars[i], 'e' | 'E') {
                    let mut j = i + 1;
                    if j < n && matches!(chars[j], '+' | '-') {
                        j += 1;
                    }
                    if j < n && chars[j].is_ascii_digit() {
                        i = j;
                        while i < n && chars[i].is_ascii_digit() {
                            i += 1;
                        }
                    }
                }
            }
            // a trailing numeric type suffix (u8/f32/i64/L/n), stopping at '.' or '('
            while i < n && (chars[i].is_ascii_alphanumeric()) && chars[i] != '.' {
                i += 1;
            }
            push(
                &mut spans,
                &collect(&chars, start, i),
                SynClass::Number,
                theme,
            );
            continue;
        }
        // identifier / keyword / type / func
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < n && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word = collect(&chars, start, i);
            let class = if spec.keywords.contains(&word.as_str()) {
                SynClass::Keyword
            } else if i < n && chars[i] == '(' {
                SynClass::Func
            } else if spec.types_capitalized
                && word
                    .chars()
                    .next()
                    .map(|c| c.is_uppercase())
                    .unwrap_or(false)
            {
                SynClass::Type
            } else {
                SynClass::Text
            };
            push(&mut spans, &word, class, theme);
            continue;
        }
        // punctuation / operator
        let start = i;
        i += 1;
        push(
            &mut spans,
            &collect(&chars, start, i),
            SynClass::Punct,
            theme,
        );
    }
    if spans.is_empty() {
        spans.push(Span::raw(String::new()));
    }
    spans
}

fn consume_block_comment(
    chars: &[char],
    mut i: usize,
    close: &str,
    nest: bool,
    depth: &mut u16,
    spans: &mut Vec<Span<'static>>,
    theme: &Theme,
) -> usize {
    let open = "/*";
    let start = i;
    while i < chars.len() {
        if nest && starts_with_at(chars, i, open) {
            *depth += 1;
            i += 2;
            continue;
        }
        if starts_with_at(chars, i, close) {
            i += close.chars().count();
            *depth -= 1;
            if *depth == 0 {
                break;
            }
            continue;
        }
        i += 1;
    }
    if i > start {
        let s = collect(chars, start, i);
        spans.push(Span::styled(s, theme.syn_style(SynClass::Comment)));
    }
    i
}

fn scan_string(chars: &[char], open: usize, delim: char) -> usize {
    let mut i = open + 1;
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
            continue;
        }
        if chars[i] == delim {
            return i + 1;
        }
        i += 1;
    }
    chars.len() // unterminated: to end of line (error recovery — state not propagated)
}

fn starts_with_at(chars: &[char], i: usize, pat: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    i + p.len() <= chars.len() && chars[i..i + p.len()] == p[..]
}

fn find_sub(chars: &[char], from: usize, pat: &str) -> Option<usize> {
    let p: Vec<char> = pat.chars().collect();
    // Guard: when the line is shorter than the pattern there is no match. Without this, the
    // `..=len.saturating_sub(p.len())` inclusive bound clamps to 0 and still evaluates j=0, slicing
    // chars[0..p.len()] out of bounds — a CRITICAL panic on any blank/short line inside an open
    // Python triple-quoted string (a normal docstring), crashing the whole TUI every frame (review).
    if p.is_empty() || chars.len() < from + p.len() {
        return None;
    }
    (from..=chars.len() - p.len()).find(|&j| chars[j..j + p.len()] == p[..])
}

fn collect(chars: &[char], from: usize, to: usize) -> String {
    chars[from..to.min(chars.len())].iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(lang: &str, line: &str, st: &mut LexState) -> Vec<String> {
        let theme = Theme::dark();
        code_spans(Some(lang), line, st, &theme)
            .iter()
            .map(|s| s.content.to_string())
            .collect()
    }

    #[test]
    fn rust_keywords_and_strings() {
        let theme = Theme::dark();
        let mut st = LexState::new();
        let spans = code_spans(Some("rust"), "let x = \"hi\"; // c", &mut st, &theme);
        let text: String = spans.iter().map(|s| s.content.to_string()).collect();
        assert_eq!(
            text, "let x = \"hi\"; // c",
            "highlighter is lossless (round-trips the text)"
        );
        // keyword `let` colored differently from plain text
        let let_span = spans.iter().find(|s| s.content.trim() == "let").unwrap();
        let x_span = spans.iter().find(|s| s.content.trim() == "x").unwrap();
        assert_ne!(
            let_span.style.fg, x_span.style.fg,
            "keyword and identifier differ"
        );
    }

    #[test]
    fn multiline_block_comment_carries_state() {
        let theme = Theme::dark();
        let mut st = LexState::new();
        let _ = code_spans(Some("rust"), "code /* start", &mut st, &theme);
        assert!(
            st.block_depth > 0,
            "open block comment carries to next line"
        );
        let spans = code_spans(Some("rust"), "still comment */ let y = 1;", &mut st, &theme);
        assert_eq!(st.block_depth, 0, "close resets");
        // `let` after the close is a keyword again
        assert!(spans.iter().any(|s| s.content.trim() == "let"));
    }

    #[test]
    fn python_triple_string_carries() {
        let theme = Theme::dark();
        let mut st = LexState::new();
        let _ = code_spans(Some("python"), "x = '''start", &mut st, &theme);
        assert_eq!(st.triple, Some('\''));
        let _ = code_spans(Some("python"), "still string''' + y", &mut st, &theme);
        assert_eq!(st.triple, None);
    }

    #[test]
    fn unterminated_string_does_not_propagate() {
        // R6 error recovery: an unterminated single/double string ends at the line, state clean.
        let theme = Theme::dark();
        let mut st = LexState::new();
        let _ = code_spans(Some("rust"), "let s = \"oops no close", &mut st, &theme);
        assert_eq!(st.block_depth, 0);
        assert_eq!(st.triple, None);
    }

    #[test]
    fn unknown_language_is_lossless_and_benign() {
        let mut st = LexState::new();
        let out = classes("cobol", "MOVE X TO Y. * comment", &mut st).join("");
        assert_eq!(out, "MOVE X TO Y. * comment");
    }

    #[test]
    fn open_triple_string_then_blank_or_short_line_does_not_panic() {
        // CRITICAL regression: an open Python triple-quoted string followed by a blank or <=2-char
        // line (a normal docstring) must not panic find_sub — it crashed the whole TUI every frame.
        let theme = Theme::dark();
        for follow in ["", "a", "ab", "  ", "\t"] {
            let mut st = LexState::new();
            let _ = code_spans(Some("python"), "def f():", &mut st, &theme);
            let _ = code_spans(Some("python"), "    '''", &mut st, &theme); // opens triple
            let _ = code_spans(Some("python"), follow, &mut st, &theme); // must not panic
            let _ = code_spans(Some("python"), "    '''", &mut st, &theme); // closes
            assert_eq!(st.triple, None, "triple closed after follow={follow:?}");
        }
    }

    #[test]
    fn number_scanner_does_not_swallow_following_tokens() {
        let theme = Theme::dark();
        // `1..10`: the `1` is a Number and `..10` is NOT part of it (no desync).
        let mut st = LexState::new();
        let spans = code_spans(Some("rust"), "arr[1..10]", &mut st, &theme);
        let one = spans
            .iter()
            .find(|s| s.content == "1")
            .expect("`1` is its own number token");
        assert_eq!(one.style.fg, Some(theme.syn_number));
        // `1.toString()`: `1` number, then `.` then `toString`
        let mut st = LexState::new();
        let spans = code_spans(Some("ts"), "let x = 1.toString();", &mut st, &theme);
        assert!(spans.iter().any(|s| s.content == "1"), "1 is its own token");
        assert!(
            spans.iter().any(|s| s.content == "toString"),
            "method name not swallowed"
        );
    }

    #[test]
    fn css_and_markdown_hash_is_not_a_comment() {
        let theme = Theme::dark();
        // CSS `#main` — the whole line must NOT be greyed as a comment.
        let mut st = LexState::new();
        let spans = code_spans(Some("css"), "#main { color: #fff; }", &mut st, &theme);
        let all_comment = spans
            .iter()
            .filter(|s| !s.content.trim().is_empty())
            .all(|s| s.style.fg == Some(theme.syn_comment));
        assert!(!all_comment, "CSS #selector must not grey the whole line");
        // Markdown heading likewise.
        let mut st = LexState::new();
        let spans = code_spans(Some("markdown"), "# Heading Title", &mut st, &theme);
        assert!(
            spans.iter().all(|s| s.style.fg != Some(theme.syn_comment)),
            "md heading is not a comment"
        );
    }

    #[test]
    fn find_sub_shorter_than_pattern_is_none() {
        assert_eq!(find_sub(&['a'], 0, "'''"), None);
        assert_eq!(find_sub(&[], 0, "'''"), None);
        assert_eq!(find_sub(&['a', 'b', 'c'], 2, "'''"), None);
    }

    const LANGS: &[&str] = &[
        "rust", "ts", "python", "go", "c", "java", "json", "toml", "yaml", "bash", "sql", "cobol",
    ];

    fn rt_line(lang: &str, line: &str, st: &mut LexState) -> String {
        let theme = Theme::dark();
        code_spans(Some(lang), line, st, &theme)
            .iter()
            .map(|s| s.content.to_string())
            .collect()
    }

    #[test]
    fn roundtrip_single_line_tricky() {
        let tricky = [
            "let s = \"http://x\"; // c",
            "r#\"he said \\\"hi\\\" \"#",
            "f\"val={x}\" + '''triple'''",
            "`tmpl ${x} /re/g` a / b",
            "echo 'it\\'s' \"a#b\"",
            "cat <<EOF",
            "x = \"a\\\"b\" # tail",
            "/* a /* b */ c */ let z = 1;",
            "'''",
            "\"\"\"",
            "\"\"\"\"",
            "''''''",
            "SELECT * FROM t -- c",
            "0x1F 3.14e10 1..10 1_000",
            "a\\",
            "\\",
            "\"\\",
            "\"unterminated",
            "  ",
            "\t\tx",
            "",
            "型 = \"日本語\" // 注释",
            "}{)(][><.,;:!@#$%^&*-+=~",
        ];
        for lang in LANGS {
            for line in tricky {
                let mut st = LexState::new();
                let out = rt_line(lang, line, &mut st);
                assert_eq!(out, line, "DROP lang={lang} line={line:?} -> {out:?}");
            }
        }
    }

    #[test]
    fn roundtrip_multiline_sequences() {
        let seqs: &[(&str, &[&str])] = &[
            (
                "rust",
                &["code /* open", "still /* nested", "close */ */ let y=1;"],
            ),
            ("python", &["x = '''start", "", "  ", "a", "still''' + y"]),
            (
                "python",
                &["s = \"\"\"doc", "line \\ with backslash", "end\"\"\""],
            ),
            ("ts", &["const t = `line1", "line2 ${x}", "line3`;"]),
            ("bash", &["cat <<EOF", "  body $x #notcomment", "EOF"]),
            ("c", &["/* multi", "line * / not close", "real */ int x;"]),
        ];
        for (lang, lines) in seqs {
            let mut st = LexState::new();
            for line in *lines {
                let out = rt_line(lang, line, &mut st);
                assert_eq!(
                    out, *line,
                    "DROP multiline lang={lang} line={line:?} -> {out:?}"
                );
            }
        }
    }

    #[test]
    fn roundtrip_fuzz_no_drop_no_panic() {
        // xorshift, deterministic
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet: Vec<char> = "\"'`\\/*#-{}()[]<>=+ \tabcxyz01._$".chars().collect();
        for _ in 0..20000 {
            let len = (next() % 12) as usize;
            let line: String = (0..len)
                .map(|_| alphabet[(next() as usize) % alphabet.len()])
                .collect();
            for lang in LANGS {
                // fresh state per line keeps it a pure single-line round-trip check
                let mut st = LexState::new();
                let out = rt_line(lang, &line, &mut st);
                assert_eq!(out, line, "FUZZ DROP lang={lang} line={line:?} -> {out:?}");
            }
        }
    }

    #[test]
    fn roundtrip_fuzz_multiline_stateful() {
        let mut state: u64 = 0xDEADBEEFCAFEF00D;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet: Vec<char> = "\"'`\\/*#{} \tab01".chars().collect();
        for lang in LANGS {
            let mut st = LexState::new();
            for _ in 0..5000 {
                let len = (next() % 8) as usize;
                let line: String = (0..len)
                    .map(|_| alphabet[(next() as usize) % alphabet.len()])
                    .collect();
                let out = rt_line(lang, &line, &mut st);
                assert_eq!(
                    out, line,
                    "FUZZ STATE DROP lang={lang} line={line:?} -> {out:?}"
                );
            }
        }
    }
}
