//! Code intelligence: definition, references, hover.
//!
//! The protocol lets a server answer the same question in several shapes. `textDocument/definition`
//! may return a single `Location`, an array of them, an array of `LocationLink`s, or null -- all
//! valid, all in the wild, chosen per server and sometimes per call. A caller that handles only the
//! array form silently loses every single-result answer, which reads as "no definition found" and
//! is the worst possible failure for an agent: confidently wrong rather than visibly broken. So the
//! union is normalised here, once.
//!
//! Results are ordered and bounded. Ordering is not cosmetic: an agent that feeds "the first
//! reference" into an edit must get the same one on every run, and servers do not promise a stable
//! order. Truncation is counted and reported rather than silently applied.

use crate::{LspError, MAX_LOCATIONS, documents::DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Location {
    pub uri: String,
    pub range: Range,
}

/// What a caller asked for. The method string is derived here so a typo cannot produce a request
/// that a server answers with silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query {
    Definition,
    References { include_declaration: bool },
    Hover,
}

impl Query {
    pub fn method(self) -> &'static str {
        match self {
            Query::Definition => "textDocument/definition",
            Query::References { .. } => "textDocument/references",
            Query::Hover => "textDocument/hover",
        }
    }

    /// Build the `params` object. `uri` is passed through verbatim: percent-encoding is the
    /// caller's business, and re-encoding here would corrupt a URI that is already correct.
    pub fn params(self, uri: &str, at: Position) -> Value {
        let mut params = json!({
            "textDocument": { "uri": uri },
            "position": { "line": at.line, "character": at.character },
        });
        if let Query::References {
            include_declaration,
        } = self
        {
            params["context"] = json!({ "includeDeclaration": include_declaration });
        }
        params
    }
}

/// A normalised answer plus what had to be discarded to produce it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Locations {
    pub locations: Vec<Location>,
    /// Results dropped because the answer exceeded the bound. Reported so a caller can say
    /// "first 200 of 4,000" instead of implying it saw everything.
    pub truncated: usize,
    /// Entries that did not parse as either shape. A server sending one malformed entry must not
    /// discard the whole answer, but the loss is still counted.
    pub malformed: usize,
}

/// Normalise `Location | Location[] | LocationLink[] | null` into an ordered, bounded list.
///
/// `LocationLink` is folded onto its `targetSelectionRange` when present -- that is the identifier
/// itself, whereas `targetRange` spans the whole definition body. Jumping to the body start is
/// technically "correct" and practically useless.
pub fn parse_locations(value: &Value, limit: usize) -> Locations {
    let mut out = Locations::default();
    let items: Vec<&Value> = match value {
        Value::Null => return out,
        Value::Array(items) => items.iter().collect(),
        single => vec![single],
    };

    for item in items {
        match location_from(item) {
            Some(location) => out.locations.push(location),
            None => out.malformed += 1,
        }
    }

    // Sort before truncating, so the bound keeps a deterministic prefix rather than whichever
    // entries the server happened to emit first.
    out.locations.sort();
    out.locations.dedup();
    if out.locations.len() > limit {
        out.truncated = out.locations.len() - limit;
        out.locations.truncate(limit);
    }
    out
}

fn location_from(item: &Value) -> Option<Location> {
    if let Some(uri) = item.get("uri").and_then(Value::as_str) {
        return Some(Location {
            uri: uri.to_owned(),
            range: range_from(item.get("range")?)?,
        });
    }
    // LocationLink: prefer the selection range (the identifier) over the full target range.
    let uri = item.get("targetUri").and_then(Value::as_str)?;
    let target = item.get("targetRange").and_then(range_from);
    let selection = item.get("targetSelectionRange").and_then(range_from);

    // The spec requires the selection range to lie within the target range. A server that violates
    // it would otherwise have us jump outside the definition it claims to be pointing at, so the
    // pair is rejected rather than half-believed.
    if let (Some(t), Some(sel)) = (target, selection)
        && !contains(&t, &sel)
    {
        return None;
    }
    let range = selection.or(target)?;
    Some(Location {
        uri: uri.to_owned(),
        range,
    })
}

fn contains(outer: &Range, inner: &Range) -> bool {
    (inner.start.line, inner.start.character) >= (outer.start.line, outer.start.character)
        && (inner.end.line, inner.end.character) <= (outer.end.line, outer.end.character)
}

/// Validate a `Range` payload. Public so the document store can share exactly this validation
/// rather than growing a second, subtly different one.
pub fn range_of(value: &Value) -> Option<Range> {
    range_from(value)
}

fn range_from(value: &Value) -> Option<Range> {
    let start = position_from(value.get("start")?)?;
    let end = position_from(value.get("end")?)?;
    // An inverted range is not a range. Passing one through produces a negative length wherever a
    // caller subtracts, and silently selects the wrong span wherever it does not.
    if (end.line, end.character) < (start.line, start.character) {
        return None;
    }
    Some(Range { start, end })
}

/// LSP `uinteger` is `0 ..= 2^31 - 1`, not the full `u32` range.
///
/// Accepting up to `u32::MAX` lets a server hand back a coordinate the protocol cannot express,
/// which downstream arithmetic (`line + 1`, range containment) then treats as a real position.
const MAX_UINTEGER: u64 = (1u64 << 31) - 1;

fn uinteger(value: &Value) -> Option<u32> {
    // `as_u64` rejects negative and fractional values, so `-1` or `1.5` is malformed rather than
    // wrapped or rounded.
    let n = value.as_u64()?;
    if n > MAX_UINTEGER {
        return None;
    }
    u32::try_from(n).ok()
}

fn position_from(value: &Value) -> Option<Position> {
    Some(Position {
        line: uinteger(value.get("line")?)?,
        character: uinteger(value.get("character")?)?,
    })
}

/// Longest hover text carried into the agent's context.
///
/// A hover on a generic-heavy symbol legitimately runs to thousands of characters of expanded
/// types. Forwarding it whole spends the context window on one incidental lookup, so it is bounded
/// and the elision is marked -- a silently shortened type signature reads as a different, simpler
/// type, which is worse than an obviously cut one.
pub const MAX_HOVER_BYTES: usize = 4 * 1024;

/// Flatten hover contents into plain text.
///
/// Handles `MarkupContent`, a bare string, a `{language, value}` pair, and arrays of any of those.
/// Returns `None` for a hover with nothing in it, which is distinct from a hover that failed.
pub fn parse_hover_text(value: &Value) -> Option<String> {
    let contents = value.get("contents")?;
    let text = hover_fragment(contents);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() <= MAX_HOVER_BYTES {
        return Some(trimmed.to_owned());
    }
    let mut end = MAX_HOVER_BYTES;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = trimmed[..end].to_owned();
    out.push_str("\n[hover truncated]");
    Some(out)
}

fn hover_fragment(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(hover_fragment)
            .filter(|s| !s.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n\n"),
        Value::Object(_) => value
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        _ => String::new(),
    }
}

/// Reject an answer computed against text the agent has already replaced.
///
/// Code intelligence carries positions. Applying a position from an older revision to current text
/// silently points at the wrong line, so a stale answer is refused rather than returned with a
/// warning a caller may not read.
pub fn ensure_fresh(
    store: &DocumentStore,
    uri: &str,
    issued_at_version: i32,
) -> Result<(), LspError> {
    match store.version(uri) {
        Some(current) if current == issued_at_version => Ok(()),
        Some(current) => Err(LspError::StaleResult {
            have: current,
            issued: issued_at_version,
        }),
        None => Err(LspError::UnknownDocument {
            uri: uri.to_owned(),
        }),
    }
}

/// Default bound for one answer.
pub fn default_limit() -> usize {
    MAX_LOCATIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(uri: &str, line: u32) -> Value {
        json!({
            "uri": uri,
            "range": {
                "start": { "line": line, "character": 0 },
                "end": { "line": line, "character": 4 }
            }
        })
    }

    #[test]
    fn a_single_location_object_is_not_mistaken_for_no_result() {
        // The failure this guards: treating only the array form as valid turns every
        // single-definition answer into "not found".
        let parsed = parse_locations(&loc("file:///a.rs", 3), 10);
        assert_eq!(parsed.locations.len(), 1);
        assert_eq!(parsed.locations[0].uri, "file:///a.rs");
        assert_eq!(parsed.locations[0].range.start.line, 3);
    }

    #[test]
    fn an_array_of_locations_is_parsed() {
        let value = json!([loc("file:///a.rs", 1), loc("file:///b.rs", 2)]);
        assert_eq!(parse_locations(&value, 10).locations.len(), 2);
    }

    #[test]
    fn null_is_an_empty_answer_not_an_error() {
        assert_eq!(parse_locations(&Value::Null, 10), Locations::default());
    }

    #[test]
    fn location_link_folds_onto_the_identifier_not_the_body() {
        let value = json!([{
            "targetUri": "file:///a.rs",
            "targetRange":          { "start": {"line": 10, "character": 0}, "end": {"line": 40, "character": 1} },
            "targetSelectionRange": { "start": {"line": 12, "character": 7}, "end": {"line": 12, "character": 15} }
        }]);
        let parsed = parse_locations(&value, 10);
        assert_eq!(parsed.locations.len(), 1);
        // 12, the identifier -- not 10, the start of the whole definition body.
        assert_eq!(parsed.locations[0].range.start.line, 12);
        assert_eq!(parsed.locations[0].range.start.character, 7);
    }

    #[test]
    fn location_link_falls_back_to_target_range_when_selection_is_absent() {
        let value = json!([{
            "targetUri": "file:///a.rs",
            "targetRange": { "start": {"line": 5, "character": 0}, "end": {"line": 9, "character": 1} }
        }]);
        assert_eq!(parse_locations(&value, 10).locations[0].range.start.line, 5);
    }

    #[test]
    fn results_are_ordered_and_deduplicated() {
        let value = json!([
            loc("file:///b.rs", 5),
            loc("file:///a.rs", 9),
            loc("file:///a.rs", 2),
            loc("file:///a.rs", 2),
        ]);
        let parsed = parse_locations(&value, 10);
        let seen: Vec<(String, u32)> = parsed
            .locations
            .iter()
            .map(|l| (l.uri.clone(), l.range.start.line))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("file:///a.rs".into(), 2),
                ("file:///a.rs".into(), 9),
                ("file:///b.rs".into(), 5),
            ]
        );
    }

    #[test]
    fn truncation_keeps_a_deterministic_prefix_and_reports_the_loss() {
        // Emitted in descending order; the bound must still keep the lowest two.
        let value = json!([
            loc("file:///a.rs", 9),
            loc("file:///a.rs", 5),
            loc("file:///a.rs", 1),
        ]);
        let parsed = parse_locations(&value, 2);
        assert_eq!(parsed.truncated, 1);
        assert_eq!(
            parsed
                .locations
                .iter()
                .map(|l| l.range.start.line)
                .collect::<Vec<_>>(),
            vec![1, 5]
        );
    }

    #[test]
    fn one_malformed_entry_does_not_discard_the_whole_answer() {
        let value = json!([loc("file:///a.rs", 1), { "uri": "file:///b.rs" }]);
        let parsed = parse_locations(&value, 10);
        assert_eq!(parsed.locations.len(), 1);
        assert_eq!(parsed.malformed, 1);
    }

    #[test]
    fn negative_and_fractional_coordinates_are_malformed_not_wrapped() {
        for bad in [json!(-1), json!(1.5)] {
            let value = json!([{
                "uri": "file:///a.rs",
                "range": { "start": {"line": bad, "character": 0}, "end": {"line": 2, "character": 0} }
            }]);
            let parsed = parse_locations(&value, 10);
            assert!(parsed.locations.is_empty(), "{bad} must not parse");
            assert_eq!(parsed.malformed, 1);
        }
    }

    #[test]
    fn a_coordinate_beyond_lsp_uinteger_is_malformed() {
        // LSP `uinteger` is 0..=2^31-1, not the full u32 range. Accepting more lets a server hand
        // back a coordinate the protocol cannot express, which downstream arithmetic then treats
        // as a real position.
        let too_big = (1u64 << 31) as f64;
        let value = json!([{
            "uri": "file:///a.rs",
            "range": { "start": {"line": too_big, "character": 0}, "end": {"line": too_big, "character": 0} }
        }]);
        let parsed = parse_locations(&value, 10);
        assert!(parsed.locations.is_empty());
        assert_eq!(parsed.malformed, 1);

        // One below the ceiling is still valid.
        let ok = json!([{
            "uri": "file:///a.rs",
            "range": { "start": {"line": (1u64 << 31) - 1, "character": 0}, "end": {"line": (1u64 << 31) - 1, "character": 0} }
        }]);
        assert_eq!(parse_locations(&ok, 10).locations.len(), 1);
    }

    #[test]
    fn an_inverted_range_is_malformed() {
        // A negative-length range produces nonsense wherever a caller subtracts, and silently
        // selects the wrong span wherever it does not.
        let value = json!([{
            "uri": "file:///a.rs",
            "range": { "start": {"line": 9, "character": 0}, "end": {"line": 2, "character": 0} }
        }]);
        let parsed = parse_locations(&value, 10);
        assert!(parsed.locations.is_empty());
        assert_eq!(parsed.malformed, 1);
    }

    #[test]
    fn a_selection_range_outside_its_target_range_is_refused() {
        // The spec requires containment. Half-believing a server that violates it would have us
        // jump outside the definition it claims to point at.
        let value = json!([{
            "targetUri": "file:///a.rs",
            "targetRange":          { "start": {"line": 10, "character": 0}, "end": {"line": 20, "character": 0} },
            "targetSelectionRange": { "start": {"line": 90, "character": 0}, "end": {"line": 91, "character": 0} }
        }]);
        let parsed = parse_locations(&value, 10);
        assert!(parsed.locations.is_empty());
        assert_eq!(parsed.malformed, 1);
    }

    #[test]
    fn a_selection_range_inside_its_target_range_is_accepted() {
        let value = json!([{
            "targetUri": "file:///a.rs",
            "targetRange":          { "start": {"line": 10, "character": 0}, "end": {"line": 20, "character": 0} },
            "targetSelectionRange": { "start": {"line": 12, "character": 4}, "end": {"line": 12, "character": 9} }
        }]);
        let parsed = parse_locations(&value, 10);
        assert_eq!(parsed.locations.len(), 1);
        assert_eq!(parsed.locations[0].range.start.line, 12);
    }

    #[test]
    fn reference_params_carry_the_declaration_flag_and_definition_does_not() {
        let refs = Query::References {
            include_declaration: true,
        }
        .params(
            "file:///a.rs",
            Position {
                line: 1,
                character: 2,
            },
        );
        assert_eq!(refs["context"]["includeDeclaration"], true);
        assert_eq!(refs["position"]["line"], 1);

        let def = Query::Definition.params(
            "file:///a.rs",
            Position {
                line: 1,
                character: 2,
            },
        );
        assert!(def.get("context").is_none());
        assert_eq!(Query::Definition.method(), "textDocument/definition");
    }

    #[test]
    fn hover_handles_every_content_encoding() {
        // MarkupContent
        assert_eq!(
            parse_hover_text(&json!({"contents": {"kind":"markdown","value":"fn a()"}})).unwrap(),
            "fn a()"
        );
        // bare string
        assert_eq!(
            parse_hover_text(&json!({"contents": "fn a()"})).unwrap(),
            "fn a()"
        );
        // array mixing {language,value} and string
        assert_eq!(
            parse_hover_text(&json!({"contents": [
                {"language":"rust","value":"fn a()"},
                "docs here"
            ]}))
            .unwrap(),
            "fn a()\n\ndocs here"
        );
    }

    #[test]
    fn an_enormous_hover_is_bounded_and_the_cut_is_marked() {
        // A generic-heavy symbol legitimately hovers to thousands of characters. Forwarding it
        // whole spends the context window on one incidental lookup; cutting it silently makes a
        // truncated type signature read as a different, simpler type.
        let huge = "T".repeat(MAX_HOVER_BYTES * 3);
        let text = parse_hover_text(&json!({ "contents": huge })).unwrap();
        assert!(text.len() <= MAX_HOVER_BYTES + "\n[hover truncated]".len());
        assert!(
            text.ends_with("[hover truncated]"),
            "the cut must be visible"
        );
    }

    #[test]
    fn an_empty_hover_is_none_rather_than_an_empty_string() {
        assert!(parse_hover_text(&json!({"contents": ""})).is_none());
        assert!(parse_hover_text(&json!({"contents": []})).is_none());
        assert!(parse_hover_text(&json!({})).is_none());
    }

    #[test]
    fn an_answer_for_superseded_text_is_refused() {
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 1);
        assert!(ensure_fresh(&store, "file:///a.rs", 1).is_ok());

        store.change("file:///a.rs", 2);
        assert_eq!(
            ensure_fresh(&store, "file:///a.rs", 1),
            Err(LspError::StaleResult { have: 2, issued: 1 })
        );
    }

    #[test]
    fn an_answer_for_an_untracked_document_is_refused() {
        let store = DocumentStore::new();
        assert_eq!(
            ensure_fresh(&store, "file:///gone.rs", 1),
            Err(LspError::UnknownDocument {
                uri: "file:///gone.rs".into()
            })
        );
    }
}
