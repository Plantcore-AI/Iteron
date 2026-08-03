//! Configurable status line and window title, over values the agent does not control.
//!
//! Two rules shape this crate, and both exist because the alternative is a quiet lie.
//!
//! **A field is either known or it is not; it is never zero.** A status line that renders a missing
//! token count as `0 tokens` tells the operator the run is free. Unknown is its own state and it
//! renders as a placeholder, so "we did not measure this" never reads as "this measured zero".
//!
//! **The field set is a closed allowlist.** A typo in a user's configuration is an error, not a
//! silently blank segment -- a status line that quietly drops `{tokns}` looks identical to one
//! whose token count is genuinely unavailable.
//!
//! Values reach the terminal inside escape sequences, so they are an injection surface. See
//! [`safe_text`].

pub mod safe_text;
pub mod title;

pub use safe_text::{MAX_FIELD_BYTES, Unsafe, check, lossy};
pub use title::{restore_title, set_title, title_stack_pop, title_stack_push};

/// Placeholder for a value that was not measured. Deliberately not `0`, not `-`, and not empty:
/// it has to be visibly *absent* rather than plausibly small.
pub const UNKNOWN: &str = "—";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("unknown status field {name:?}; known fields are {known}")]
    UnknownField { name: String, known: String },
    #[error("status line requests {count} fields, over the {limit} limit")]
    TooManyFields { count: usize, limit: usize },
}

/// The closed set of things a status line may show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    Model,
    Branch,
    Cwd,
    Tokens,
    CostUsd,
    ContextPercent,
    SessionId,
}

/// A status line may not grow without bound; it shares one terminal row with the prompt.
pub const MAX_FIELDS: usize = 8;

impl Field {
    pub fn name(self) -> &'static str {
        match self {
            Field::Model => "model",
            Field::Branch => "branch",
            Field::Cwd => "cwd",
            Field::Tokens => "tokens",
            Field::CostUsd => "cost",
            Field::ContextPercent => "context",
            Field::SessionId => "session",
        }
    }

    pub const ALL: [Field; 7] = [
        Field::Model,
        Field::Branch,
        Field::Cwd,
        Field::Tokens,
        Field::CostUsd,
        Field::ContextPercent,
        Field::SessionId,
    ];

    /// Resolve a configured name. Unknown names are refused with the allowlist attached, so the
    /// operator can fix the typo without reading the source.
    pub fn parse(name: &str) -> Result<Field, ConfigError> {
        Field::ALL
            .into_iter()
            .find(|f| f.name() == name)
            .ok_or_else(|| ConfigError::UnknownField {
                name: name.to_owned(),
                known: Field::ALL
                    .iter()
                    .map(|f| f.name())
                    .collect::<Vec<_>>()
                    .join(", "),
            })
    }
}

/// What the runtime knows about one field right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Count(u64),
    /// Milli-units, so cost is exact rather than a rounded float.
    Milli(u64),
    Percent(u8),
    /// Not measured. Renders as [`UNKNOWN`], never as a zero.
    Unknown,
}

impl Value {
    /// Render one value, escaping-safe. Untrusted text goes through the lossy path so a hostile
    /// branch name degrades the display instead of driving the terminal.
    pub fn render(&self) -> String {
        match self {
            Value::Unknown => UNKNOWN.to_owned(),
            Value::Text(t) => lossy(t),
            Value::Count(n) => n.to_string(),
            Value::Percent(p) => format!("{p}%"),
            Value::Milli(m) => format!("{}.{:03}", m / 1000, m % 1000),
        }
    }
}

/// An operator-configured status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    fields: Vec<Field>,
}

impl StatusLine {
    /// Build from configured names, refusing unknown ones.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, ConfigError> {
        let fields = names
            .into_iter()
            .map(Field::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if fields.len() > MAX_FIELDS {
            return Err(ConfigError::TooManyFields {
                count: fields.len(),
                limit: MAX_FIELDS,
            });
        }
        Ok(Self { fields })
    }

    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// Render with a lookup that may not know every field.
    ///
    /// A field the lookup cannot answer renders as [`UNKNOWN`]. It is never omitted: a segment that
    /// disappears changes the shape of the line, and an operator reading a line whose columns move
    /// cannot tell absence from a layout change.
    pub fn render(&self, lookup: impl Fn(Field) -> Value) -> String {
        self.fields
            .iter()
            .map(|f| lookup(*f).render())
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unmeasured_count_never_renders_as_zero() {
        // The lie this prevents: "0 tokens", "$0.000" on a run that in fact spent money nobody
        // measured.
        assert_eq!(Value::Unknown.render(), UNKNOWN);
        assert_ne!(Value::Unknown.render(), "0");
        assert_ne!(Value::Unknown.render(), Value::Count(0).render());
    }

    #[test]
    fn a_real_zero_is_still_a_zero() {
        assert_eq!(Value::Count(0).render(), "0");
    }

    #[test]
    fn an_unknown_field_name_is_refused_with_the_allowlist() {
        let err = StatusLine::from_names(["model", "tokns"]).unwrap_err();
        match err {
            ConfigError::UnknownField { name, known } => {
                assert_eq!(name, "tokns");
                assert!(known.contains("tokens"), "{known}");
            }
            other => panic!("expected UnknownField, got {other:?}"),
        }
    }

    #[test]
    fn every_known_field_round_trips_through_its_name() {
        for field in Field::ALL {
            assert_eq!(Field::parse(field.name()).unwrap(), field);
        }
    }

    #[test]
    fn an_unknown_field_holds_its_column_instead_of_vanishing() {
        let line = StatusLine::from_names(["model", "tokens", "branch"]).unwrap();
        let rendered = line.render(|f| match f {
            Field::Model => Value::Text("opus".into()),
            Field::Branch => Value::Text("main".into()),
            _ => Value::Unknown,
        });
        assert_eq!(rendered, format!("opus | {UNKNOWN} | main"));
        assert_eq!(rendered.split(" | ").count(), 3, "the column must remain");
    }

    #[test]
    fn a_hostile_branch_name_cannot_drive_the_terminal_through_the_status_line() {
        let line = StatusLine::from_names(["branch"]).unwrap();
        let rendered = line.render(|_| Value::Text("x\u{1b}]0;pwned\u{7}".into()));
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert_eq!(check(&rendered), Ok(()));
    }

    #[test]
    fn too_many_fields_is_refused() {
        let many: Vec<&str> = std::iter::repeat_n("model", MAX_FIELDS + 1).collect();
        assert_eq!(
            StatusLine::from_names(many),
            Err(ConfigError::TooManyFields {
                count: MAX_FIELDS + 1,
                limit: MAX_FIELDS
            })
        );
    }

    #[test]
    fn cost_is_exact_rather_than_a_rounded_float() {
        assert_eq!(Value::Milli(1_234).render(), "1.234");
        assert_eq!(Value::Milli(7).render(), "0.007");
    }
}
