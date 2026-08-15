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
pub mod terminal;
pub mod title;
pub mod width;

pub use safe_text::{MAX_FIELD_BYTES, Unsafe, check, lossy};
pub use terminal::{Capabilities, Color, Presentation, Rgb, contrast_ratio, meets_aa};
pub use title::{restore_title, set_title, title_stack_pop, title_stack_push};
pub use width::{char_cells, str_cells, truncate_to_cells};

/// Placeholder for a value that was not measured. Deliberately not `0`, not `-`, and not empty:
/// it has to be visibly *absent* rather than plausibly small.
pub const UNKNOWN: &str = "—";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("unknown status field {name:?}; known fields are {known}")]
    UnknownField { name: String, known: String },
    #[error("status line requests {count} fields, over the {limit} limit")]
    TooManyFields { count: usize, limit: usize },
    #[error("field {name:?} appears twice; a status line must not show one fact in two places")]
    DuplicateField { name: String },
    #[error("snapshot supplies field {name:?} twice")]
    DuplicateSnapshotField { name: String },
    #[error("percent {value} is over 100")]
    PercentOutOfRange { value: u16 },
    #[error("field {field:?} takes {expected}, not {got}")]
    WrongValueKind {
        field: &'static str,
        expected: &'static str,
        got: &'static str,
    },
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

/// One immutable, revisioned read of runtime-owned status facts. This crate never polls a
/// provider, Git, or mutable agent state: a frontend captures facts once and every column renders
/// from that same object, so a row cannot mix values from different turns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshot {
    revision: u64,
    values: std::collections::BTreeMap<Field, Value>,
}

impl StatusSnapshot {
    pub fn new(
        revision: u64,
        values: impl IntoIterator<Item = (Field, Value)>,
    ) -> Result<Self, ConfigError> {
        let mut snapshot = std::collections::BTreeMap::new();
        for (field, value) in values {
            value.check(field)?;
            if snapshot.insert(field, value).is_some() {
                return Err(ConfigError::DuplicateSnapshotField {
                    name: field.name().to_owned(),
                });
            }
        }
        Ok(Self {
            revision,
            values: snapshot,
        })
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn value(&self, field: Field) -> Value {
        self.values.get(&field).cloned().unwrap_or(Value::Unknown)
    }
}

/// A status line may not grow without bound; it shares one terminal row with the prompt.
pub const MAX_FIELDS: usize = 8;

/// Cells the whole rendered row may occupy. Measured in cells, not bytes: eight fields of 256
/// bytes each would be a ~2 KiB "one-row" status line, and a CJK row overflows a byte budget long
/// before it overflows a cell budget. The row is elided to fit rather than allowed to wrap, because
/// a wrapped status line pushes the prompt off-screen on every redraw.
pub const MAX_ROW_CELLS: usize = 120;

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
    /// The kind name, for reporting a field/value mismatch.
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Unknown => "unknown",
            Value::Text(_) => "text",
            Value::Count(_) => "count",
            Value::Milli(_) => "milli",
            Value::Percent(_) => "percent",
        }
    }

    /// Check that this value is one the field can actually take, and that it is in range.
    ///
    /// Without this, `Field::Model` paired with `Percent(200)` is representable and renders as
    /// "200%" beside a model name -- nonsense the type system was not stopping.
    pub fn check(&self, field: Field) -> Result<(), ConfigError> {
        if let Value::Percent(p) = self
            && *p > 100
        {
            return Err(ConfigError::PercentOutOfRange {
                value: u16::from(*p),
            });
        }
        if matches!(self, Value::Unknown) {
            return Ok(());
        }
        let ok = match field {
            Field::Model | Field::Branch | Field::Cwd | Field::SessionId => {
                matches!(self, Value::Text(_))
            }
            Field::Tokens => matches!(self, Value::Count(_)),
            Field::CostUsd => matches!(self, Value::Milli(_)),
            Field::ContextPercent => matches!(self, Value::Percent(_)),
        };
        if ok {
            Ok(())
        } else {
            Err(ConfigError::WrongValueKind {
                field: field.name(),
                expected: match field {
                    Field::Model | Field::Branch | Field::Cwd | Field::SessionId => "text",
                    Field::Tokens => "count",
                    Field::CostUsd => "milli",
                    Field::ContextPercent => "percent",
                },
                got: self.kind(),
            })
        }
    }

    /// Render one value, escaping-safe. Untrusted text goes through the lossy path so a hostile
    /// branch name degrades the display instead of driving the terminal.
    pub fn render(&self) -> String {
        match self {
            Value::Unknown => {
                iteron_tunables::param_str("statusline.lib.unknown", UNKNOWN).to_owned()
            }
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
        if fields.len() > iteron_tunables::param_integer("statusline.lib.max_fields", MAX_FIELDS) {
            return Err(ConfigError::TooManyFields {
                count: fields.len(),
                limit: iteron_tunables::param_integer("statusline.lib.max_fields", MAX_FIELDS),
            });
        }
        // One fact shown twice is a configuration mistake, not a layout choice: the two copies can
        // disagree the instant one is stale, and a reader cannot tell which is current.
        for (i, f) in fields.iter().enumerate() {
            if fields[..i].contains(f) {
                return Err(ConfigError::DuplicateField {
                    name: f.name().to_owned(),
                });
            }
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
        let row = self
            .fields
            .iter()
            .map(|f| lookup(*f).render())
            .collect::<Vec<_>>()
            .join(" | ");
        // Elided to fit the row rather than allowed to wrap.
        width::truncate_to_cells(
            &row,
            iteron_tunables::param_integer("statusline.lib.max_row_cells", MAX_ROW_CELLS),
        )
    }

    pub fn render_snapshot(&self, snapshot: &StatusSnapshot) -> String {
        self.render(|field| snapshot.value(field))
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
    fn a_percent_over_100_is_refused() {
        assert_eq!(
            Value::Percent(101).check(Field::ContextPercent),
            Err(ConfigError::PercentOutOfRange { value: 101 })
        );
        assert!(Value::Percent(100).check(Field::ContextPercent).is_ok());
    }

    #[test]
    fn a_value_of_the_wrong_kind_for_its_field_is_refused() {
        // Previously representable: a model name rendered as "200%" beside itself.
        assert!(matches!(
            Value::Percent(50).check(Field::Model),
            Err(ConfigError::WrongValueKind { field: "model", .. })
        ));
        assert!(matches!(
            Value::Text("x".into()).check(Field::Tokens),
            Err(ConfigError::WrongValueKind {
                field: "tokens",
                ..
            })
        ));
        assert!(Value::Count(5).check(Field::Tokens).is_ok());
        assert!(Value::Milli(1).check(Field::CostUsd).is_ok());
    }

    #[test]
    fn unknown_is_acceptable_for_every_field() {
        for f in Field::ALL {
            assert!(Value::Unknown.check(f).is_ok(), "{f:?}");
        }
    }

    #[test]
    fn a_duplicated_field_is_refused() {
        assert_eq!(
            StatusLine::from_names(["model", "branch", "model"]),
            Err(ConfigError::DuplicateField {
                name: "model".into()
            })
        );
    }

    #[test]
    fn the_rendered_row_is_bounded_in_cells_not_bytes() {
        // Eight fields of long CJK text: a byte budget would pass this and the row would wrap.
        let line = StatusLine::from_names(["model", "branch", "cwd", "session"]).unwrap();
        let rendered = line.render(|_| Value::Text("中文".repeat(200)));
        assert!(
            str_cells(&rendered) <= MAX_ROW_CELLS,
            "row was {} cells, over the {MAX_ROW_CELLS} budget",
            str_cells(&rendered)
        );
    }

    #[test]
    fn cost_is_exact_rather_than_a_rounded_float() {
        assert_eq!(Value::Milli(1_234).render(), "1.234");
        assert_eq!(Value::Milli(7).render(), "0.007");
    }

    #[test]
    fn revisioned_snapshot_is_atomic_and_missing_values_stay_unknown() {
        let snapshot = StatusSnapshot::new(
            7,
            [
                (Field::Model, Value::Text("model-a".into())),
                (Field::Tokens, Value::Count(42)),
            ],
        )
        .unwrap();
        let line = StatusLine::from_names(["model", "tokens", "cost"]).unwrap();
        assert_eq!(snapshot.revision(), 7);
        assert_eq!(
            line.render_snapshot(&snapshot),
            format!("model-a | 42 | {UNKNOWN}")
        );
    }
}
