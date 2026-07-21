//! Bounded, deterministic parsing and matching for optional skill frontmatter.

use std::path::{Component, Path, PathBuf};

const MAX_PATH_PATTERNS: usize = 64;
const MAX_PATH_PATTERN_BYTES: usize = 256;
const MAX_ACTIVE_PATHS: usize = 128;
const MAX_ACTIVE_PATH_BYTES: usize = 1_024;
const MAX_TASK_TOKENS: usize = 512;
const MAX_HINT_BYTES: usize = 512;

/// Optional metadata that controls how a skill is advertised. It never grants a capability.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillMetadata {
    /// Human-facing usage suffix, for example `<ticket> [path]`.
    pub argument_hint: Option<String>,
    /// A concise activation hint rendered in the progressive-disclosure index.
    pub when_to_use: Option<String>,
    /// Repository-relative wildcard patterns. A scoped skill is hidden unless one is active.
    pub paths: Vec<String>,
    /// Hide the skill from model discovery while keeping explicit lookup available to the user.
    pub disable_model_invocation: bool,
}

/// Extract a bounded, order-preserving set of repository-relative path hints from operator text.
/// This is selection metadata only: it never reads the named paths or grants filesystem access.
pub fn active_paths_from_text(text: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for raw in text.split_whitespace().take(MAX_TASK_TOKENS) {
        if paths.len() == MAX_ACTIVE_PATHS {
            break;
        }
        let token = raw
            .trim_matches(|character: char| {
                matches!(
                    character,
                    '`' | '\'' | '"' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
                )
            })
            .strip_prefix('@')
            .unwrap_or(raw.trim_matches(|character: char| {
                matches!(
                    character,
                    '`' | '\'' | '"' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
                )
            }));
        let token = strip_line_suffix(token);
        if token.is_empty()
            || token.len() > MAX_ACTIVE_PATH_BYTES
            || !(token.contains('/')
                || Path::new(token)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains('.')))
        {
            continue;
        }
        let candidate = PathBuf::from(token);
        if normalize_active_path(&candidate).is_some() && !paths.contains(&candidate) {
            paths.push(candidate);
        }
    }
    paths
}

fn strip_line_suffix(token: &str) -> &str {
    let Some((path, suffix)) = token.rsplit_once(':') else {
        return token;
    };
    if !path.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        path
    } else {
        token
    }
}

pub(super) fn parse(frontmatter: &str) -> Result<SkillMetadata, String> {
    let mut metadata = SkillMetadata::default();
    let mut saw_argument_hint = false;
    let mut saw_when_to_use = false;
    let mut saw_paths = false;
    let mut saw_disable_model_invocation = false;

    for raw_line in frontmatter.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once(':') else {
            // Unknown YAML shapes remain forward-compatible. Known fields cannot appear without a
            // colon because there is no unambiguous value to validate.
            if is_known_key(line) {
                return Err(format!("malformed skill frontmatter field `{line}`"));
            }
            continue;
        };
        let key = raw_key.trim();
        let value = unquote(raw_value.trim());
        match key {
            "argument-hint" | "argument_hint" | "arguments" => {
                reject_duplicate(key, &mut saw_argument_hint)?;
                metadata.argument_hint = Some(parse_text(key, value)?);
            }
            "when_to_use" | "when-to-use" => {
                reject_duplicate(key, &mut saw_when_to_use)?;
                metadata.when_to_use = Some(parse_text(key, value)?);
            }
            "paths" => {
                reject_duplicate(key, &mut saw_paths)?;
                metadata.paths = parse_paths(value)?;
            }
            "disable-model-invocation" | "disable_model_invocation" => {
                reject_duplicate(key, &mut saw_disable_model_invocation)?;
                metadata.disable_model_invocation = parse_bool(key, value)?;
            }
            // `name` and `description` are parsed by the parent module. Extra keys are explicitly
            // tolerated so newer producers do not make older clients reject an otherwise safe
            // skill.
            _ => {}
        }
    }
    Ok(metadata)
}

fn reject_duplicate(key: &str, seen: &mut bool) -> Result<(), String> {
    if *seen {
        return Err(format!("duplicate skill frontmatter field `{key}`"));
    }
    *seen = true;
    Ok(())
}

fn is_known_key(line: &str) -> bool {
    matches!(
        line.trim(),
        "argument-hint"
            | "argument_hint"
            | "arguments"
            | "when_to_use"
            | "when-to-use"
            | "paths"
            | "disable-model-invocation"
            | "disable_model_invocation"
    )
}

fn parse_text(key: &str, value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err(format!("skill frontmatter `{key}` must not be empty"));
    }
    if value.len() > MAX_HINT_BYTES {
        return Err(format!(
            "skill frontmatter `{key}` exceeds {MAX_HINT_BYTES} bytes"
        ));
    }
    Ok(value.to_string())
}

fn parse_bool(key: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!(
            "skill frontmatter `{key}` must be exactly true or false"
        )),
    }
}

fn parse_paths(value: &str) -> Result<Vec<String>, String> {
    let inner = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value);
    if inner.trim().is_empty() {
        return Err("skill frontmatter `paths` must contain at least one pattern".into());
    }
    let mut paths = Vec::new();
    for raw in inner.split(',') {
        if paths.len() == MAX_PATH_PATTERNS {
            return Err(format!(
                "skill frontmatter `paths` exceeds {MAX_PATH_PATTERNS} patterns"
            ));
        }
        let pattern = normalize_pattern(unquote(raw.trim()))?;
        if !paths.contains(&pattern) {
            paths.push(pattern);
        }
    }
    paths.sort();
    Ok(paths)
}

fn normalize_pattern(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("skill frontmatter `paths` contains an empty pattern".into());
    }
    if value.len() > MAX_PATH_PATTERN_BYTES {
        return Err(format!(
            "skill path pattern exceeds {MAX_PATH_PATTERN_BYTES} bytes"
        ));
    }
    let normalized = value.trim_start_matches("./").replace('\\', "/");
    let path = Path::new(&normalized);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
    {
        return Err("skill path patterns must stay repository-relative".into());
    }
    Ok(normalized)
}

fn unquote(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes[0], bytes[value.len() - 1]),
            (b'\'', b'\'') | (b'"', b'"')
        ) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

impl SkillMetadata {
    /// Whether the model may see this skill for the bounded set of active repository paths.
    pub(super) fn model_visible(&self, active_paths: &[PathBuf]) -> bool {
        if self.disable_model_invocation {
            return false;
        }
        if self.paths.is_empty() {
            return true;
        }
        active_paths
            .iter()
            .take(MAX_ACTIVE_PATHS)
            .filter_map(|path| normalize_active_path(path))
            .any(|path| {
                self.paths
                    .iter()
                    .any(|pattern| wildcard_match(pattern, &path))
            })
    }
}

fn normalize_active_path(path: &Path) -> Option<String> {
    let value = path.to_string_lossy().replace('\\', "/");
    if value.is_empty() || value.len() > MAX_ACTIVE_PATH_BYTES || path.is_absolute() {
        return None;
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
    {
        return None;
    }
    Some(value.trim_start_matches("./").to_string())
}

/// Linear wildcard matcher: `*` (and repeated `**`) matches any bytes, `?` one byte. Inputs are
/// tightly bounded before reaching this helper, so matching work cannot grow with the workspace.
fn wildcard_match(pattern: &str, candidate: &str) -> bool {
    let pattern = pattern.as_bytes();
    let candidate = candidate.as_bytes();
    let (mut pattern_index, mut candidate_index) = (0usize, 0usize);
    let mut star_after = None;
    let mut star_candidate = 0usize;

    while candidate_index < candidate.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?'
                || pattern[pattern_index] == candidate[candidate_index])
        {
            pattern_index += 1;
            candidate_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
                pattern_index += 1;
            }
            star_after = Some(pattern_index);
            star_candidate = candidate_index;
        } else if let Some(after) = star_after {
            star_candidate += 1;
            candidate_index = star_candidate;
            pattern_index = after;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matching_is_bounded_and_path_oriented() {
        assert!(wildcard_match("src/**", "src/lib.rs"));
        assert!(wildcard_match("docs/*.md", "docs/guide/setup.md"));
        assert!(!wildcard_match("src/**", "tests/lib.rs"));
        assert!(wildcard_match("?.rs", "x.rs"));
        assert!(!wildcard_match("?.rs", "long.rs"));
    }

    #[test]
    fn metadata_rejects_unsafe_or_malformed_known_fields() {
        assert!(parse("disable-model-invocation: perhaps").is_err());
        assert!(parse("paths: [../secret]").is_err());
        assert!(parse("paths: []").is_err());
        assert!(parse("argument-hint:").is_err());
    }

    #[test]
    fn task_path_hints_are_relative_bounded_and_ordered() {
        assert_eq!(
            active_paths_from_text(
                "edit @src/lib.rs:42, then `Cargo.toml`; ignore /etc/passwd and ../secret.txt"
            ),
            [PathBuf::from("src/lib.rs"), PathBuf::from("Cargo.toml")]
        );
    }
}
