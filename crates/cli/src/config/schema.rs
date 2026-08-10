//! Version dispatch and pure migration for the CLI-host config file.

use super::FileConfig;

pub(crate) const FILE_CONFIG_SCHEMA_VERSION: u32 = 2;

/// A schema failure detected before the strict current-schema decoder runs.
///
/// Keeping version dispatch separate from `deny_unknown_fields` makes version skew actionable:
/// a future config is not misreported as a typo in an otherwise-current document.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FileConfigSchemaError {
    InvalidVersion,
    FutureVersion { found: u64, supported: u32 },
    InvalidDocument,
    CurrentSchema(String),
}

impl std::fmt::Display for FileConfigSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVersion => write!(
                f,
                "config `schema_version` must be a non-negative integer (current version is {FILE_CONFIG_SCHEMA_VERSION})"
            ),
            Self::FutureVersion { found, supported } => write!(
                f,
                "config schema_version {found} is newer than this Core binary supports (maximum {supported}); upgrade Core or use a version-{supported} config"
            ),
            Self::InvalidDocument => write!(f, "config must be a JSON object"),
            Self::CurrentSchema(message) => write!(f, "invalid config: {message}"),
        }
    }
}

impl std::error::Error for FileConfigSchemaError {}

pub(super) const fn current_version() -> u32 {
    FILE_CONFIG_SCHEMA_VERSION
}

/// Migrate historical JSON shapes before handing them to the strict current-schema decoder.
/// v0 is the released shape with no `schema_version`; v1 introduced only that discriminator, and
/// v2 adds the optional bounded retry-policy object, exact per-server MCP tool filters, and the
/// user-owned terminal-notification preference. Both migrations are intentionally lossless and
/// leave every operator field untouched.
pub(super) fn parse(text: &str) -> Result<FileConfig, FileConfigSchemaError> {
    let document: serde_json::Value = serde_json::from_str(text)
        .map_err(|error| FileConfigSchemaError::CurrentSchema(error.to_string()))?;
    let source_version = classify(&document)?;
    if source_version < FILE_CONFIG_SCHEMA_VERSION {
        if document
            .as_object()
            .is_some_and(|object| object.contains_key("retry"))
        {
            return Err(FileConfigSchemaError::CurrentSchema(format!(
                "`retry` requires schema_version {FILE_CONFIG_SCHEMA_VERSION}"
            )));
        }
        if document
            .as_object()
            .is_some_and(|object| object.contains_key("completion_notifications"))
        {
            return Err(FileConfigSchemaError::CurrentSchema(format!(
                "`completion_notifications` requires schema_version {FILE_CONFIG_SCHEMA_VERSION}"
            )));
        }
        if document
            .get("mcp_servers")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|servers| {
                servers.iter().any(|server| {
                    server
                        .as_object()
                        .is_some_and(|server| server.contains_key("tools"))
                })
            })
        {
            return Err(FileConfigSchemaError::CurrentSchema(format!(
                "`mcp_servers[].tools` requires schema_version {FILE_CONFIG_SCHEMA_VERSION}"
            )));
        }
    }
    // Decode the original text, rather than the probe `Value`, so Serde still rejects duplicate
    // fields instead of inheriting JSON-map last-write-wins behavior from the version probe.
    let mut config: FileConfig = serde_json::from_str(text)
        .map_err(|error| FileConfigSchemaError::CurrentSchema(error.to_string()))?;
    // A decorative or newer-binary top-level key degrades instead of bricking startup, but it is
    // never silent: a typo'd budget knob must still be visible to the operator who wrote it.
    for key in config.unknown.keys() {
        eprintln!(
            "warning: ignoring unknown top-level config key `{key}` (this Core binary does not know it; check for a typo or upgrade Core)"
        );
    }
    if source_version < FILE_CONFIG_SCHEMA_VERSION {
        config.schema_version = FILE_CONFIG_SCHEMA_VERSION;
    }
    config
        .validate()
        .map_err(FileConfigSchemaError::CurrentSchema)?;
    Ok(config)
}

fn classify(document: &serde_json::Value) -> Result<u32, FileConfigSchemaError> {
    let object = document
        .as_object()
        .ok_or(FileConfigSchemaError::InvalidDocument)?;
    let version = match object.get("schema_version") {
        None => 0,
        Some(value) => value
            .as_u64()
            .ok_or(FileConfigSchemaError::InvalidVersion)?,
    };
    match version {
        0 => Ok(0),
        1 => Ok(1),
        version if version == u64::from(FILE_CONFIG_SCHEMA_VERSION) => {
            Ok(FILE_CONFIG_SCHEMA_VERSION)
        }
        found if found > u64::from(FILE_CONFIG_SCHEMA_VERSION) => {
            Err(FileConfigSchemaError::FutureVersion {
                found,
                supported: FILE_CONFIG_SCHEMA_VERSION,
            })
        }
        found => Err(FileConfigSchemaError::CurrentSchema(format!(
            "schema_version {found} has no migration path to {FILE_CONFIG_SCHEMA_VERSION}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V0_FIXTURE: &str = include_str!("../../tests/fixtures/config-v0.json");

    fn fixture_repo(name: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "core-config-schema-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn d13_06_g1_prior_format_fixture_loads_through_the_v0_migrator() {
        let repo = fixture_repo("v0");
        let config_dir = repo.join(iteron_protocol::home::HOME_DIR);
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.json"), V0_FIXTURE).unwrap();

        let config = FileConfig::load(&repo).expect("v0 fixture should migrate and load");
        assert_eq!(config.schema_version, FILE_CONFIG_SCHEMA_VERSION);
        assert_eq!(config.provider.as_deref(), Some("local-vllm"));
        assert_eq!(config.max_turns, Some(17));
        assert_eq!(config.effort.as_deref(), Some("xhigh"));

        std::fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn d13_06_g2_future_schema_is_a_typed_actionable_error() {
        let future_version = u64::from(FILE_CONFIG_SCHEMA_VERSION) + 1;
        let error = FileConfig::parse(&format!(
            r#"{{"schema_version":{future_version},"max_turns":17}}"#
        ))
        .expect_err("a future schema must fail before current-field decoding");
        assert_eq!(
            error,
            FileConfigSchemaError::FutureVersion {
                found: future_version,
                supported: FILE_CONFIG_SCHEMA_VERSION,
            }
        );
        let message = error.to_string();
        assert!(message.contains("newer than this Core binary supports"));
        assert!(message.contains("upgrade Core"));

        let repo = fixture_repo("future");
        let config_dir = repo.join(iteron_protocol::home::HOME_DIR);
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.json"),
            format!(r#"{{"schema_version":{future_version},"max_turns":17}}"#),
        )
        .unwrap();
        let surfaced = FileConfig::load(&repo).expect_err("future config must not load");
        assert!(matches!(
            surfaced
                .root_cause()
                .downcast_ref::<FileConfigSchemaError>(),
            Some(FileConfigSchemaError::FutureVersion {
                found,
                supported: FILE_CONFIG_SCHEMA_VERSION,
            }) if *found == future_version
        ));
        assert!(format!("{surfaced:#}").contains("upgrade Core"));
        std::fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn v1_config_migrates_to_v2_without_changing_operator_fields() {
        let migrated = FileConfig::parse(r#"{"schema_version":1,"provider":"glm","max_turns":17}"#)
            .expect("v1 config should migrate");
        assert_eq!(migrated.schema_version, FILE_CONFIG_SCHEMA_VERSION);
        assert_eq!(migrated.provider.as_deref(), Some("glm"));
        assert_eq!(migrated.max_turns, Some(17));
        assert!(migrated.retry.is_none());
    }

    #[test]
    fn retry_field_requires_the_schema_version_that_introduced_it() {
        let error = FileConfig::parse(
            r#"{"schema_version":1,"retry":{"base_ms":25,"cap_ms":40,"max_attempts":3}}"#,
        )
        .expect_err("a v2-only field must not hide under the v1 discriminator");
        assert!(
            error
                .to_string()
                .contains("`retry` requires schema_version 2")
        );
    }

    #[test]
    fn completion_notifications_require_the_schema_version_that_introduced_them() {
        let error = FileConfig::parse(r#"{"schema_version":1,"completion_notifications":true}"#)
            .expect_err("a v2-only field must not hide under the v1 discriminator");
        assert!(
            error
                .to_string()
                .contains("`completion_notifications` requires schema_version 2")
        );
    }

    #[test]
    fn mcp_filter_requires_the_schema_version_that_introduced_it() {
        let error = FileConfig::parse(
            r#"{"schema_version":1,"mcp_servers":[{"name":"alpha","command":"mcp","tools":{"deny":["delete"]}}]}"#,
        )
        .expect_err("a v2-only nested field must not hide under the v1 discriminator");
        assert!(
            error
                .to_string()
                .contains("`mcp_servers[].tools` requires schema_version 2")
        );
    }

    #[test]
    fn d13_06_g3_migrated_config_round_trips_without_losing_operator_fields() {
        let migrated = FileConfig::parse(V0_FIXTURE).expect("v0 fixture migrates");
        let current = serde_json::to_value(&migrated).expect("current config serializes");
        assert_eq!(
            current
                .get("schema_version")
                .and_then(serde_json::Value::as_u64),
            Some(u64::from(FILE_CONFIG_SCHEMA_VERSION))
        );

        let prior: serde_json::Value = serde_json::from_str(V0_FIXTURE).unwrap();
        for (field, operator_value) in prior.as_object().unwrap() {
            assert_eq!(
                current.get(field),
                Some(operator_value),
                "operator-set field `{field}` changed during migration"
            );
        }

        let serialized = serde_json::to_string_pretty(&migrated).unwrap();
        let reparsed = FileConfig::parse(&serialized).expect("current schema reparses");
        assert_eq!(serde_json::to_value(reparsed).unwrap(), current);
    }
}
