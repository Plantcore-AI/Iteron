//! Bounded, operator-refreshable provider metadata.
//!
//! These snapshots are world data, not adapter policy. The embedded document keeps offline startup
//! deterministic; an operator may replace it from `~/.core/provider-metadata.json` without a code
//! change. Every capability is explicit and route-scoped: absence remains unknown.

use crate::{AdapterKind, ErrorProfile, ProviderError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, OnceLock};

const SCHEMA_VERSION: u32 = 1;
const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
const MAX_REVISION_BYTES: usize = 128;
const MAX_SOURCE_BYTES: usize = 2_048;
const MAX_MODEL_ID_BYTES: usize = 512;
const MAX_MODELS: usize = 512;
const MAX_CAPABILITY_ROUTES: usize = 32;
const MAX_HEADER_BYTES: usize = 512;
const MAX_NOTICE_BYTES: usize = 448;
const DAY_SECS: u64 = 24 * 60 * 60;
const STALE_AFTER_DAYS: u64 = 30;
const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;
const GLM_STANDARD_ROOT: &str = "https://open.bigmodel.cn/api/paas/v4";
const ANTHROPIC_ROOT: &str = "https://api.anthropic.com/v1";
const EMBEDDED: &str = include_str!("../static-provider-metadata-v1.json");

#[path = "static_metadata/support.rs"]
mod support;
use support::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticProviderMetadata {
    schema_version: u32,
    bundle_revision: String,
    glm_standard_chat: GlmMetadata,
    anthropic_messages: AnthropicMetadata,
    /// Capability snapshots keyed by route label, each scoped to one exact API root. This is the
    /// (api_root, model) lookup: any bundled provider can document a context window here without a
    /// new named section, and a route absent from the document still resolves to unknown.
    #[serde(default)]
    model_capabilities: BTreeMap<String, RouteCapabilityMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteCapabilityMetadata {
    api_root: String,
    /// Family prefixes, not exact ids: an official catalog serves dated leaves
    /// (`claude-opus-4-7-20260720`) that inherit the documented family bounds.
    families: BTreeMap<String, StaticModelCapabilities>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GlmMetadata {
    version: String,
    source: String,
    captured_at_unix_secs: u64,
    api_root: String,
    default_model: String,
    models: Vec<String>,
    capabilities: BTreeMap<String, StaticModelCapabilities>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticModelCapabilities {
    pub version: String,
    pub source: String,
    pub captured_at_unix_secs: u64,
    pub context_window_tokens: Option<u64>,
    pub max_output_tokens: Option<u32>,
    pub tool_calling: Option<bool>,
    pub semantic_effort: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnthropicMetadata {
    effort: AnthropicEffortMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnthropicEffortMetadata {
    version: String,
    source: String,
    captured_at_unix_secs: u64,
    api_root: String,
    beta_header: String,
    models: Vec<String>,
}

/// Legacy source-compatibility view of the embedded GLM catalog. Runtime catalog construction
/// intentionally does not read this constant; it uses [`StaticProviderMetadata`] so an operator
/// replacement can take effect without rebuilding Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticCatalogManifest {
    pub provider: &'static str,
    pub version: &'static str,
    pub api_root: &'static str,
    pub source: &'static str,
    pub default_model: Option<&'static str>,
    pub models: &'static [&'static str],
}

/// Legacy source-compatible model slice for the embedded 2026-07-14 fallback only.
pub const GLM_STANDARD_CHAT_MODELS: &[&str] = &[
    "glm-5.2",
    "glm-5.1",
    "glm-5-turbo",
    "glm-5",
    "glm-4.7",
    "glm-4.7-flash",
    "glm-4.7-flashx",
    "glm-4.6",
    "glm-4.5-air",
    "glm-4.5-airx",
    "glm-4.5-flash",
    "glm-4-flash-250414",
    "glm-4-flashx-250414",
];

/// Legacy source-compatible manifest for the embedded fallback. Use
/// [`StaticProviderMetadata::embedded`] or an injected replacement for active runtime truth.
pub const GLM_STANDARD_CHAT_MANIFEST: StaticCatalogManifest = StaticCatalogManifest {
    provider: "GLM",
    version: "glm-chat-completions-schema@2026-07-14",
    api_root: GLM_STANDARD_ROOT,
    source: "https://docs.bigmodel.cn/api-reference/模型-api/对话补全",
    default_model: Some("glm-5.2"),
    models: GLM_STANDARD_CHAT_MODELS,
};

impl StaticProviderMetadata {
    /// Process-wide immutable default parsed from the source-controlled data document.
    pub fn embedded() -> Arc<Self> {
        static VALUE: OnceLock<Arc<StaticProviderMetadata>> = OnceLock::new();
        VALUE
            .get_or_init(|| {
                Arc::new(
                    Self::parse_document(EMBEDDED.as_bytes())
                        .expect("embedded provider metadata must be valid"),
                )
            })
            .clone()
    }

    /// Parse a replacement document through the same strict schema and semantic validation as the
    /// production file loader. This is also the stable refresh seam for embedding frontends.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ProviderError> {
        let value = Self::parse_document(bytes)?;
        value.validate_capture_times(current_unix_secs()?)?;
        Ok(value)
    }

    /// Stamp every human-readable revision prefix with the SHA-256 of the exact canonical content
    /// it names. Refresh tooling calls this after editing a complete JSON value, then writes the
    /// resulting document atomically. Runtime loading still recomputes and verifies every stamp.
    pub fn stamp_content_versions(document: &mut serde_json::Value) -> Result<(), ProviderError> {
        let mut value: Self = serde_json::from_value(document.clone())
            .map_err(|_| configuration("provider metadata is not valid schema-v1 JSON"))?;

        let catalog =
            digest_without_fields(&value.glm_standard_chat, &["version", "capabilities"])?;
        value.glm_standard_chat.version =
            stamped_version(&value.glm_standard_chat.version, &catalog)?;
        for (model, capability) in &mut value.glm_standard_chat.capabilities {
            let digest = digest_named_snapshot(model, capability)?;
            capability.version = stamped_version(&capability.version, &digest)?;
        }
        let effort = digest_without_fields(&value.anthropic_messages.effort, &["version"])?;
        value.anthropic_messages.effort.version =
            stamped_version(&value.anthropic_messages.effort.version, &effort)?;
        for (route, capabilities) in &mut value.model_capabilities {
            for (family, capability) in &mut capabilities.families {
                let digest = digest_named_snapshot(&format!("{route}/{family}"), capability)?;
                capability.version = stamped_version(&capability.version, &digest)?;
            }
        }
        let bundle = digest_without_fields(&value, &["bundle_revision"])?;
        value.bundle_revision = stamped_version(&value.bundle_revision, &bundle)?;
        value.validate()?;
        *document = serde_json::to_value(value)
            .map_err(|_| configuration("provider metadata cannot be canonicalized"))?;
        Ok(())
    }

    fn parse_document(bytes: &[u8]) -> Result<Self, ProviderError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(configuration("provider metadata exceeds the 256 KiB bound"));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| configuration("provider metadata is not valid schema-v1 JSON"))?;
        value.validate()?;
        Ok(value)
    }

    /// Load an operator-owned replacement. Absence selects the embedded document; a present but
    /// invalid file fails loudly instead of silently falling back to dated capabilities.
    pub fn load_optional(path: &Path) -> Result<Option<Arc<Self>>, ProviderError> {
        let named = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(configuration("provider metadata file cannot be inspected")),
        };
        if named.file_type().is_symlink() || !named.is_file() {
            return Err(configuration(
                "provider metadata must be a non-symlink regular file",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if named.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(configuration(
                    "provider metadata must not use a reparse point",
                ));
            }
        }

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            // O_NONBLOCK is inert for regular files and prevents a directory-entry swap to a FIFO
            // from hanging before the opened-descriptor type/identity checks can reject it.
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            // Open the named reparse object itself instead of following it. The post-open regular
            // file, identity, owner, and DACL checks below then fail closed on a swap to a link.
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options
            .open(path)
            .map_err(|_| configuration("provider metadata file cannot be opened"))?;
        let metadata = file
            .metadata()
            .map_err(|_| configuration("provider metadata file cannot be inspected"))?;
        validate_operator_file_metadata(&named, &metadata, &file)?;
        if !metadata.is_file() || metadata.len() > MAX_DOCUMENT_BYTES as u64 {
            return Err(configuration(
                "provider metadata must resolve to a regular file within the 256 KiB bound",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
        file.take((MAX_DOCUMENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| configuration("provider metadata file cannot be read"))?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(configuration("provider metadata exceeds the 256 KiB bound"));
        }
        let value = Self::from_slice(&bytes)?;
        Ok(Some(Arc::new(value)))
    }

    pub fn bundle_revision(&self) -> &str {
        &self.bundle_revision
    }

    pub fn glm_api_root(&self) -> &str {
        &self.glm_standard_chat.api_root
    }

    pub fn glm_catalog_version(&self) -> &str {
        &self.glm_standard_chat.version
    }

    pub fn glm_catalog_source(&self) -> &str {
        &self.glm_standard_chat.source
    }

    pub fn glm_default_model(&self) -> &str {
        &self.glm_standard_chat.default_model
    }

    pub fn glm_models(&self) -> &[String] {
        &self.glm_standard_chat.models
    }

    pub fn glm_model_capabilities(&self, model: &str) -> Option<&StaticModelCapabilities> {
        self.glm_standard_chat.capabilities.get(model)
    }

    /// Capabilities documented for one exact (api_root, model) pair, or `None`.
    ///
    /// The egress destination plus the model id is the route identity, so a compatible gateway at
    /// another API root inherits nothing. GLM keeps its own exact-id section and is searched first;
    /// every other bundled route resolves through `model_capabilities` by longest family match, so
    /// `gpt-5-mini` never inherits `gpt-5`'s bounds.
    pub fn route_model_capabilities(
        &self,
        api_root: &str,
        model: &str,
    ) -> Option<&StaticModelCapabilities> {
        if api_root == self.glm_standard_chat.api_root
            && let Some(capability) = self.glm_model_capabilities(model)
        {
            return Some(capability);
        }
        self.model_capabilities
            .values()
            .find(|route| route.api_root == api_root)
            .and_then(|route| {
                route
                    .families
                    .iter()
                    .filter(|(family, _)| crate::model_matches_family(model, family))
                    .max_by_key(|(family, _)| family.len())
                    .map(|(_, capability)| capability)
            })
    }

    pub fn anthropic_effort_header(&self, model: &str) -> Option<&str> {
        self.anthropic_messages
            .effort
            .models
            .iter()
            .any(|family| crate::model_matches_family(model, family))
            .then_some(self.anthropic_messages.effort.beta_header.as_str())
    }

    pub fn anthropic_effort_api_root(&self) -> &str {
        &self.anthropic_messages.effort.api_root
    }

    /// Reject metadata that claims knowledge from materially ahead of the strategy clock. The
    /// small skew allowance covers ordinary host drift; future-dated facts never authorize a
    /// capability or wire header in the production composition path.
    pub fn validate_capture_times(&self, now_unix_secs: u64) -> Result<(), ProviderError> {
        let latest = now_unix_secs.saturating_add(MAX_FUTURE_SKEW_SECS);
        let mut captures = vec![self.glm_standard_chat.captured_at_unix_secs];
        captures.extend(
            self.glm_standard_chat
                .capabilities
                .values()
                .map(|snapshot| snapshot.captured_at_unix_secs),
        );
        captures.push(self.anthropic_messages.effort.captured_at_unix_secs);
        captures.extend(
            self.model_capabilities
                .values()
                .flat_map(|route| route.families.values())
                .map(|snapshot| snapshot.captured_at_unix_secs),
        );
        if captures.into_iter().any(|captured| captured > latest) {
            return Err(configuration(
                "provider metadata capture time is too far in the future",
            ));
        }
        Ok(())
    }

    /// Content-addressed revision evidence for the static facts actually used by one exact route.
    /// The returned string is safe to feed into a durable route digest; unsupported/custom routes
    /// return `None` instead of inheriting official-provider claims.
    pub fn route_revision_evidence(
        &self,
        adapter: AdapterKind,
        profile: ErrorProfile,
        api_root: &str,
        model: &str,
    ) -> Option<String> {
        if adapter == AdapterKind::OpenAiCompatibleChat
            && profile == ErrorProfile::Glm
            && api_root == self.glm_standard_chat.api_root
        {
            let capability = self
                .glm_model_capabilities(model)
                .map_or("none", |snapshot| snapshot.version.as_str());
            return Some(format!(
                "bundle={};catalog={};capability={capability}",
                self.bundle_revision, self.glm_standard_chat.version
            ));
        }
        if adapter == AdapterKind::AnthropicMessages
            && profile == ErrorProfile::Anthropic
            && api_root == self.anthropic_messages.effort.api_root
            && self.anthropic_effort_header(model).is_some()
        {
            return Some(format!(
                "bundle={};effort={}",
                self.bundle_revision, self.anthropic_messages.effort.version
            ));
        }
        None
    }

    /// Build one bounded, secret-free run notice for snapshots actually used by this route/model.
    /// Returning `None` for other routes prevents compatible gateways inheriting official claims.
    pub fn run_notice(
        &self,
        adapter: AdapterKind,
        profile: ErrorProfile,
        api_root: &str,
        model: &str,
        now_unix_secs: u64,
    ) -> Option<String> {
        let embedded = Self::embedded();
        if adapter == AdapterKind::OpenAiCompatibleChat
            && profile == ErrorProfile::Glm
            && api_root == self.glm_standard_chat.api_root
        {
            let mut snapshots = vec![(
                "catalog",
                self.glm_standard_chat.version.as_str(),
                self.glm_standard_chat.captured_at_unix_secs,
                embedded.glm_standard_chat.version.as_str(),
            )];
            if let Some(capability) = self.glm_model_capabilities(model) {
                let baseline = embedded.glm_model_capabilities(model);
                snapshots.push((
                    "capability",
                    capability.version.as_str(),
                    capability.captured_at_unix_secs,
                    baseline.map_or("none", |value| value.version.as_str()),
                ));
            }
            return Some(format_notice(
                &snapshots,
                now_unix_secs,
                self.bundle_revision != embedded.bundle_revision,
            ));
        }
        if adapter == AdapterKind::AnthropicMessages
            && profile == ErrorProfile::Anthropic
            && api_root == self.anthropic_messages.effort.api_root
            && self.anthropic_effort_header(model).is_some()
        {
            let effort = &self.anthropic_messages.effort;
            return Some(format_notice(
                &[(
                    "effort",
                    effort.version.as_str(),
                    effort.captured_at_unix_secs,
                    embedded.anthropic_messages.effort.version.as_str(),
                )],
                now_unix_secs,
                self.bundle_revision != embedded.bundle_revision,
            ));
        }
        None
    }

    fn validate(&self) -> Result<(), ProviderError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(configuration("provider metadata schema_version must be 1"));
        }
        validate_identifier(&self.bundle_revision, MAX_REVISION_BYTES, "bundle revision")?;
        let glm = &self.glm_standard_chat;
        validate_snapshot(&glm.version, &glm.source, glm.captured_at_unix_secs)?;
        if glm.api_root != GLM_STANDARD_ROOT {
            return Err(configuration(
                "GLM metadata must retain the official API root",
            ));
        }
        validate_models(&glm.models)?;
        if !glm.models.iter().any(|model| model == &glm.default_model) {
            return Err(configuration(
                "GLM default model is absent from its manifest",
            ));
        }
        if glm.capabilities.len() > MAX_MODELS {
            return Err(configuration("GLM capability map exceeds its model bound"));
        }
        for (model, capability) in &glm.capabilities {
            if !glm.models.iter().any(|candidate| candidate == model) {
                return Err(configuration("GLM capability names an undeclared model"));
            }
            validate_snapshot(
                &capability.version,
                &capability.source,
                capability.captured_at_unix_secs,
            )?;
            if capability.context_window_tokens == Some(0)
                || capability.max_output_tokens == Some(0)
                || matches!(
                    (capability.context_window_tokens, capability.max_output_tokens),
                    (Some(context), Some(output)) if u64::from(output) > context
                )
            {
                return Err(configuration("GLM capability token bounds are invalid"));
            }
        }
        let effort = &self.anthropic_messages.effort;
        validate_snapshot(
            &effort.version,
            &effort.source,
            effort.captured_at_unix_secs,
        )?;
        if effort.api_root != ANTHROPIC_ROOT {
            return Err(configuration(
                "Anthropic effort metadata must retain the official API root",
            ));
        }
        validate_identifier(
            &effort.beta_header,
            MAX_HEADER_BYTES,
            "Anthropic beta header",
        )?;
        reqwest::header::HeaderValue::from_str(&effort.beta_header)
            .map_err(|_| configuration("Anthropic beta header is invalid"))?;
        validate_models(&effort.models)?;
        self.validate_route_capabilities()?;
        self.validate_content_versions()
    }

    fn validate_route_capabilities(&self) -> Result<(), ProviderError> {
        if self.model_capabilities.len() > MAX_CAPABILITY_ROUTES {
            return Err(configuration(
                "provider metadata declares too many capability routes",
            ));
        }
        for (route, capabilities) in &self.model_capabilities {
            validate_identifier(route, MAX_REVISION_BYTES, "capability route label")?;
            let url = reqwest::Url::parse(&capabilities.api_root)
                .map_err(|_| configuration("capability route API root must be a URL"))?;
            if url.scheme() != "https" || url.host_str().is_none() {
                return Err(configuration(
                    "capability route API root must be an HTTPS URL",
                ));
            }
            if capabilities.families.is_empty() || capabilities.families.len() > MAX_MODELS {
                return Err(configuration(
                    "capability route family map is empty or exceeds its bound",
                ));
            }
            for (family, capability) in &capabilities.families {
                validate_identifier(family, MAX_MODEL_ID_BYTES, "capability family")?;
                validate_snapshot(
                    &capability.version,
                    &capability.source,
                    capability.captured_at_unix_secs,
                )?;
                if capability.context_window_tokens == Some(0)
                    || capability.max_output_tokens == Some(0)
                    || matches!(
                        (capability.context_window_tokens, capability.max_output_tokens),
                        (Some(context), Some(output)) if u64::from(output) > context
                    )
                {
                    return Err(configuration("capability route token bounds are invalid"));
                }
            }
        }
        Ok(())
    }

    fn validate_content_versions(&self) -> Result<(), ProviderError> {
        let catalog = digest_without_fields(&self.glm_standard_chat, &["version", "capabilities"])?;
        require_content_version(&self.glm_standard_chat.version, &catalog, "GLM catalog")?;
        for (model, capability) in &self.glm_standard_chat.capabilities {
            let digest = digest_named_snapshot(model, capability)?;
            require_content_version(&capability.version, &digest, "GLM capability")?;
        }
        let effort = digest_without_fields(&self.anthropic_messages.effort, &["version"])?;
        require_content_version(
            &self.anthropic_messages.effort.version,
            &effort,
            "Anthropic effort",
        )?;
        for (route, capabilities) in &self.model_capabilities {
            for (family, capability) in &capabilities.families {
                let digest = digest_named_snapshot(&format!("{route}/{family}"), capability)?;
                require_content_version(&capability.version, &digest, "route capability")?;
            }
        }
        let bundle = digest_without_fields(self, &["bundle_revision"])?;
        require_content_version(&self.bundle_revision, &bundle, "metadata bundle")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Url;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn bundled_routes_document_a_context_window_for_more_than_one_provider() {
        let embedded = StaticProviderMetadata::embedded();

        // The GLM section keeps its exact-id lookup and is still reached through the same seam.
        let glm = embedded
            .route_model_capabilities(GLM_STANDARD_ROOT, "glm-5.2")
            .expect("the GLM model page speaks for this route");
        assert_eq!(glm.context_window_tokens, Some(1_000_000));
        assert!(
            embedded
                .route_model_capabilities(GLM_STANDARD_ROOT, "glm-5.1")
                .is_none(),
            "a family neighbour still inherits nothing"
        );

        // A non-GLM bundled route now reports a real window instead of unknown (I-30).
        let anthropic = embedded
            .route_model_capabilities(ANTHROPIC_ROOT, "claude-opus-4-7")
            .expect("the bundled Anthropic route carries capabilities");
        assert_eq!(anthropic.context_window_tokens, Some(1_000_000));
        assert_eq!(anthropic.max_output_tokens, Some(128_000));
        // An official catalog serves dated leaves; the family bound covers them.
        assert_eq!(
            embedded
                .route_model_capabilities(ANTHROPIC_ROOT, "claude-opus-4-7-20260720")
                .and_then(|snapshot| snapshot.context_window_tokens),
            Some(1_000_000)
        );

        // Longest-family match: a smaller sibling never inherits the larger model's bounds.
        let openai_root = "https://api.openai.com/v1";
        assert_eq!(
            embedded
                .route_model_capabilities(openai_root, "gpt-5")
                .and_then(|snapshot| snapshot.context_window_tokens),
            Some(400_000)
        );
        let mini = embedded
            .route_model_capabilities(openai_root, "gpt-5-mini")
            .expect("the bundled OpenAI route carries capabilities");
        assert!(
            mini.source.contains("gpt-5-mini"),
            "gpt-5-mini resolves to its own snapshot, not the gpt-5 prefix it shares"
        );

        // The route identity is the exact egress destination; a look-alike gateway inherits nothing.
        assert!(
            embedded
                .route_model_capabilities("https://gateway.invalid/v1", "claude-opus-4-7")
                .is_none()
        );
        assert!(
            embedded
                .route_model_capabilities(ANTHROPIC_ROOT, "claude-unknown")
                .is_none()
        );
    }

    #[test]
    fn route_capability_edits_require_a_restamped_snapshot_and_bundle() {
        let mut document: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
        let families = &mut document["model_capabilities"]["anthropic_messages"]["families"];
        families["claude-opus-4-7"]["context_window_tokens"] = serde_json::json!(2_000_000);
        assert!(
            StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap())
                .unwrap_err()
                .to_string()
                .contains("canonical content digest")
        );

        StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
        let restamped =
            StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(
            restamped
                .route_model_capabilities(ANTHROPIC_ROOT, "claude-opus-4-7")
                .and_then(|snapshot| snapshot.context_window_tokens),
            Some(2_000_000)
        );
        assert_ne!(
            restamped.bundle_revision(),
            StaticProviderMetadata::embedded().bundle_revision()
        );
    }

    #[test]
    fn replacement_is_bounded_neutral_and_version_visible() {
        let embedded = StaticProviderMetadata::embedded();
        assert!(embedded.glm_model_capabilities("glm-5.1").is_none());
        assert!(
            embedded
                .run_notice(
                    AdapterKind::OpenAiCompatibleChat,
                    ErrorProfile::Glm,
                    GLM_STANDARD_ROOT,
                    "glm-5.2",
                    1784505600,
                )
                .unwrap()
                .contains("6 days old")
        );

        let mut document: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
        document["bundle_revision"] = serde_json::json!("operator-refresh@test-v2");
        document["glm_standard_chat"]["version"] =
            serde_json::json!("glm-chat-completions-schema@2026-07-21");
        document["glm_standard_chat"]["captured_at_unix_secs"] = serde_json::json!(1784592000_u64);
        StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
        let refreshed =
            StaticProviderMetadata::parse_document(&serde_json::to_vec(&document).unwrap())
                .unwrap();
        let notice = refreshed
            .run_notice(
                AdapterKind::OpenAiCompatibleChat,
                ErrorProfile::Glm,
                GLM_STANDARD_ROOT,
                "glm-5.1",
                1784678400,
            )
            .unwrap();
        assert!(notice.contains("1 days old"));
        assert!(notice.contains("provider revision changed"));
        assert!(refreshed.glm_model_capabilities("glm-5.1").is_none());

        document["bundle_revision"] = serde_json::json!("operator-refresh@test-v3");
        document["glm_standard_chat"]["version"] =
            serde_json::json!("glm-chat-completions-schema@2026-07-22");
        document["glm_standard_chat"]["captured_at_unix_secs"] = serde_json::json!(1784851200_u64);
        StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
        let future_metadata =
            StaticProviderMetadata::parse_document(&serde_json::to_vec(&document).unwrap())
                .unwrap();
        assert!(
            future_metadata
                .validate_capture_times(1784678400)
                .unwrap_err()
                .to_string()
                .contains("too far in the future")
        );
        let future = future_metadata
            .run_notice(
                AdapterKind::OpenAiCompatibleChat,
                ErrorProfile::Glm,
                GLM_STANDARD_ROOT,
                "glm-5.1",
                1784678400,
            )
            .unwrap();
        assert!(future.contains("2 days in the future (invalid)"));
    }

    #[test]
    fn public_replacement_parser_rejects_future_authorization_data() {
        let mut document: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
        document["glm_standard_chat"]["captured_at_unix_secs"] =
            serde_json::json!(current_unix_secs().unwrap() + DAY_SECS);
        StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();

        assert!(
            StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap())
                .unwrap_err()
                .to_string()
                .contains("too far in the future")
        );
    }

    #[test]
    fn operator_file_replaces_the_embedded_document_without_source_changes() {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "core-static-provider-metadata-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("provider-metadata.json");
        let document: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let loaded = StaticProviderMetadata::load_optional(&path)
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded.bundle_revision(),
            StaticProviderMetadata::embedded().bundle_revision()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(StaticProviderMetadata::load_optional(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

            let hard_link = dir.join("provider-metadata-hard-link.json");
            std::fs::hard_link(&path, &hard_link).unwrap();
            assert!(StaticProviderMetadata::load_optional(&path).is_err());
            std::fs::remove_file(&hard_link).unwrap();

            let link = dir.join("provider-metadata-link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(StaticProviderMetadata::load_optional(&link).is_err());
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn changed_snapshots_require_content_addressed_snapshot_and_bundle_versions() {
        let mut document: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
        document["glm_standard_chat"]["capabilities"]["glm-5.2"]["semantic_effort"] =
            serde_json::json!(false);
        assert!(
            StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap())
                .unwrap_err()
                .to_string()
                .contains("canonical content digest")
        );

        StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
        let first = StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap())
            .expect("a fully re-stamped replacement is valid");
        let first_revision = first.bundle_revision().to_string();

        document["glm_standard_chat"]["capabilities"]["glm-5.2"]["tool_calling"] =
            serde_json::json!(false);
        assert!(
            StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap())
                .unwrap_err()
                .to_string()
                .contains("canonical content digest")
        );
        assert_eq!(document["bundle_revision"], first_revision);
    }

    #[test]
    fn notice_is_hard_bounded_without_hiding_age_or_revision_state() {
        let mut document: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
        document["bundle_revision"] = serde_json::json!("b".repeat(40));
        document["glm_standard_chat"]["version"] = serde_json::json!("c".repeat(40));
        document["glm_standard_chat"]["capabilities"]["glm-5.2"]["version"] =
            serde_json::json!("m".repeat(40));
        StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
        let notice = StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap())
            .unwrap()
            .run_notice(
                AdapterKind::OpenAiCompatibleChat,
                ErrorProfile::Glm,
                GLM_STANDARD_ROOT,
                "glm-5.2",
                1786665600,
            )
            .unwrap();
        assert!(notice.len() <= MAX_NOTICE_BYTES);
        assert!(notice.contains("provider revision changed"));
        assert!(notice.contains("catalog is 31 days old (stale)"));
        assert!(notice.contains("capability is 30 days old (fresh)"));
    }

    #[test]
    fn bundle_revision_change_is_observable_even_when_route_snapshots_are_unchanged() {
        let embedded = StaticProviderMetadata::embedded();
        let mut document: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
        document["bundle_revision"] = serde_json::json!("operator-bundle-label@v2");
        StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
        let refreshed =
            StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap()).unwrap();

        assert_ne!(refreshed.bundle_revision(), embedded.bundle_revision());
        assert_eq!(
            refreshed.glm_catalog_version(),
            embedded.glm_catalog_version()
        );
        let notice = refreshed
            .run_notice(
                AdapterKind::OpenAiCompatibleChat,
                ErrorProfile::Glm,
                GLM_STANDARD_ROOT,
                "glm-5.1",
                1784678400,
            )
            .unwrap();
        assert!(notice.contains("provider revision changed"));
    }

    #[test]
    fn legacy_catalog_api_matches_the_embedded_fallback() {
        let embedded = StaticProviderMetadata::embedded();
        assert!(
            embedded
                .glm_catalog_version()
                .starts_with(GLM_STANDARD_CHAT_MANIFEST.version)
        );
        assert_eq!(GLM_STANDARD_CHAT_MANIFEST.api_root, embedded.glm_api_root());
        assert_eq!(
            GLM_STANDARD_CHAT_MANIFEST.default_model,
            Some(embedded.glm_default_model())
        );
        assert_eq!(
            GLM_STANDARD_CHAT_MANIFEST.models,
            embedded
                .glm_models()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            Url::parse(GLM_STANDARD_CHAT_MANIFEST.source).unwrap(),
            Url::parse(embedded.glm_catalog_source()).unwrap()
        );
    }

    #[test]
    fn anthropic_effort_age_is_visible_only_on_the_proven_route_and_family() {
        let embedded = StaticProviderMetadata::embedded();
        let notice = embedded
            .run_notice(
                AdapterKind::AnthropicMessages,
                ErrorProfile::Anthropic,
                ANTHROPIC_ROOT,
                "claude-opus-4-7-20260720",
                1763942400 + 31 * DAY_SECS,
            )
            .unwrap();
        assert!(notice.contains("effort is 31 days old (stale)"));
        assert!(notice.contains("anthropic-effort-beta@2025-11-24"));
        assert!(
            embedded
                .run_notice(
                    AdapterKind::AnthropicMessages,
                    ErrorProfile::Anthropic,
                    ANTHROPIC_ROOT,
                    "claude-unknown",
                    u64::MAX,
                )
                .is_none()
        );
        assert!(
            embedded
                .run_notice(
                    AdapterKind::AnthropicMessages,
                    ErrorProfile::Anthropic,
                    "https://gateway.invalid/v1",
                    "claude-opus-4-7",
                    u64::MAX,
                )
                .is_none()
        );
    }
}
