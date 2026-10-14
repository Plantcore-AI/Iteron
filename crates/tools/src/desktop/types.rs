//! Operator-owned native desktop endpoint; model arguments cannot select the host or app.
use serde::Deserialize;
use url::Url;
#[derive(Clone)]
pub struct DesktopConfig {
    pub(super) endpoint: Url,
    pub(super) bundle_id: String,
}
impl std::fmt::Debug for DesktopConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesktopConfig")
            .field("backend", &"appium_mac2")
            .finish_non_exhaustive()
    }
}
impl DesktopConfig {
    pub fn new(endpoint: &str, bundle_id: &str) -> Result<Self, &'static str> {
        if endpoint.len() > 2048 || !iteron_protocol::tool_image::valid_native_bundle(bundle_id) {
            return Err("desktop_configuration_bounds");
        }
        let endpoint = Url::parse(endpoint).map_err(|_| "desktop_endpoint_invalid")?;
        if endpoint.scheme() != "http"
            || !matches!(endpoint.host_str(), Some("127.0.0.1" | "[::1]"))
            || endpoint.port().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err("desktop_endpoint_requires_explicit_loopback_driver");
        }
        Ok(Self {
            endpoint,
            bundle_id: bundle_id.into(),
        })
    }
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Command {
    Open,
    Observe {
        view_ref: String,
    },
    Click {
        view_ref: String,
        selector: String,
    },
    Type {
        view_ref: String,
        text: String,
    },
    Key {
        view_ref: String,
        key: Key,
    },
    Scroll {
        view_ref: String,
        selector: String,
        delta_y: i32,
    },
    Close {
        view_ref: String,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Key {
    Enter,
    Escape,
    Tab,
    Backspace,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
}
impl Key {
    pub(super) fn native(&self) -> &'static str {
        match self {
            Self::Enter => "XCUIKeyboardKeyReturn",
            Self::Escape => "XCUIKeyboardKeyEscape",
            Self::Tab => "XCUIKeyboardKeyTab",
            Self::Backspace => "XCUIKeyboardKeyDelete",
            Self::ArrowUp => "XCUIKeyboardKeyUpArrow",
            Self::ArrowDown => "XCUIKeyboardKeyDownArrow",
            Self::ArrowLeft => "XCUIKeyboardKeyLeftArrow",
            Self::ArrowRight => "XCUIKeyboardKeyRightArrow",
        }
    }
}
impl Command {
    pub(super) fn reference(&self) -> Option<&str> {
        match self {
            Self::Open => None,
            Self::Observe { view_ref }
            | Self::Click { view_ref, .. }
            | Self::Type { view_ref, .. }
            | Self::Key { view_ref, .. }
            | Self::Scroll { view_ref, .. }
            | Self::Close { view_ref } => Some(view_ref),
        }
    }
    pub(super) fn mutates(&self) -> bool {
        matches!(
            self,
            Self::Click { .. } | Self::Type { .. } | Self::Key { .. } | Self::Scroll { .. }
        )
    }
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if let Some(reference) = self.reference()
            && (reference.is_empty()
                || reference.len() > 128
                || !reference
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        {
            return Err("desktop_reference_bounds");
        }
        match self {
            Self::Click { selector, .. } | Self::Scroll { selector, .. }
                if selector.is_empty()
                    || selector.len() > 1024
                    || selector.chars().any(char::is_control) =>
            {
                Err("desktop_selector_bounds")
            }
            Self::Type { text, .. }
                if text.len() > 4096
                    || text.chars().any(|c| {
                        c == '\0'
                            || (c.is_control() && c != '\n' && c != '\t')
                            || ('\u{e000}'..='\u{f8ff}').contains(&c)
                    }) =>
            {
                Err("desktop_text_bounds")
            }
            Self::Scroll { delta_y, .. } if delta_y.unsigned_abs() > 4096 => {
                Err("desktop_scroll_bounds")
            }
            _ => Ok(()),
        }
    }
}
pub(super) fn bounded_input(input: &serde_json::Value) -> bool {
    input.as_object().is_some_and(|object| {
        object.len() <= 5
            && object.iter().all(|(key, value)| {
                key.len() <= 32
                    && match value {
                        serde_json::Value::String(text) => text.len() <= 4096,
                        serde_json::Value::Number(_) => true,
                        _ => false,
                    }
            })
    })
}
