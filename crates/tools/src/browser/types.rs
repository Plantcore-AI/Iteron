//! Model input selects bounded actions and opaque current views; host configuration owns authority.
use serde::Deserialize;
use std::collections::BTreeSet;
use url::Url;

#[derive(Clone)]
pub struct BrowserConfig {
    pub(super) endpoint: Url,
    pub(super) origins: BTreeSet<String>,
}
impl std::fmt::Debug for BrowserConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserConfig")
            .field("origins", &self.origins.len())
            .finish_non_exhaustive()
    }
}
impl BrowserConfig {
    /// Only an explicitly selected local driver can mint a fresh isolated browser. No attach,
    /// credentials, executable/profile path, cookie or arbitrary script capability is admitted.
    pub fn new(endpoint: &str, origins: Vec<String>) -> Result<Self, &'static str> {
        if endpoint.len() > 2048 || origins.is_empty() || origins.len() > 32 {
            return Err("browser_configuration_bounds");
        }
        let mut endpoint = Url::parse(endpoint).map_err(|_| "browser_endpoint_invalid")?;
        if endpoint.scheme() != "http"
            || !matches!(endpoint.host_str(), Some("127.0.0.1" | "[::1]"))
            || endpoint.port().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err("browser_endpoint_must_be_explicit_loopback_driver");
        }
        endpoint.set_path("/");
        let mut admitted = BTreeSet::new();
        for raw in origins {
            let url = web_url(&raw)?;
            if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
                return Err("browser_origin_requires_origin_only");
            }
            admitted.insert(url.origin().ascii_serialization());
        }
        Ok(Self {
            endpoint,
            origins: admitted,
        })
    }
    pub(super) fn permits(&self, url: &Url) -> bool {
        self.origins.contains(&url.origin().ascii_serialization())
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum BrowserCommand {
    Open {
        url: String,
    },
    Observe {
        page_ref: String,
    },
    Click {
        page_ref: String,
        selector: String,
    },
    Type {
        page_ref: String,
        selector: String,
        text: String,
    },
    Pointer {
        page_ref: String,
        x: u16,
        y: u16,
    },
    Scroll {
        page_ref: String,
        delta_y: i32,
    },
    Screenshot {
        page_ref: String,
    },
    Close {
        page_ref: String,
    },
    #[serde(skip)]
    Key {
        page_ref: String,
        key: super::computer::ComputerKey,
    },
}
impl BrowserCommand {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if let Self::Open { url } = self {
            web_url(url)?;
            return Ok(());
        }
        let page = self.page_ref().ok_or("browser_page_required")?;
        if page.is_empty()
            || page.len() > 128
            || !page.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("browser_page_reference_bounds");
        }
        match self {
            Self::Click { selector, .. } | Self::Type { selector, .. } => {
                if selector.is_empty()
                    || selector.len() > 1024
                    || selector.chars().any(char::is_control)
                {
                    return Err("browser_selector_bounds");
                }
            }
            Self::Pointer { x, y, .. } if *x >= 1280 || *y >= 720 => {
                return Err("browser_pointer_outside_viewport");
            }
            Self::Scroll { delta_y, .. } if delta_y.unsigned_abs() > 4096 => {
                return Err("browser_scroll_bounds");
            }
            _ => {}
        }
        if let Self::Type { text, .. } = self {
            if text.len() > 4096
                || text.chars().any(|c| {
                    ('\u{e000}'..='\u{f8ff}').contains(&c)
                        || c == '\0'
                        || (c.is_control() && c != '\n' && c != '\t')
                })
            {
                return Err("browser_text_bounds");
            }
        }
        Ok(())
    }
    pub(super) fn page_ref(&self) -> Option<&str> {
        match self {
            Self::Open { .. } => None,
            Self::Observe { page_ref }
            | Self::Click { page_ref, .. }
            | Self::Type { page_ref, .. }
            | Self::Pointer { page_ref, .. }
            | Self::Scroll { page_ref, .. }
            | Self::Screenshot { page_ref }
            | Self::Close { page_ref }
            | Self::Key { page_ref, .. } => Some(page_ref),
        }
    }
    pub(super) fn mutates_page(&self) -> bool {
        matches!(
            self,
            Self::Click { .. }
                | Self::Type { .. }
                | Self::Pointer { .. }
                | Self::Scroll { .. }
                | Self::Key { .. }
        )
    }
}
pub(super) fn web_url(raw: &str) -> Result<Url, &'static str> {
    if raw.is_empty() || raw.len() > 2048 || raw.chars().any(char::is_control) {
        return Err("browser_url_bounds");
    }
    let url = Url::parse(raw).map_err(|_| "browser_url_invalid")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("browser_url_scheme_or_credentials_refused");
    }
    Ok(url)
}
