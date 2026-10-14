//! Actual installed runtime-boundary settings. This view constructs no provider, config or path
//! authority; the authenticated host retains dispatch and the frontend retains only display facts.
use super::{App, block, kv, ui_safe_text};
use crate::route::{RouteLimits, RouteView};
use iteron_protocol::{Budget, Effort, PermissionMode, RunId};
use serde::Deserialize as _;
use serde_json::Value;

pub(super) struct Settings {
    provider: Option<String>,
    model: String,
    effort: Effort,
    mode: PermissionMode,
    budget: Budget,
    workspace: String,
    window: Option<u64>,
    output: Option<u32>,
    bypass: bool,
    approval_channel: bool,
}
impl Settings {
    pub(super) fn invalidate(app: &mut App) {
        app.route = RouteView::unresolved();
        app.model.clear();
        app.telemetry.bind_model_capacity(None);
        app.remote_settings_pending = true;
    }
    pub(super) fn capture(value: &Value, run: &RunId) -> Result<Self, &'static str> {
        if value["type"] != "client_inventory_v1"
            || value["contract_version"]
                != iteron_protocol::client_inventory::CLIENT_INVENTORY_VERSION
            || value["kind"] != "overview"
            || value["available"] != true
            || value["provenance"] != "installed_runtime_boundary"
        {
            return Err("installed runtime settings unavailable");
        }
        let rows = value["records"]
            .as_array()
            .filter(|rows| rows.len() == 1)
            .ok_or("installed runtime settings shape invalid")?;
        let row = &rows[0];
        if row["run_id"] != run.0 {
            return Err("installed runtime settings belong to another run");
        }
        let text = |key: &str, bound: usize| {
            row[key]
                .as_str()
                .filter(|text| text.len() <= bound && !text.chars().any(char::is_control))
                .ok_or("installed runtime setting exceeds its text bound")
        };
        let provider = match &row["provider_id"] {
            Value::Null => None,
            Value::String(value) if value.is_empty() => None,
            Value::String(_) => Some(text("provider_id", 512)?.to_owned()),
            _ => return Err("installed provider identity invalid"),
        };
        let model = text("model_id", 512)?.to_owned();
        if model.is_empty() {
            return Err("installed model identity unavailable");
        }
        let effort = Effort::deserialize(&row["effort"])
            .map_err(|_| "installed effort is not understood")?;
        let mode = PermissionMode::deserialize(&row["permission_mode"])
            .map_err(|_| "installed permission mode is not understood")?;
        let bypass = row["bypass_permissions"]
            .as_bool()
            .ok_or("permission bypass observation unavailable")?;
        let approval_channel = row["approval_channel_available"]
            .as_bool()
            .ok_or("approval channel observation unavailable")?;
        let budget = Budget::deserialize(&row["budget"])
            .map_err(|_| "installed budget is not understood")?;
        if budget
            .max_usd
            .is_some_and(|usd| !usd.is_finite() || usd < 0.0)
        {
            return Err("installed monetary ceiling invalid");
        }
        let window = match &row["model_context_window_tokens"] {
            Value::Null => None,
            value => Some(
                value
                    .as_u64()
                    .filter(|window| *window > 0)
                    .ok_or("installed context capacity invalid")?,
            ),
        };
        let output = match &row["model_max_output_tokens"] {
            Value::Null => None,
            value => Some(
                value
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .filter(|output| *output > 0)
                    .ok_or("installed output capacity invalid")?,
            ),
        };
        Ok(Self {
            provider,
            model,
            effort,
            mode,
            budget,
            workspace: text("workspace", 4096)?.to_owned(),
            window,
            output,
            bypass,
            approval_channel,
        })
    }
    pub(super) fn apply(self, app: &mut App, show: bool) {
        let mut route = RouteView::unresolved();
        route.provider_id = self.provider.clone().unwrap_or_default();
        route.provider_display_name = route.provider_id.clone();
        route.model_id = self.model.clone();
        route.catalog_provenance = "installed runtime boundary".into();
        route.context_window_tokens = self.window;
        route.max_output_tokens = self.output;
        route.limits = RouteLimits {
            max_turns: self.budget.max_turns,
            max_usd: self.budget.max_usd,
            max_tokens: self.budget.max_tokens,
            max_wall_secs: self.budget.max_wall_secs,
        };
        app.remote_settings_pending = false;
        app.route = route;
        app.model = self.model;
        app.mode = self.mode;
        app.effort = self.effort;
        app.telemetry.bind_model_capacity(self.window);
        if show {
            app.panel("≡", "service settings · installed runtime boundary", vec![
                kv("provider", self.provider.as_deref().unwrap_or("unavailable")),
                kv("model", &app.model),
                kv("requested effort", self.effort.label()),
                kv("permission mode", self.mode.label()),
                kv("approval requests", if self.bypass {
                    "operator bypass selected"
                } else if self.approval_channel {
                    "available through the existing kernel channel"
                } else {
                    "unavailable; an operation that needs approval refuses finitely"
                }),
                kv("workspace", &ui_safe_text(&self.workspace)),
                kv("turn ceiling", &if self.budget.max_turns == Budget::UNLIMITED_TURNS { "no ceiling".into() } else { self.budget.max_turns.to_string() }),
                kv("token ceiling", &self.budget.max_tokens.map_or_else(|| "no ceiling".into(), |tokens| tokens.to_string())),
                kv("monetary ceiling", &self.budget.max_usd.map_or_else(|| "no ceiling".into(), |usd| format!("${usd:.6}"))),
                kv("wall ceiling", &format!("{} seconds", self.budget.max_wall_secs)),
                block::PanelRow::Note("Settings captured at the host's last idle/turn boundary; active physical task state is available through /activity.".into()),
            ]);
        }
    }
}

#[cfg(test)]
mod tests;
