//! TUI inventories consume the same bounded public projection as remote clients.

use super::{App, Session, block, command_dispatch, item, kv, transcript_effect, ui_safe_text};
use iteron_protocol::client_inventory::{ClientInventoryKindV1, ClientInventoryQueryV1};
use serde_json::Value;
use std::sync::{Arc, atomic::AtomicBool};

fn parse(argument: &str) -> Result<ClientInventoryQueryV1, &'static str> {
    if argument.len() > 1024 {
        return Err("inventory query exceeds its bound");
    }
    let words = argument.split_whitespace().take(4).collect::<Vec<_>>();
    let kind = match words.first().copied().unwrap_or("overview") {
        "overview" => ClientInventoryKindV1::Overview,
        "providers" => ClientInventoryKindV1::Providers,
        "models" => ClientInventoryKindV1::Models,
        "plugins" => ClientInventoryKindV1::Plugins,
        "tools" => ClientInventoryKindV1::Tools,
        "hooks" => ClientInventoryKindV1::Hooks,
        "agents" => ClientInventoryKindV1::Agents,
        "skills" => ClientInventoryKindV1::Skills,
        "effective_config" | "effective" => ClientInventoryKindV1::EffectiveConfig,
        "permissions" => ClientInventoryKindV1::Permissions,
        _ => {
            return Err(
                "/config overview|providers|models [PROVIDER] [OFFSET]|plugins|tools|hooks|agents|skills|effective|permissions [OFFSET]",
            );
        }
    };
    let (provider_id, offset) = if matches!(kind, ClientInventoryKindV1::Models) {
        if words.len() > 3 {
            return Err("use /config models [PROVIDER] [OFFSET]");
        }
        (
            words
                .get(1)
                .filter(|word| **word != "*")
                .map(|word| (*word).to_owned()),
            words.get(2).copied(),
        )
    } else {
        if words.len() > 2 {
            return Err("use /config KIND [OFFSET]");
        }
        (None, words.get(1).copied())
    };
    let query = ClientInventoryQueryV1 {
        kind,
        provider_id,
        offset: offset
            .unwrap_or("0")
            .parse()
            .map_err(|_| "invalid inventory offset")?,
        limit: 32,
    };
    query.validate()?;
    Ok(query)
}

pub(super) fn queue(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    argument: &str,
) {
    match parse(argument) {
        Ok(query) => command_dispatch::queue_command_control(
            app,
            session,
            effects,
            interrupt,
            crate::app_server::Control::Inventory(query),
            transcript_effect::ControlKind::Inventory,
        ),
        Err(reason) => app.note(block::NoticeLevel::Warn, reason),
    }
}

pub(super) fn render(app: &mut App, value: &Value) {
    let mut rows = vec![
        kv(
            "source",
            value["provenance"].as_str().unwrap_or("unavailable"),
        ),
        kv(
            "available",
            if value["available"] == true {
                "yes"
            } else {
                "no"
            },
        ),
        kv("total", &value["total"].to_string()),
    ];
    if let Some(records) = value["records"].as_array() {
        for record in records.iter().take(100) {
            let label = record["name"]
                .as_str()
                .or_else(|| record["plugin_id"].as_str())
                .or_else(|| record["model_id"].as_str())
                .or_else(|| record["provider_id"].as_str())
                .or_else(|| record["event"].as_str())
                .or_else(|| record["family_id"].as_str())
                .unwrap_or("runtime");
            let text = serde_json::to_string(record).unwrap_or_else(|_| "unavailable".into());
            let detail = text.chars().take(2048).collect::<String>();
            rows.push(item("◇", &ui_safe_text(label), &ui_safe_text(&detail)));
        }
    }
    if let Some(next) = value["next_offset"].as_u64() {
        rows.push(block::PanelRow::Note(format!(
            "next offset {next}; request another page with /config KIND OFFSET"
        )));
    }
    if value["available"] != true {
        rows.push(block::PanelRow::Note("no captured owner evidence for this inventory; the client does not rediscover mutable files".into()));
    }
    app.panel("⚙", value["kind"].as_str().unwrap_or("inventory"), rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_queries_keep_bounds_and_filter_scope() {
        let query = parse("models openai 100").unwrap();
        assert_eq!(query.provider_id.as_deref(), Some("openai"));
        assert_eq!(query.offset, 100);
        for bad in [
            "plugins x x",
            "tools 50001",
            "models x 1 extra",
            "not-an-inventory",
        ] {
            assert!(parse(bad).is_err());
        }
    }
}
