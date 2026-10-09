//! Remote tool cards consume only run-scoped Product item facts, never legacy machine events.
use super::App;
use iteron_protocol::{
    RunId,
    product_contract::{
        ItemContentChannelV1, ItemKindV1, ItemStateV1, ProductEventKindV1, ProductEventV1,
    },
};
use std::collections::HashMap;
const MAX_TOOLS: usize = 256;
const MAX_TOOL_BYTES: usize = 256 * 1024;
const MAX_PENDING_BYTES: usize = 1024 * 1024;
#[derive(Default)]
pub(super) struct ProductTools {
    rows: HashMap<String, Row>,
    bytes: usize,
}
struct Row {
    key: String,
    input: String,
    output: String,
    input_omitted: bool,
    output_omitted: bool,
}
impl ProductTools {
    pub(super) fn select_run(&mut self, app: &mut App, _run: &RunId) {
        self.rows.clear();
        self.bytes = 0;
        app.tools.clear();
    }
    pub(super) fn observe(&mut self, app: &mut App, event: &ProductEventV1) {
        let Some(item) = event
            .item_id
            .as_deref()
            .filter(|item| !item.is_empty() && item.len() <= 256)
        else {
            return;
        };
        match &event.event {
            ProductEventKindV1::ItemStarted {
                kind: ItemKindV1::ToolCall,
                title,
            } => {
                if self.rows.len() >= MAX_TOOLS || self.rows.contains_key(item) {
                    return;
                }
                let name = title
                    .as_deref()
                    .filter(|name| name.len() <= 1024)
                    .unwrap_or("tool · name unavailable");
                let key = format!(
                    "product-tool-{}-{}",
                    event.turn_id.map_or(0, |turn| turn.0),
                    item
                );
                app.tool_start(key.clone(), name.to_owned(), serde_json::Value::Null);
                self.rows.insert(
                    item.to_owned(),
                    Row {
                        key,
                        input: String::new(),
                        output: String::new(),
                        input_omitted: false,
                        output_omitted: false,
                    },
                );
            }
            ProductEventKindV1::ItemContent { channel, content } => {
                let Some(row) = self.rows.get_mut(item) else {
                    return;
                };
                let (target, omitted) = match channel {
                    ItemContentChannelV1::ToolInputJson => (&mut row.input, &mut row.input_omitted),
                    ItemContentChannelV1::ToolOutput => (&mut row.output, &mut row.output_omitted),
                    _ => return,
                };
                if *omitted
                    || target.len().saturating_add(content.len()) > MAX_TOOL_BYTES
                    || self.bytes.saturating_add(content.len()) > MAX_PENDING_BYTES
                {
                    *omitted = true;
                    return;
                }
                self.bytes += content.len();
                target.push_str(content);
                if *channel == ItemContentChannelV1::ToolInputJson
                    && let Ok(args) = serde_json::from_str(&row.input)
                {
                    app.observe_tool_arguments(&row.key, args);
                }
            }
            ProductEventKindV1::ContentOmitted { channel, .. } => {
                if let Some(row) = self.rows.get_mut(item) {
                    match channel {
                        ItemContentChannelV1::ToolInputJson => row.input_omitted = true,
                        ItemContentChannelV1::ToolOutput => row.output_omitted = true,
                        _ => {}
                    }
                }
            }
            ProductEventKindV1::ItemEnded { state } => {
                let Some(mut row) = self.rows.remove(item) else {
                    return;
                };
                self.bytes = self
                    .bytes
                    .saturating_sub(row.input.len() + row.output.len());
                if row.output_omitted {
                    row.output.push_str("\n[tool output omitted from resident view; full artifact read remains available]");
                }
                app.tool_end(
                    &row.key,
                    *state == ItemStateV1::Completed,
                    None,
                    row.output,
                    None,
                );
            }
            _ => {}
        }
    }
}
