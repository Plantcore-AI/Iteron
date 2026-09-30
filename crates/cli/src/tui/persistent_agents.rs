//! Live agent commands consume the public controller surface and retain only immutable views.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use iteron_protocol::agent_control::{
    AgentBudgetV1, AgentCommandV1, AgentIdV1, AgentStateV1, AgentViewV1,
};
use iteron_protocol::client_agent_control::ClientAgentControlV1;
use iteron_protocol::{Capability, capability_set::CapabilitySet};
use serde_json::Value;

use super::{App, Session, block, command_dispatch, item, kv, transcript_effect, ui_safe_text};

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

fn request_id() -> String {
    format!(
        "tui-agent-{}-{}",
        std::process::id(),
        NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)
    )
}

fn identity(text: Option<&str>) -> Result<AgentIdV1, &'static str> {
    text.and_then(|text| text.parse::<u64>().ok())
        .filter(|id| *id > 0)
        .map(AgentIdV1)
        .ok_or("supply a non-zero agent ID from /agents live")
}

fn usd(text: &str) -> Result<u64, &'static str> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() || fraction.len() > 6 || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("USD must have at most six decimal places");
    }
    whole
        .parse::<u64>()
        .ok()
        .and_then(|whole| whole.checked_mul(1_000_000))
        .and_then(|whole| {
            fraction
                .parse::<u64>()
                .ok()
                .or_else(|| fraction.is_empty().then_some(0))
                .and_then(|fraction_value| {
                    fraction_value.checked_mul(10_u64.pow(6 - fraction.len() as u32))
                })
                .and_then(|fraction| whole.checked_add(fraction))
        })
        .ok_or("invalid bounded USD budget")
}

fn budget(arguments: &[&str]) -> Result<AgentBudgetV1, &'static str> {
    if arguments.len() != 4 {
        return Err("use /agents enable TURNS TOKENS USD WALL_SECONDS");
    }
    let budget = AgentBudgetV1 {
        turns: arguments[0].parse().map_err(|_| "invalid turn budget")?,
        tokens: arguments[1].parse().map_err(|_| "invalid token budget")?,
        cost_microusd: usd(arguments[2])?,
        wall_ms: arguments[3]
            .parse::<u64>()
            .ok()
            .and_then(|seconds| seconds.checked_mul(1000))
            .ok_or("invalid wall budget")?,
    };
    budget.validate()?;
    Ok(budget)
}

fn parse(app: &App, argument: &str) -> Result<ClientAgentControlV1, &'static str> {
    if argument.len() > iteron_protocol::agent_control::MAX_AGENT_TEXT_BYTES + 512 {
        return Err("agent command exceeds its text bound");
    }
    let (verb, rest) = argument
        .trim()
        .split_once(' ')
        .unwrap_or((argument.trim(), ""));
    match verb {
        "live" | "list" => Ok(ClientAgentControlV1::List),
        "enable" => Ok(ClientAgentControlV1::Enable {
            capabilities: CapabilitySet::only(Capability::ReadOnly),
            budget: budget(&rest.split_whitespace().take(5).collect::<Vec<_>>())?,
            max_agents: 8,
            max_pending_per_agent: 32,
            parallel: 4,
        }),
        "inspect" => Ok(ClientAgentControlV1::Inspect {
            agent_id: identity(Some(rest.trim()))?,
        }),
        "receipt" => Ok(ClientAgentControlV1::MessageReceipt {
            message_id: iteron_protocol::agent_control::AgentMessageIdV1(
                identity(Some(rest.trim()))?.0,
            ),
        }),
        "wait" => {
            let args = rest.split_whitespace().take(3).collect::<Vec<_>>();
            if args.len() > 2 {
                return Err("use /agents wait [REVISION] [MILLISECONDS]");
            }
            Ok(ClientAgentControlV1::Wait {
                after_revision: args
                    .first()
                    .map_or(Ok(0), |value| value.parse().map_err(|_| "invalid revision"))?,
                timeout_ms: args.get(1).map_or(Ok(1000), |value| {
                    value.parse().map_err(|_| "invalid wait duration")
                })?,
            })
        }
        "spawn" => {
            let (parent, task) = rest
                .trim()
                .split_once(' ')
                .ok_or("use /agents spawn PARENT_ID TASK")?;
            let parent_id = identity(Some(parent))?;
            let view = app
                .persistent_agent_views
                .iter()
                .find(|view| view.agent_id == parent_id)
                .ok_or("read /agents live before choosing the parent")?;
            Ok(ClientAgentControlV1::Command {
                request_id: request_id(),
                command: AgentCommandV1::Spawn {
                    parent_id,
                    label: format!("agent-{}", NEXT_REQUEST.load(Ordering::Relaxed)),
                    task: task.into(),
                    capabilities: CapabilitySet::only(Capability::ReadOnly),
                    write_paths: Vec::new(),
                    budget: AgentBudgetV1 {
                        turns: 1,
                        tokens: view.budget.tokens.min(32_000),
                        cost_microusd: view.budget.cost_microusd.min(1_000_000),
                        wall_ms: view.budget.wall_ms.min(120_000),
                    },
                },
            })
        }
        "send" | "followup" | "steer" => {
            let (id, text) = rest
                .trim()
                .split_once(' ')
                .ok_or("use /agents send|followup|steer ID TEXT")?;
            let agent_id = identity(Some(id))?;
            let command = match verb {
                "send" => AgentCommandV1::SendMessage {
                    agent_id,
                    text: text.into(),
                },
                "followup" => AgentCommandV1::FollowupTask {
                    agent_id,
                    text: text.into(),
                },
                _ => {
                    let epoch = app
                        .persistent_agent_views
                        .iter()
                        .find(|view| view.agent_id == agent_id)
                        .and_then(|view| view.state.epoch())
                        .ok_or("inspect the running agent before steering its current task")?;
                    AgentCommandV1::Steer {
                        agent_id,
                        epoch,
                        text: text.into(),
                    }
                }
            };
            Ok(ClientAgentControlV1::Command {
                request_id: request_id(),
                command,
            })
        }
        "interrupt" => {
            let agent_id = identity(Some(rest.trim()))?;
            let epoch = app
                .persistent_agent_views
                .iter()
                .find(|view| view.agent_id == agent_id)
                .and_then(|view| view.state.epoch())
                .ok_or("inspect the running agent before interrupting its current task")?;
            Ok(ClientAgentControlV1::Command {
                request_id: request_id(),
                command: AgentCommandV1::Interrupt { agent_id, epoch },
            })
        }
        "close" => {
            let args = rest.split_whitespace().take(3).collect::<Vec<_>>();
            if args.is_empty()
                || args.len() > 2
                || args.get(1).is_some_and(|value| *value != "tree")
            {
                return Err("use /agents close ID [tree]");
            }
            Ok(ClientAgentControlV1::Command {
                request_id: request_id(),
                command: AgentCommandV1::Close {
                    agent_id: identity(args.first().copied())?,
                    include_descendants: args.len() == 2,
                },
            })
        }
        _ => Err(
            "/agents live | enable TURNS TOKENS USD WALL_SECONDS | spawn PARENT TASK | inspect ID | send ID TEXT | followup ID TEXT | steer ID TEXT | interrupt ID | close ID [tree] | receipt ID | wait [REVISION] [MS]",
        ),
    }
}

pub(super) fn queue(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    argument: &str,
) {
    match parse(app, argument).and_then(|command| {
        command.validate()?;
        Ok(command)
    }) {
        Ok(command) => command_dispatch::queue_command_control(
            app,
            session,
            effects,
            interrupt,
            crate::app_server::Control::PersistentAgents(command),
            transcript_effect::ControlKind::PersistentAgents,
        ),
        Err(reason) => app.note(block::NoticeLevel::Warn, reason),
    }
}

fn state(state: AgentStateV1) -> &'static str {
    match state {
        AgentStateV1::Idle => "idle",
        AgentStateV1::Running { .. } => "running",
        AgentStateV1::Interrupting { .. } => "interrupting",
        AgentStateV1::Closing { .. } => "closing",
        AgentStateV1::RecoveryRequired { .. } => "recovery required",
        AgentStateV1::Closed => "closed",
    }
}

pub(super) fn render(app: &mut App, value: &Value) {
    let views = value.get("agents").cloned().or_else(|| {
        value
            .get("agent")
            .cloned()
            .map(|agent| serde_json::json!([agent]))
    });
    if let Some(views) =
        views.and_then(|views| serde_json::from_value::<Vec<AgentViewV1>>(views).ok())
    {
        if views.len() > 64 {
            app.note(block::NoticeLevel::Warn, "agent view exceeds its capacity");
            return;
        }
        if value.get("agents").is_some() {
            app.persistent_agent_views.clear();
        }
        for view in views {
            if let Some(existing) = app
                .persistent_agent_views
                .iter_mut()
                .find(|existing| existing.agent_id == view.agent_id)
            {
                *existing = view;
            } else if app.persistent_agent_views.len() < 64 {
                app.persistent_agent_views.push(view);
            }
        }
        let mut rows = app
            .persistent_agent_views
            .iter()
            .map(|view| {
                item(
                    "◇",
                    &format!("{} {}", view.agent_id.0, ui_safe_text(&view.label)),
                    &format!("{} · queued {}", state(view.state), view.queued_messages),
                )
            })
            .collect::<Vec<_>>();
        if rows.is_empty() {
            rows.push(block::PanelRow::Note("no persistent agents".into()));
        }
        if value["timed_out"] == true {
            rows.push(block::PanelRow::Note(
                "observation wait elapsed without a newer revision".into(),
            ));
        }
        if let Some(view) = value
            .get("agent")
            .and_then(|agent| serde_json::from_value::<AgentViewV1>(agent.clone()).ok())
        {
            rows.push(kv(
                "parent",
                &view
                    .parent_id
                    .map(|id| id.0.to_string())
                    .unwrap_or_else(|| "root".into()),
            ));
            rows.push(kv("turn ceiling", &view.budget.turns.to_string()));
            rows.push(kv("token ceiling", &view.budget.tokens.to_string()));
            rows.push(kv(
                "cost ceiling (micro USD)",
                &view.budget.cost_microusd.to_string(),
            ));
            rows.push(kv("wall ceiling (ms)", &view.budget.wall_ms.to_string()));
            if let Some(summary) = view.last_summary {
                rows.extend(
                    summary
                        .lines()
                        .take(128)
                        .map(|line| block::PanelRow::Note(ui_safe_text(line))),
                );
            }
        }
        app.panel("◇", "live agents", rows);
    } else if let Some(receipt) = value.get("receipt") {
        app.panel(
            "◇",
            "agent acceptance",
            vec![
                kv("agent", &receipt["agent_id"].to_string()),
                kv("revision", &receipt["revision"].to_string()),
                kv("message receipt", &receipt["message_id"].to_string()),
                block::PanelRow::Note(
                    "accepted durably; receipt/delivery/request inclusion remain separate states"
                        .into(),
                ),
            ],
        );
    } else if let Some(message) = value.get("message") {
        app.panel(
            "◇",
            "agent message receipt",
            vec![
                kv("message", &message["id"].to_string()),
                kv("state", &message["state"].to_string()),
            ],
        );
    } else {
        app.note(block::NoticeLevel::Warn, "agent reply unavailable");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_are_exact_and_interrupt_cannot_guess_a_new_epoch() {
        assert_eq!(usd("1.000001").unwrap(), 1_000_001);
        for bad in ["NaN", "-1", "1.0000001", "1e5", "18446744073709551615"] {
            assert!(usd(bad).is_err());
        }
        assert!(budget(&["0", "10", "1", "60"]).is_err());
        let app = App::new();
        assert!(parse(&app, "interrupt 2").is_err());
        assert!(parse(&app, "spawn 1 task").is_err());
    }
}
