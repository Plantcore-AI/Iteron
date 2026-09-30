//! Artifact rendering consumes the same session-scoped read contract as external clients.

use base64::Engine;
use iteron_protocol::client_artifact::ClientArtifactCommandV1;

use super::{App, Session, block, dim, item, ui_safe_text};

pub(super) fn render(app: &mut App, session: &Session, argument: &str) {
    let Some(thread) = session.client.thread_snapshot_v1() else {
        app.note(
            block::NoticeLevel::Warn,
            "artifacts are unavailable until the thread is bound",
        );
        return;
    };
    let argument = argument.trim();
    if argument.is_empty() {
        let reply = session.client.artifacts_v1(ClientArtifactCommandV1::List {
            thread_id: thread.thread_id,
        });
        let rows = reply["artifacts"]
            .as_array()
            .map(|artifacts| {
                artifacts
                    .iter()
                    .map(|artifact| {
                        let id = artifact["artifact_id"].as_str().unwrap_or("?");
                        item(
                            "•",
                            artifact["schema"].as_str().unwrap_or("artifact"),
                            &format!(
                                "{} · {} bytes · {}",
                                &id[..id.len().min(12)],
                                artifact["bytes"],
                                if artifact["complete"] == true {
                                    "complete"
                                } else {
                                    "truncated"
                                }
                            ),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        app.panel("≡", "thread artifacts", rows);
        return;
    }
    let artifact_id = if argument.len() < 64 {
        let listing = session.client.artifacts_v1(ClientArtifactCommandV1::List {
            thread_id: thread.thread_id.clone(),
        });
        let matches = listing["artifacts"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry["artifact_id"].as_str())
                    .filter(|id| id.starts_with(argument))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if argument.len() < 8 || matches.len() != 1 {
            app.note(block::NoticeLevel::Warn, "artifact prefix must match exactly one published artifact and contain at least 8 characters");
            return;
        }
        matches[0].to_owned()
    } else {
        argument.to_owned()
    };
    let reply = session.client.artifacts_v1(ClientArtifactCommandV1::Read {
        thread_id: thread.thread_id,
        artifact_id,
        offset: 0,
        max_bytes: 32 * 1024,
    });
    if reply["type"] != "artifact_chunk_v1" {
        app.note(
            block::NoticeLevel::Warn,
            ui_safe_text(reply["reason"].as_str().unwrap_or("artifact unavailable")),
        );
        return;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(reply["content_base64"].as_str().unwrap_or(""))
        .unwrap_or_default();
    app.push(dim(), ui_safe_text(&String::from_utf8_lossy(&bytes)));
    if reply["eof"] != true {
        app.note(
            block::NoticeLevel::Warn,
            "showing the first 32 KiB; the public artifact API supports paged download",
        );
    }
}
