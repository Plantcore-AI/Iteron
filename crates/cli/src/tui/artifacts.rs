//! Artifact rendering consumes the same session-scoped read contract as external clients.

use iteron_protocol::client_artifact::ClientArtifactCommandV1;

use super::{App, Session, block, item};

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
        render_listing(app, &reply);
        return;
    }
    let result = app.artifact_viewer.open_local(
        session.client.clone(),
        thread.thread_id,
        thread.run_id,
        argument.to_owned(),
    );
    super::artifact_view::note_open_result(app, result);
}

pub(super) fn render_listing(app: &mut App, reply: &serde_json::Value) {
    let Some(artifacts) = reply["artifacts"]
        .as_array()
        .filter(|rows| rows.len() <= 512)
    else {
        app.note(
            block::NoticeLevel::Warn,
            "artifact listing unavailable or exceeds its bound",
        );
        return;
    };
    if reply["type"] != "artifacts_v1" || reply["contract_version"] != 1 {
        app.note(
            block::NoticeLevel::Warn,
            "artifact listing contract unavailable",
        );
        return;
    }
    let rows = {
        artifacts
            .iter()
            .map(|artifact| {
                let id = artifact["artifact_id"]
                    .as_str()
                    .filter(|id| {
                        id.len() == 64
                            && id
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    .unwrap_or("?");
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
    };
    app.panel("≡", "thread artifacts", rows);
}
