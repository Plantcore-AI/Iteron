use super::*;
use core_protocol::{Event, EventKind, Seq, TurnId};

struct Runs(std::path::PathBuf);

impl Drop for Runs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn runs_dir(label: &str) -> Runs {
    let path = std::env::temp_dir().join(format!(
        "core-session-view-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    Runs(path)
}

fn write_run(dir: &std::path::Path, run: &RunId, texts: &[&str]) {
    let mut rollout = core_record::Rollout::open(dir, run, TenantId::default()).unwrap();
    for (index, text) in texts.iter().enumerate() {
        rollout
            .append(&Event {
                seq: Seq(index as u64 + 1),
                turn: TurnId(1),
                kind: EventKind::Text {
                    delta: (*text).to_owned(),
                },
            })
            .unwrap();
    }
}

fn write_tagged_run(dir: &std::path::Path, run: &RunId, tag: Option<&str>, texts: &[&str]) {
    let mut rollout = core_record::Rollout::open(dir, run, TenantId::default()).unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::RunStart {
                cwd: "/repo".into(),
                model: "model".into(),
                effort: core_protocol::Effort::Medium,
                created_at: 1,
                environment: None,
                parent_run: None,
                forked_at: None,
                parent_hash_at_seq: None,
                config_digest: String::new(),
                agent_definition_tag: tag.map(str::to_owned),
                max_usd: None,
            },
        })
        .unwrap();
    for (index, text) in texts.iter().enumerate() {
        rollout
            .append(&Event {
                seq: Seq(index as u64 + 1),
                turn: TurnId(1),
                kind: EventKind::Text {
                    delta: (*text).to_owned(),
                },
            })
            .unwrap();
    }
}

/// A client must be able to read a conversation without opening anything under `.core/runs`.
#[test]
fn a_transcript_is_readable_through_the_contract() {
    let runs = runs_dir("read");
    let run = RunId("read-me".into());
    write_run(&runs.0, &run, &["hello", "world"]);

    let document = read_transcript(&runs.0, &run).expect("the transcript reads back");
    assert_eq!(document.schema_version, SESSION_VIEW_SCHEMA_VERSION);
    assert_eq!(document.run_id, "read-me");
    assert!(!document.truncated);
    assert!(document.total_events >= 2);
    let rendered = serde_json::to_string(&document.events).unwrap();
    assert!(rendered.contains("hello"), "{rendered}");
    assert!(rendered.contains("world"), "{rendered}");
}

/// A credential-shaped token in a historical transcript must not reach the client.
#[test]
fn the_read_path_redacts_rather_than_trusting_the_writer() {
    let runs = runs_dir("redact");
    let run = RunId("secret-run".into());
    let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
    write_run(&runs.0, &run, &[secret]);

    let document = read_transcript(&runs.0, &run).expect("the transcript reads back");
    let rendered = serde_json::to_string(&document.events).unwrap();
    assert!(
        !rendered.contains(secret),
        "a credential must not survive the read path: {rendered}"
    );
    assert!(rendered.contains("REDACTED"), "{rendered}");
}

/// A missing run is an error, not an empty conversation that reads as complete.
#[test]
fn a_missing_run_is_an_error_not_an_empty_transcript() {
    let runs = runs_dir("missing");
    assert!(read_transcript(&runs.0, &RunId("absent".into())).is_err());
}

/// A listing must answer even with no index at all, and must say when it is only a page.
#[test]
fn listing_degrades_to_replay_and_reports_truncation() {
    let runs = runs_dir("list");
    for index in 0..3 {
        write_run(&runs.0, &RunId(format!("run-{index}")), &["hi"]);
    }
    // No `sessions.index` is written by this path, so the listing is already the degraded one.
    let all = list_sessions(&runs.0, &TenantId::default(), None, MAX_SESSIONS_PER_PAGE);
    assert_eq!(all.schema_version, SESSION_VIEW_SCHEMA_VERSION);
    assert_eq!(all.total, 3, "the replay path still answers");
    assert!(!all.truncated);
    assert_eq!(all.sessions.len(), 3);

    let paged = list_sessions(&runs.0, &TenantId::default(), None, 2);
    assert_eq!(paged.total, 3);
    assert!(paged.truncated, "a page must say it is a page");
    assert_eq!(paged.sessions.len(), 2);
}

/// The page bound is a ceiling a caller cannot argue past.
#[test]
fn the_page_bound_cannot_be_exceeded_by_the_caller() {
    let runs = runs_dir("bound");
    write_run(&runs.0, &RunId("only".into()), &["hi"]);
    let document = list_sessions(&runs.0, &TenantId::default(), None, usize::MAX);
    assert_eq!(document.sessions.len(), 1);
    assert!(!document.truncated);
}

#[test]
fn opaque_list_cursors_traverse_without_duplicates_and_bind_the_filter() {
    let runs = runs_dir("cursor-list");
    write_tagged_run(&runs.0, &RunId("run-a".into()), Some("agent-a"), &["a"]);
    write_tagged_run(&runs.0, &RunId("run-b".into()), Some("agent-a"), &["b"]);
    write_tagged_run(&runs.0, &RunId("run-c".into()), Some("agent-b"), &["c"]);

    let first =
        list_sessions_page(&runs.0, &TenantId::default(), Some("agent-a"), 1, None, 4).unwrap();
    assert_eq!(first.frame_type, "session_list_page");
    assert_eq!(first.sessions.len(), 1);
    let cursor = first.next_cursor.as_deref().expect("a second filtered row");
    let second = list_sessions_page(
        &runs.0,
        &TenantId::default(),
        Some("agent-a"),
        1,
        Some(cursor),
        4,
    )
    .unwrap();
    assert_eq!(second.sessions.len(), 1);
    assert_ne!(first.sessions[0].run_id, second.sessions[0].run_id);
    assert!(second.next_cursor.is_none());
    assert!(
        list_sessions_page(
            &runs.0,
            &TenantId::default(),
            Some("agent-b"),
            1,
            Some(cursor),
            4,
        )
        .is_err(),
        "a cursor from one tag filter must not be replayed against another"
    );
}

#[test]
fn transcript_pages_walk_the_tail_without_gaps_or_cross_run_reuse() {
    let runs = runs_dir("cursor-transcript");
    let run = RunId("paged".into());
    write_run(&runs.0, &run, &["first", "second", "third"]);
    let other = RunId("different".into());
    write_run(&runs.0, &other, &["other"]);
    let events = core_record::load_forked(&runs.0, &run).unwrap();
    let one_event_bound = events
        .iter()
        .map(|event| serde_json::to_vec(&redact_event(event)).unwrap().len() + 1)
        .max()
        .unwrap();

    let mut cursor = None;
    let mut deltas = Vec::new();
    loop {
        let page =
            read_transcript_page_with_limit(&runs.0, &run, cursor.as_deref(), 4, one_event_bound)
                .unwrap();
        assert_eq!(page.frame_type, "session_transcript_page");
        assert_eq!(page.events.len(), 1);
        deltas.push(page.events[0]["kind"]["delta"].as_str().unwrap().to_owned());
        let Some(next) = page.older_cursor else {
            break;
        };
        if cursor.is_none() {
            assert!(
                read_transcript_page_with_limit(&runs.0, &other, Some(&next), 4, one_event_bound,)
                    .is_err()
            );
        }
        cursor = Some(next);
    }
    assert_eq!(deltas, ["third", "second", "first"]);
}

#[test]
fn agent_definition_tags_are_bounded_control_free_and_secret_averse() {
    assert!(validate_agent_definition_tag("reviewer-a").is_ok());
    assert!(validate_agent_definition_tag("").is_err());
    assert!(validate_agent_definition_tag("bad\ntag").is_err());
    assert!(validate_agent_definition_tag(&"x".repeat(129)).is_err());
    assert!(validate_agent_definition_tag("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx").is_err());
}
