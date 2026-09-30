//! Actual optional route/calibration writers and their independent public journal observation.
use super::*;
use iteron_protocol::advisory_maintenance::{MaintenanceKindV1, MaintenanceStateV1};
use iteron_protocol::advisory_maintenance_control::MaintenanceEventV1;

fn observe(
    connection: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    thread_id: &str,
    id: u64,
    subscribe: bool,
    mut live_seen: Option<&mut bool>,
) -> Value {
    send(
        connection,
        control(
            id,
            PROTOCOL_VERSION,
            json!({"type":"maintenance_v1","command":{
                "type":if subscribe { "subscribe" } else { "read" },"thread_id":thread_id
            }}),
        ),
    );
    loop {
        let frame = receive(reader);
        if frame["type"] == "advisory_maintenance_v1" {
            let event: MaintenanceEventV1 = serde_json::from_value(frame["event"].clone()).unwrap();
            event.validate().unwrap();
            assert_eq!(event.thread_id.0, thread_id);
            if let Some(seen) = live_seen.as_deref_mut() {
                *seen = true;
            }
        }
        if frame["type"] == "control_reply" && frame["request_id"] == id {
            return frame["reply"].clone();
        }
    }
}

#[test]
fn actual_maintenance_snapshot_is_readonly_scope_bound_and_survives_restart() {
    let provider = ToolProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    fs::write(scratch.repo().join("large-output.txt"), "small actual file").unwrap();
    let (child, token, address) = launch(&scratch, &scratch.repo(), 2, &[]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let thread_id = receive(&mut reader)["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let subscription = observe(&mut connection, &mut reader, &thread_id, 801, true, None);
    assert!(matches!(
        subscription["type"].as_str(),
        Some("maintenance_snapshot_v1" | "maintenance_unavailable_v1")
    ));
    assert_eq!(
        observe(
            &mut connection,
            &mut reader,
            "foreign-thread",
            802,
            false,
            None
        )["type"],
        "maintenance_refused_v1"
    );
    send(
        &mut connection,
        json!({"type":"submit","protocol_version":PROTOCOL_VERSION,
        "op":{"op":"user_input","text":"read large-output.txt then answer"}}),
    );
    let deadline = Instant::now() + timeout();
    let mut saw_journal_event = false;
    loop {
        assert!(
            Instant::now() < deadline,
            "maintenance/answer journey timed out"
        );
        let frame = receive(&mut reader);
        if frame["type"] == "advisory_maintenance_v1" {
            let event: MaintenanceEventV1 = serde_json::from_value(frame["event"].clone()).unwrap();
            event.validate().unwrap();
            assert_eq!(event.thread_id.0, thread_id);
            saw_journal_event = true;
        }
        if frame["type"] == "result" {
            assert_eq!(frame["result"]["outcome"], "done");
            break;
        }
    }
    let mut request = 803;
    let actual = loop {
        assert!(
            Instant::now() < deadline,
            "real optional journal jobs did not settle"
        );
        let reply = observe(
            &mut connection,
            &mut reader,
            &thread_id,
            request,
            false,
            Some(&mut saw_journal_event),
        );
        request += 1;
        if let Ok(event) = serde_json::from_value::<MaintenanceEventV1>(reply["event"].clone()) {
            event.validate().unwrap();
            if event
                .observation
                .jobs
                .iter()
                .any(|job| job.kind == MaintenanceKindV1::LastSuccessfulRoute)
                && event
                    .observation
                    .jobs
                    .iter()
                    .any(|job| job.kind == MaintenanceKindV1::TokenCalibration)
                && event
                    .observation
                    .jobs
                    .iter()
                    .all(|job| job.state == MaintenanceStateV1::Completed)
            {
                break event;
            }
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert!(
        saw_journal_event,
        "subscribed TCP client did not receive an actual journal observation"
    );
    let serialized = serde_json::to_string(&actual).unwrap();
    assert!(!serialized.contains(KEY));
    assert!(!serialized.contains("target"));
    assert!(!serialized.contains("large-output.txt"));
    let run = actual.run_id.0.clone();
    // Verify actual retained journal bytes, independent of a frontend's completion wording.
    #[cfg(unix)]
    {
        let journal = scratch
            .runs()
            .join("advisory-maintenance-v1")
            .join(&actual.observation.scope_sha256[7..])
            .join("maintenance.json");
        let bytes = fs::read(&journal).unwrap();
        let envelope: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            envelope["snapshot"]["revision"],
            actual.observation.journal_revision
        );
        assert_eq!(envelope["sha256"], actual.observation.journal_sha256);
        let marker = b"\"snapshot\":";
        let start = bytes
            .windows(marker.len())
            .position(|part| part == marker)
            .unwrap()
            + marker.len();
        let payload = &bytes[start..bytes.len() - 1];
        assert_eq!(
            serde_json::from_slice::<Value>(payload).unwrap(),
            envelope["snapshot"]
        );
        assert_eq!(
            format!("sha256:{:x}", Sha256::digest(payload)),
            actual.observation.journal_sha256
        );
    }
    drop(reader);
    drop(connection);
    child.stop();
    provider.finish();
    let (restored, token, address) = launch(&scratch, &scratch.repo(), 2, &["--resume", &run]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    receive(&mut reader);
    let deadline = Instant::now() + timeout();
    let recovered = loop {
        let reply = observe(
            &mut connection,
            &mut reader,
            &thread_id,
            request,
            false,
            Some(&mut saw_journal_event),
        );
        request += 1;
        if let Ok(event) = serde_json::from_value::<MaintenanceEventV1>(reply["event"].clone()) {
            break event;
        }
        assert!(
            Instant::now() < deadline,
            "maintenance owner did not restore"
        );
        thread::sleep(Duration::from_millis(20));
    };
    recovered.validate().unwrap();
    assert_eq!(recovered.observation, actual.observation);
    drop(reader);
    drop(connection);
    restored.stop();
}
