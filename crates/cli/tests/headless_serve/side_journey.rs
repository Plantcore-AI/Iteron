//! Existing side conversations via an authenticated client and actual provider IO.
use super::*;

struct OwnedSideService(Option<CoreProcess>);

impl OwnedSideService {
    fn stop(mut self) {
        stop(self.0.take().expect("actual service is still owned"));
    }
}

impl Drop for OwnedSideService {
    fn drop(&mut self) {
        if let Some(mut process) = self.0.take() {
            let _ = process.child.kill();
            let _ = process.child.wait();
            if let Some(stderr) = process.stderr.take() {
                let _ = stderr.join();
            }
        }
    }
}

fn side(
    connection: &mut TcpStream,
    request_id: u64,
    version: u32,
    thread: &str,
    run: &str,
    command: Value,
) {
    send(
        connection,
        control(
            request_id,
            version,
            json!({"type":"side_v1","command":{"thread_id":thread,"run_id":run,"command":command}}),
        ),
    );
}

#[test]
fn public_side_uses_the_same_owner_scope_and_survives_client_observer_loss() {
    let provider = PausedProvider::spawn_two_requests();
    let scratch = Scratch::new(&provider.api_root);
    let (process, token, address) = launch(&scratch, &scratch.repo(), 4, &[]);
    let process = OwnedSideService(Some(process));
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let greeting = receive(&mut reader);
    let thread = greeting["session_id"].as_str().unwrap().to_owned();
    let run = thread.strip_prefix("session-").unwrap().to_owned();

    side(
        &mut connection,
        1500,
        PROTOCOL_VERSION,
        &thread,
        &run,
        json!({"action":"status"}),
    );
    let status = matching_control(&mut reader, 1500);
    assert_eq!(status["type"], "side_status_v1");
    assert!(status["status"].is_null());
    assert_eq!(status["closed"], false);
    assert!(!scratch.runs().join("side").exists());
    side(
        &mut connection,
        1501,
        PROTOCOL_VERSION,
        &thread,
        "foreign",
        json!({"action":"ask","text":"must not dispatch"}),
    );
    assert_eq!(matching_control(&mut reader, 1501)["type"], "refused");
    assert!(!scratch.runs().join("side").exists());
    assert!(matches!(
        provider.request_seen.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));

    side(
        &mut connection,
        1502,
        PROTOCOL_VERSION,
        &thread,
        &run,
        json!({"action":"ask","text":"first public side question"}),
    );
    provider.request_seen.recv_timeout(timeout()).unwrap();
    drop(reader);
    drop(connection);
    provider.release.send(()).unwrap();
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    assert_eq!(receive(&mut reader)["session_id"], thread);
    side(
        &mut connection,
        1503,
        PROTOCOL_VERSION,
        &thread,
        &run,
        json!({"action":"status"}),
    );
    let first = matching_control(&mut reader, 1503);
    assert_eq!(first["status"]["asks"], 1);
    let side_run = first["status"]["side_run_id"].as_str().unwrap().to_owned();
    assert!(!first.to_string().contains("record_path"));
    assert!(
        !first
            .to_string()
            .contains(&scratch.runs().to_string_lossy().to_string())
    );

    side(
        &mut connection,
        1504,
        PROTOCOL_VERSION,
        &thread,
        &run,
        json!({"action":"ask","text":"continue the same public side conversation"}),
    );
    provider.request_seen.recv_timeout(timeout()).unwrap();
    provider.release.send(()).unwrap();
    let second = matching_control(&mut reader, 1504);
    assert_eq!(second["type"], "side_answer_v1");
    assert_eq!(second["outcome"], "done");
    assert_eq!(second["text"], "parity reply");
    assert_eq!(second["text_complete"], true);
    assert_eq!(second["status"]["side_run_id"], side_run);
    assert_eq!(second["status"]["asks"], 2);
    assert!(second["status"]["cost"]["status"].is_string());
    provider.finish();

    let mut observer = connect(address);
    send(
        &mut observer,
        json!({"type":"hello","bearer_token":token,"protocol_version":PROTOCOL_VERSION-1,"observation_only":true}),
    );
    let mut observed = BufReader::new(observer.try_clone().unwrap());
    assert_eq!(receive(&mut observed)["type"], "hello");
    side(
        &mut observer,
        1505,
        PROTOCOL_VERSION - 1,
        &thread,
        &run,
        json!({"action":"status"}),
    );
    assert_eq!(
        matching_control(&mut observed, 1505)["status"]["side_run_id"],
        side_run
    );
    side(
        &mut observer,
        1506,
        PROTOCOL_VERSION - 1,
        &thread,
        &run,
        json!({"action":"close"}),
    );
    assert_eq!(receive(&mut observed)["code"], "observer_authority");
    drop(observed);
    drop(observer);

    side(
        &mut connection,
        1507,
        PROTOCOL_VERSION,
        &thread,
        &run,
        json!({"action":"close"}),
    );
    let closed = matching_control(&mut reader, 1507);
    assert_eq!(closed["closed"], true);
    assert_eq!(closed["status"]["side_run_id"], side_run);
    side(
        &mut connection,
        1508,
        PROTOCOL_VERSION,
        &thread,
        &run,
        json!({"action":"status"}),
    );
    assert!(matching_control(&mut reader, 1508)["status"].is_null());
    drop(reader);
    drop(connection);
    process.stop();

    let records = fs::read_dir(scratch.runs().join("side"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        records.len(),
        1,
        "both questions must use one physical side journal"
    );
    let events = iteron_record::replay(&records[0]).unwrap();
    let provider_intents = events.iter().filter(|event| {
        matches!(&event.kind, iteron_protocol::EventKind::EffectIntent { tool, .. } if tool == "provider")
    }).count();
    assert_eq!(
        provider_intents, 2,
        "reconnect/status/close cannot redispatch side questions"
    );
}
