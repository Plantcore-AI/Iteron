//! Native CLI/TCP project initialization consumes actual host identity and preserves real files.
use super::*;
#[test]
fn native_project_init_is_scoped_create_only_and_refused_to_observers_and_plan() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let scratch = Scratch::new(&format!("http://{}/v1", listener.local_addr().unwrap()));
    let (process, token, address) = launch(&scratch, &scratch.repo(), 4, &[]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let greeting = receive(&mut reader);
    let thread = greeting["session_id"].as_str().unwrap().to_owned();
    let run = thread.strip_prefix("session-").unwrap().to_owned();
    let command =
        |run: &str| json!({"type":"project_init_v1","command":{"thread_id":thread,"run_id":run}});
    send(
        &mut connection,
        control(1210, PROTOCOL_VERSION, command("foreign-run")),
    );
    assert_eq!(matching_control(&mut reader, 1210)["type"], "refused");
    assert!(!scratch.repo().join(".iteron").exists());
    send(
        &mut connection,
        control(
            1211,
            PROTOCOL_VERSION,
            json!({"type":"set_permission_mode","mode":"plan"}),
        ),
    );
    assert_eq!(matching_control(&mut reader, 1211)["type"], "state");
    send(
        &mut connection,
        control(1212, PROTOCOL_VERSION, command(&run)),
    );
    let refused = matching_control(&mut reader, 1212);
    assert_eq!(refused["type"], "project_init_v1", "{refused}");
    assert!(refused["receipt"]["refusal"].is_string());
    assert!(!scratch.repo().join(".iteron").exists());
    send(
        &mut connection,
        control(
            1213,
            PROTOCOL_VERSION,
            json!({"type":"set_permission_mode","mode":"default"}),
        ),
    );
    assert_eq!(matching_control(&mut reader, 1213)["type"], "state");
    send(
        &mut connection,
        control(1214, PROTOCOL_VERSION, command(&run)),
    );
    let receipt = matching_control(&mut reader, 1214);
    assert_eq!(receipt["receipt"]["source_run"], run, "{receipt}");
    assert_eq!(receipt["receipt"]["entries"].as_array().unwrap().len(), 3);
    assert!(
        receipt["receipt"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["status"] == "created"),
        "{receipt}"
    );
    let config = fs::read(scratch.repo().join(".iteron/config.json")).unwrap();
    assert!(serde_json::from_slice::<Value>(&config).is_ok());
    fs::write(
        scratch.repo().join("AGENTS.md"),
        b"actual operator instructions",
    )
    .unwrap();
    send(
        &mut connection,
        control(1215, PROTOCOL_VERSION, command(&run)),
    );
    let preserved = matching_control(&mut reader, 1215);
    assert!(
        preserved["receipt"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["status"] == "existing"),
        "{preserved}"
    );
    assert_eq!(
        fs::read(scratch.repo().join(".iteron/config.json")).unwrap(),
        config
    );
    assert_eq!(
        fs::read(scratch.repo().join("AGENTS.md")).unwrap(),
        b"actual operator instructions"
    );
    let mut observer = connect(address);
    let mut request = hello(&token, PROTOCOL_VERSION, 0);
    request["observation_only"] = json!(true);
    send(&mut observer, request);
    let mut observed = BufReader::new(observer.try_clone().unwrap());
    receive(&mut observed);
    send(
        &mut observer,
        control(1216, PROTOCOL_VERSION, command(&run)),
    );
    assert_eq!(matching_control(&mut observed, 1216)["type"], "refused");
    drop(connection);
    drop(observer);
    let _ = stop(process);
    assert!(matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
}
