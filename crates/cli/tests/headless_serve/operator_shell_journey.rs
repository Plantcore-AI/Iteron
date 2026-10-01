//! Real TCP operator shell control: native workspace/policy and explicit observer refusal.
use super::*;
#[test]
fn actual_operator_shell_uses_host_scope_and_current_mode_without_a_model_turn() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_root = format!("http://{}/v1", listener.local_addr().unwrap());
    let scratch = Scratch::new(&api_root);
    let (process, token, address) = launch(&scratch, &scratch.repo(), 4, &[]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let greeting = receive(&mut reader);
    let thread = greeting["session_id"].as_str().unwrap().to_owned();
    let run = thread.strip_prefix("session-").unwrap().to_owned();
    let shell = |run: &str, command: &str| json!({"type":"operator_shell_v1","command":{"thread_id":thread,"run_id":run,"command":command}});
    send(
        &mut connection,
        control(
            1180,
            PROTOCOL_VERSION,
            shell("foreign", "printf wrong > wrong-source"),
        ),
    );
    assert_eq!(matching_control(&mut reader, 1180)["type"], "refused");
    assert!(!scratch.repo().join("wrong-source").exists());
    send(
        &mut connection,
        control(
            1181,
            PROTOCOL_VERSION,
            shell(&run, "printf actual > shell-owned; printf 'native reply\n'"),
        ),
    );
    let value = matching_control(&mut reader, 1181);
    assert_eq!(value["type"], "operator_shell_v1", "{value}");
    assert_eq!(value["receipt"]["source_run"], run);
    assert_eq!(value["receipt"]["outcome"], "completed");
    assert_eq!(value["receipt"]["cleanup"], "reaped");
    assert!(
        value["receipt"]["body"]
            .as_str()
            .unwrap()
            .contains("native reply")
    );
    assert_eq!(
        fs::read(scratch.repo().join("shell-owned")).unwrap(),
        b"actual"
    );
    send(
        &mut connection,
        control(
            1182,
            PROTOCOL_VERSION,
            json!({"type":"set_permission_mode","mode":"plan"}),
        ),
    );
    assert_eq!(matching_control(&mut reader, 1182)["type"], "state");
    send(
        &mut connection,
        control(
            1183,
            PROTOCOL_VERSION,
            shell(&run, "printf forbidden > plan-denied"),
        ),
    );
    let value = matching_control(&mut reader, 1183);
    assert_eq!(value["receipt"]["outcome"], "not_started", "{value}");
    assert!(!scratch.repo().join("plan-denied").exists());
    let mut observer = connect(address);
    let mut observed_hello = hello(&token, PROTOCOL_VERSION, 0);
    observed_hello["observation_only"] = json!(true);
    send(&mut observer, observed_hello);
    let mut observed = BufReader::new(observer.try_clone().unwrap());
    assert_eq!(receive(&mut observed)["type"], "hello");
    send(
        &mut observer,
        control(
            1184,
            PROTOCOL_VERSION,
            shell(&run, "printf forbidden > observer-denied"),
        ),
    );
    assert_eq!(matching_control(&mut observed, 1184)["type"], "refused");
    assert!(!scratch.repo().join("observer-denied").exists());
    drop(observer);
    drop(connection);
    let _ = stop(process);
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "operator shell must not invoke a model or discovery"
    );
}
