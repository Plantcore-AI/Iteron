//! Real CLI-selected approval owner, physical native write, two authenticated TCP clients and WAL.
use super::*;

#[derive(Clone, Copy)]
enum Decision {
    Approve,
    Deny,
    Race,
    Cancel,
    Timeout,
    Unavailable,
}
fn attach(address: SocketAddr, token: &str) -> (TcpStream, BufReader<TcpStream>, String) {
    let mut connection = connect(address);
    let mut greeting = hello(token, PROTOCOL_VERSION, 0);
    greeting["product_contract_version"] =
        json!(iteron_protocol::product_contract::PRODUCT_CONTRACT_VERSION);
    send(&mut connection, greeting);
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let hello = receive(&mut reader);
    assert_eq!(hello["type"], "hello");
    let thread = hello["session_id"].as_str().unwrap().to_owned();
    (connection, reader, thread)
}
fn control_reply(reader: &mut BufReader<TcpStream>, id: u64) -> Value {
    super::super::native_host_control::matching_control(reader, id)
}
fn control_frame(id: u64, command: Value) -> Value {
    json!({"type":"control","protocol_version":PROTOCOL_VERSION,"request_id":id,
        "control":{"type":"product_v1","command":command}})
}
fn pending(
    socket: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    thread: &str,
) -> (String, u64, u64) {
    let deadline = Instant::now() + timeout();
    let mut request = 100;
    loop {
        assert!(
            Instant::now() < deadline,
            "actual native approval was not observed"
        );
        send(
            socket,
            control_frame(request, json!({"type":"thread_read","thread_id":thread})),
        );
        let reply = control_reply(reader, request);
        request += 1;
        let turn = &reply["thread"]["turn"];
        if let Some(approval) = turn["pending_approval"].as_u64() {
            assert_eq!(turn["state"], "running");
            return (
                reply["thread"]["run_id"].as_str().unwrap().to_owned(),
                turn["turn_id"].as_u64().unwrap(),
                approval,
            );
        }
        assert!(
            !matches!(
                turn["state"].as_str(),
                Some("completed" | "failed" | "budget_exhausted")
            ),
            "turn ended before the explicitly selected approval channel became reachable"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
fn answer(thread: &str, turn: u64, approval: u64, approved: bool) -> Value {
    json!({"type":"approval_respond","thread_id":thread,"turn_id":turn,
        "approval_id":approval,"approved":approved,"remember":false})
}
fn terminal(socket: &mut TcpStream, reader: &mut BufReader<TcpStream>, thread: &str) -> Value {
    let deadline = Instant::now() + timeout();
    let mut request = 100_000;
    loop {
        assert!(
            Instant::now() < deadline,
            "actual public terminal was not observed"
        );
        send(
            socket,
            control_frame(request, json!({"type":"thread_read","thread_id":thread})),
        );
        let reply = control_reply(reader, request);
        request += 1;
        let turn = &reply["thread"]["turn"];
        if matches!(
            turn["state"].as_str(),
            Some("completed" | "interrupted" | "budget_exhausted" | "failed")
        ) {
            assert!(turn["pending_approval"].is_null());
            assert!(reply["thread"]["source_event_seq"].as_u64().unwrap() > 0);
            return reply["thread"].clone();
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn journey(decision: Decision) {
    let provider = ToolProvider::spawn_for_calls(
        vec![
            json!({"index":0,"id":"real-client-approved-write","type":"function",
            "function":{"name":"write_file","arguments":json!({
                "path":"approval-marker.txt","content":"one admitted native write\n"}).to_string()}}),
        ],
        !matches!(decision, Decision::Cancel | Decision::Timeout),
    );
    let scratch = Scratch::new(&provider.api_root);
    let mut command = core_command_with_launch(
        &scratch,
        &scratch.repo(),
        2,
        &[
            "--mode",
            "default",
            "--max-wall-secs",
            if matches!(decision, Decision::Timeout) {
                "5"
            } else {
                "10"
            },
        ],
    );
    if !matches!(decision, Decision::Unavailable) {
        // This subcommand selection belongs to the operator process, never a Hello or wire op.
        command.arg("--client-approvals");
    }
    let token = fresh_bearer_token();
    let mut process = spawn_core_command_with_token_input(command, token.as_bytes());
    let address = wait_for_listening(&mut process);
    let owner = OwnedCore(Some(process));
    let (mut first, mut first_read, thread) = attach(address, &token);
    let (mut second, mut second_read, second_thread) = attach(address, &token);
    assert_eq!(thread, second_thread);
    let text =
        "Create the specified marker using the native write tool after the operator decision.";
    let request_key = super::super::turn_start_journey::request_key(&thread, text);
    send(
        &mut first,
        control_frame(
            1,
            json!({"type":"turn_start","request_key":request_key,"thread_id":thread,"text":text}),
        ),
    );
    assert_eq!(
        control_reply(&mut first_read, 1)["type"],
        "turn_start_receipt_v2"
    );
    let observed = if matches!(decision, Decision::Unavailable) {
        None
    } else {
        Some(pending(&mut first, &mut first_read, &thread))
    };
    if let Some((_, turn, approval)) = &observed {
        match decision {
            Decision::Approve | Decision::Deny | Decision::Race => {
                let approved = !matches!(decision, Decision::Deny);
                send(
                    &mut first,
                    control_frame(2, answer(&thread, *turn, *approval, approved)),
                );
                if matches!(decision, Decision::Race) {
                    send(
                        &mut second,
                        control_frame(3, answer(&thread, *turn, *approval, false)),
                    );
                }
                let first_reply = control_reply(&mut first_read, 2);
                if matches!(decision, Decision::Race) {
                    let response = control_reply(&mut second_read, 3);
                    assert!(matches!(
                        response["type"].as_str(),
                        Some("control_queued_v1" | "control_refused_v1")
                    ));
                    assert!(matches!(
                        first_reply["type"].as_str(),
                        Some("control_queued_v1" | "control_refused_v1")
                    ));
                    assert!(
                        first_reply["type"] == "control_queued_v1"
                            || response["type"] == "control_queued_v1"
                    );
                } else {
                    assert_eq!(first_reply["type"], "control_queued_v1");
                }
            }
            Decision::Cancel => {
                send(
                    &mut second,
                    control_frame(
                        3,
                        json!({"type":"turn_interrupt",
                    "thread_id":thread,"turn_id":turn}),
                    ),
                );
                assert_eq!(
                    control_reply(&mut second_read, 3)["type"],
                    "control_queued_v1"
                );
            }
            Decision::Timeout => {}
            Decision::Unavailable => unreachable!(),
        }
    }
    // A result broadcast may precede a control reply. Query the same authoritative retained
    // Product terminal rather than accidentally discarding that frame and awaiting a duplicate.
    let terminal = terminal(&mut first, &mut first_read, &thread);
    let outcome = terminal["turn"]["state"].as_str().unwrap();
    match decision {
        Decision::Cancel => assert_eq!(outcome, "interrupted"),
        Decision::Timeout => assert_eq!(outcome, "budget_exhausted"),
        _ => assert_eq!(outcome, "completed"),
    }
    if let Some((run, turn, approval)) = &observed {
        assert_eq!(terminal["run_id"], *run);
        send(
            &mut first,
            control_frame(4, answer(&thread, *turn, *approval, true)),
        );
        assert_eq!(
            control_reply(&mut first_read, 4)["type"],
            "control_refused_v1",
            "a stale/duplicate old approval cannot grant a future turn"
        );
    }
    provider.finish();
    owner.stop();
    let path = only_rollout(&scratch.runs());
    let events = iteron_record::replay(&path).unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event.kind, EventKind::Done { .. })),
        "the observed terminal also has an actual committed journal end"
    );
    let approvals = events
        .iter()
        .filter_map(|event| {
            if let EventKind::Approval {
                id, tool, verdict, ..
            } = &event.kind
            {
                assert_eq!(tool, "write_file");
                Some((*id, *verdict))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        approvals.len(),
        2,
        "one real ask and one physical writer-confirmed verdict"
    );
    assert_eq!(approvals[0].0, approvals[1].0);
    assert_eq!(approvals[0].1, iteron_protocol::Verdict::Ask);
    let approved = approvals[1].1 == iteron_protocol::Verdict::Auto;
    assert_eq!(
        scratch.repo().join("approval-marker.txt").exists(),
        approved
    );
    match decision {
        Decision::Approve => assert!(approved),
        Decision::Race => {}
        _ => assert!(!approved),
    }
    if approved {
        assert_eq!(
            fs::read(scratch.repo().join("approval-marker.txt")).unwrap(),
            b"one admitted native write\n"
        );
    }
}
#[test]
fn explicit_cli_approval_selection_reaches_actual_write_deny_and_two_client_race() {
    for decision in [Decision::Approve, Decision::Deny, Decision::Race] {
        journey(decision);
    }
}
#[test]
fn explicit_cli_approval_interrupt_and_wall_timeout_never_dispatch_the_pending_write() {
    for decision in [Decision::Cancel, Decision::Timeout] {
        journey(decision);
    }
}
#[test]
fn default_cli_service_preserves_finite_noninteractive_approval_refusal() {
    journey(Decision::Unavailable);
}
