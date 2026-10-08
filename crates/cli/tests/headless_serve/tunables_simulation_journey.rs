//! Actual CLI/TCP reads the operator's workspace file; no provider request supplies a report.
use super::*;
#[test]
fn native_workspace_simulation_is_scoped_bounded_redacted_and_operator_only() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let scratch = Scratch::new(&format!("http://{}/v1", listener.local_addr().unwrap()));
    let activation = iteron_tunables::families()
        .iter()
        .filter_map(|family| match family.activation.predicate {
            iteron_tunables::ActivationPredicate::RuntimeDerived { seam } => Some(json!({
                "family":family.id,"seam":seam,"subject_digest_sha256":"a".repeat(64),
                "evidence_digest_sha256":"b".repeat(64),"active":true,
            })),
            _ => None,
        })
        .collect::<Vec<_>>();
    let bytes=serde_json::to_vec(&json!({
        "schema_version":iteron_tunables::RESOLUTION_SCHEMA_VERSION,
        "registry_id":iteron_tunables::REGISTRY_ID,"registry_revision":iteron_tunables::REGISTRY_REVISION,
        "registry_digest":iteron_tunables::REGISTRY_DIGEST_SHA256,"activation_evidence":activation,
        "declared_values":[],"default_evidence":[],"constraint_evidence":[],"runtime":{},
    })).unwrap();
    fs::write(scratch.repo().join("request.json"), &bytes).unwrap();
    fs::write(
        scratch.repo().join("large.json"),
        vec![b' '; iteron_tunables::RESOLUTION_INPUT_MAX_BYTES + 1],
    )
    .unwrap();
    let (process, token, address) = launch(&scratch, &scratch.repo(), 4, &[]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let greeting = receive(&mut reader);
    let thread = greeting["session_id"].as_str().unwrap().to_owned();
    let run = thread.strip_prefix("session-").unwrap().to_owned();
    let command = |source: &str, path: &str| {
        json!({"type":"tunables_simulation_v1","command":{
            "thread_id":thread,"run_id":source,"relative_path":path,
        }})
    };
    for (id, source, path) in [
        (1410, "foreign", "request.json"),
        (1411, run.as_str(), "../request.json"),
        (1412, run.as_str(), "large.json"),
    ] {
        send(
            &mut connection,
            control(id, PROTOCOL_VERSION, command(source, path)),
        );
        assert_eq!(matching_control(&mut reader, id)["type"], "refused");
    }
    send(
        &mut connection,
        control(1413, PROTOCOL_VERSION, command(&run, "request.json")),
    );
    let reply = matching_control(&mut reader, 1413);
    assert_eq!(reply["type"], "tunables_simulation_v1", "{reply}");
    assert_eq!(reply["receipt"]["run_id"], run);
    assert_eq!(reply["runtime_bound"], false);
    assert_eq!(
        reply["receipt"]["view"]["status"],
        "active resolution failed"
    );
    assert_eq!(
        reply["receipt"]["view"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        iteron_tunables::EXPECTED_FAMILY_COUNT
    );
    let encoded = serde_json::to_string(&reply).unwrap();
    assert!(!encoded.contains(&"a".repeat(64)));
    assert!(!encoded.contains(&"b".repeat(64)));
    assert_eq!(
        fs::read(scratch.repo().join("request.json")).unwrap(),
        bytes
    );
    let mut observer = connect(address);
    let mut request = hello(&token, PROTOCOL_VERSION, 0);
    request["observation_only"] = json!(true);
    send(&mut observer, request);
    let mut observed = BufReader::new(observer.try_clone().unwrap());
    receive(&mut observed);
    send(
        &mut observer,
        control(1414, PROTOCOL_VERSION, command(&run, "request.json")),
    );
    assert_eq!(matching_control(&mut observed, 1414)["type"], "refused");
    drop(connection);
    drop(observer);
    let _ = stop(process);
    assert!(matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
}
