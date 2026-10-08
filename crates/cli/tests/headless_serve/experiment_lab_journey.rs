//! Real CLI/TCP native lab storage and exact signed repository evidence; no model invocation.
use super::*;

#[test]
fn native_lab_request_list_and_comparison_share_scope_policy_and_exact_signed_sources() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let scratch = Scratch::new(&format!("http://{}/v1", listener.local_addr().unwrap()));
    let family = iteron_tunables::families()
        .iter()
        .find(|family| {
            family.implementation_status == iteron_tunables::ImplementationStatus::Full
                && family.optimization.class != iteron_tunables::OptimizationClass::Pin
        })
        .unwrap()
        .id;
    let (process, token, address) = launch(&scratch, &scratch.repo(), 4, &[]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let greeting = receive(&mut reader);
    let thread = greeting["session_id"].as_str().unwrap().to_owned();
    let run = thread.strip_prefix("session-").unwrap().to_owned();
    let command = |source: &str, action: Value| {
        json!({"type":"lab_v1","command":{
        "thread_id":thread,"run_id":source,"action":action}})
    };
    let request = || json!({"type":"request","family":family,"value":"true"});
    send(
        &mut connection,
        control(1450, PROTOCOL_VERSION, command("foreign", request())),
    );
    assert_eq!(matching_control(&mut reader, 1450)["type"], "refused");
    assert!(!scratch.repo().join(".iteron/experiments").exists());
    send(
        &mut connection,
        control(
            1451,
            PROTOCOL_VERSION,
            json!({"type":"set_permission_mode","mode":"plan"}),
        ),
    );
    assert_eq!(matching_control(&mut reader, 1451)["type"], "state");
    send(
        &mut connection,
        control(1452, PROTOCOL_VERSION, command(&run, request())),
    );
    assert_eq!(matching_control(&mut reader, 1452)["type"], "refused");
    assert!(!scratch.repo().join(".iteron/experiments").exists());
    send(
        &mut connection,
        control(
            1453,
            PROTOCOL_VERSION,
            json!({"type":"set_permission_mode","mode":"default"}),
        ),
    );
    assert_eq!(matching_control(&mut reader, 1453)["type"], "state");
    send(
        &mut connection,
        control(1454, PROTOCOL_VERSION, command(&run, request())),
    );
    let created = matching_control(&mut reader, 1454);
    assert_eq!(created["type"], "lab_v1", "{created}");
    assert_eq!(created["receipt"]["run_id"], run);
    assert_eq!(created["runtime_activation"], false);
    let receipt = &created["receipt"]["facts"]["receipt"];
    assert_eq!(receipt["status"], "created");
    let path = scratch
        .repo()
        .join(receipt["relative_path"].as_str().unwrap());
    let bytes = fs::read(&path).unwrap();
    let stored: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stored["allowed_partition"], "train");
    assert_eq!(stored["promotion"]["self_promotion"], false);
    assert_eq!(stored["promotion"]["runtime_activation"], false);
    send(
        &mut connection,
        control(1455, PROTOCOL_VERSION, command(&run, request())),
    );
    let existing = matching_control(&mut reader, 1455);
    assert_eq!(
        existing["receipt"]["facts"]["receipt"]["status"],
        "existing"
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    send(
        &mut connection,
        control(
            1456,
            PROTOCOL_VERSION,
            command(&run, json!({"type":"list"})),
        ),
    );
    let inventory = matching_control(&mut reader, 1456);
    assert_eq!(
        inventory["receipt"]["facts"]["requests"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(inventory["receipt"]["facts"]["incomplete"], false);

    let evidence = scratch
        .repo()
        .join(".iteron/experiments/evidence/evidence-bundle-v1");
    fs::create_dir_all(&evidence).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../eval/fixtures/evidence-bundle-v1");
    for entry in fs::read_dir(fixture).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), evidence.join(entry.file_name())).unwrap();
    }
    let key = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
    let compare = |bundle: &str, key: &str| json!({"type":"compare","bundle_id":bundle,"trusted_public_key":key});
    send(
        &mut connection,
        control(
            1457,
            PROTOCOL_VERSION,
            command(&run, compare("evidence-bundle-v1", key)),
        ),
    );
    let compared = matching_control(&mut reader, 1457);
    assert_eq!(
        compared["receipt"]["facts"]["type"], "comparison",
        "{compared}"
    );
    let view = &compared["receipt"]["facts"]["view"];
    assert_eq!(view["synthetic"], true);
    assert_eq!(view["success"], 2);
    assert_eq!(view["task_failure"], 1);
    assert_eq!(view["infrastructure_failure"], 1);
    assert_eq!(view["held_out"], 1);
    let index: Value =
        serde_json::from_slice(&fs::read(evidence.join("bundle.index.json")).unwrap()).unwrap();
    let report = index["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["role"] == "paired_report")
        .unwrap()["file_name"]
        .as_str()
        .unwrap();
    let report_path = evidence.join(report);
    let mut altered = fs::read(&report_path).unwrap();
    altered.push(b' ');
    fs::write(report_path, altered).unwrap();
    for (id, bundle, key) in [(1458, "evidence-bundle-v1", key), (1459, "../outside", key)] {
        send(
            &mut connection,
            control(id, PROTOCOL_VERSION, command(&run, compare(bundle, key))),
        );
        assert_eq!(matching_control(&mut reader, id)["type"], "refused");
    }
    let mut observer = connect(address);
    let mut greeting = hello(&token, PROTOCOL_VERSION, 0);
    greeting["observation_only"] = json!(true);
    send(&mut observer, greeting);
    let mut observed = BufReader::new(observer.try_clone().unwrap());
    receive(&mut observed);
    send(
        &mut observer,
        control(
            1460,
            PROTOCOL_VERSION,
            command(&run, json!({"type":"list"})),
        ),
    );
    assert_eq!(matching_control(&mut observed, 1460)["type"], "refused");
    drop(connection);
    drop(observer);
    let _ = stop(process);
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}
