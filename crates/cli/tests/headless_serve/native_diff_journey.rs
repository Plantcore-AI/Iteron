//! Actual native transaction -> public whole-file references -> restart download.

use super::*;

fn native_call(index: usize, id: &str, name: &str, input: Value) -> Value {
    json!({"index":index,"id":id,"type":"function",
        "function":{"name":name,"arguments":input.to_string()}})
}

fn download(
    connection: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    thread_id: &str,
    descriptor: &Value,
    request_id: &mut u64,
) -> Vec<u8> {
    let id = descriptor["artifact_id"]
        .as_str()
        .expect("resolvable served artifact identity");
    assert_eq!(id.len(), 64);
    assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let mut bytes = Vec::new();
    let mut offset = 0;
    for _ in 0..130 {
        *request_id += 1;
        let chunk = artifact_read(connection, reader, thread_id, id, *request_id, offset);
        assert_eq!(chunk["type"], "artifact_chunk_v1", "{chunk}");
        assert_eq!(chunk["artifact"], *descriptor);
        assert_eq!(chunk["offset"], offset);
        assert_eq!(chunk["provenance"], "retained_owner_manifest");
        bytes.extend(
            base64::engine::general_purpose::STANDARD
                .decode(chunk["content_base64"].as_str().unwrap())
                .unwrap(),
        );
        offset = chunk["next_offset"].as_u64().unwrap();
        assert!(bytes.len() <= 8 * 1024 * 1024);
        if chunk["eof"] == true {
            assert_eq!(bytes.len() as u64, descriptor["bytes"].as_u64().unwrap());
            assert_eq!(hex::encode(Sha256::digest(&bytes)), id);
            return bytes;
        }
    }
    panic!("bounded whole-file download did not reach EOF");
}

fn manifests(listing: &Value) -> Vec<Value> {
    listing["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["schema"] == "iteron.file-diff.v1")
        .cloned()
        .collect()
}

#[test]
fn actual_native_commits_publish_resolvable_scrubbed_whole_snapshots_after_restart() {
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let write_before = format!(
        "header before\n{}\napi_key={secret}\nwhole before tail\n",
        "original safe fragment\n".repeat(15000)
    );
    let write_after = format!(
        "header after\n{}\napi_key={secret}\nwhole after tail\n",
        "replaced safe fragment\n".repeat(15000)
    );
    assert!(write_before.len() > 256 * 1024 && write_after.len() > 256 * 1024);
    let edit_before = "\u{feff}header\r\nbefore\r\nfooter";
    let edit_after = "\u{feff}header\r\nafter\r\nsecond\r\nfooter";
    let calls = vec![
        native_call(
            0,
            "diff-write",
            "write_file",
            json!({"path":"whole.txt","content":write_after,"expected_sha256":hex::encode(Sha256::digest(write_before.as_bytes()))}),
        ),
        native_call(
            1,
            "diff-edit",
            "edit",
            json!({"path":"edit.txt","old":"before","new":"after\nsecond"}),
        ),
        native_call(
            2,
            "diff-patch",
            "apply_patch",
            json!({"files":[
                {"path":"a.txt","hunks":[{"old":"before","new":"after"}]},
                {"path":"b.txt","hunks":[{"old":"before","new":"changed"}]}
            ]}),
        ),
        native_call(
            3,
            "diff-create",
            "write_file",
            json!({"path":"created.txt","content":"created whole bytes\n"}),
        ),
    ];
    // The listener starts before physical startup and journal fsync. Its bounded admission
    // window must cover the same 30-second transaction journey as the runtime and observer.
    let provider =
        ToolProvider::spawn_for_calls_with_wait(calls, true, timeout().saturating_mul(3));
    let scratch = Scratch::new(&provider.api_root);
    // Four physical transactions retain complete snapshots, including two 300 KiB files.
    // Give this artifact journey its own finite wall ceiling, matching its terminal wait.
    let config_path = scratch.home().join(".iteron/config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    config["max_wall_secs"] = json!(30);
    fs::write(config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    for (path, text) in [
        ("whole.txt", write_before.as_str()),
        ("edit.txt", edit_before),
        ("a.txt", "a header\nbefore\na footer\n"),
        ("b.txt", "b header\nbefore\nb footer\n"),
    ] {
        fs::write(scratch.repo().join(path), text).unwrap();
    }
    // The real executable launches the owned Landlock process on Linux. This is no bypass/test
    // thread fixture; macOS retains descriptor transactions and its explicit platform notice.
    let (child, token, address) = launch(
        &scratch,
        &scratch.repo(),
        2,
        &["--mode", "accept_edits", "--confine"],
    );
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let thread_id = receive(&mut reader)["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    send(
        &mut connection,
        json!({"type":"submit","protocol_version":PROTOCOL_VERSION,
        "op":{"op":"user_input","text":"Apply the specified complete file replacement, unique edit, two-file patch and creation."}}),
    );
    let deadline = Instant::now() + timeout().saturating_mul(3);
    let terminal = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "native diff transactions did not settle"
        );
        reader.get_mut().set_read_timeout(Some(remaining)).unwrap();
        let frame = receive(&mut reader);
        if frame["type"] == "result" {
            break frame;
        }
    };
    assert_eq!(terminal["result"]["outcome"], "done", "{terminal}");
    provider.finish();
    assert_eq!(
        fs::read_to_string(scratch.repo().join("whole.txt")).unwrap(),
        write_after
    );
    assert_eq!(
        fs::read_to_string(scratch.repo().join("edit.txt")).unwrap(),
        edit_after
    );
    assert_eq!(
        fs::read_to_string(scratch.repo().join("a.txt")).unwrap(),
        "a header\nafter\na footer\n"
    );
    assert_eq!(
        fs::read_to_string(scratch.repo().join("b.txt")).unwrap(),
        "b header\nchanged\nb footer\n"
    );
    let run_id = thread_id.strip_prefix("session-").unwrap();
    send(
        &mut connection,
        control(
            490,
            PROTOCOL_VERSION,
            json!({"type":"host_final_evidence_v1","command":{"thread_id":thread_id,"run_id":run_id}}),
        ),
    );
    let final_fact = matching_control(&mut reader, 490);
    assert_eq!(final_fact["source"], "actual_host_receipt");
    assert_eq!(final_fact["run_id"], run_id);
    assert_eq!(final_fact["evidence"]["work_state"], "changed_unverified");
    // Four native completions changed five members (the two-file patch is one tool).
    // This is not a filesystem scan or a count of current distinct dirty files.
    assert_eq!(final_fact["evidence"]["observed_native_file_changes"], 5);
    assert_eq!(final_fact["evidence"]["observed_tool_completions"], 4);
    assert_eq!(final_fact["evidence"]["configured_check"], "not_observed");
    assert_eq!(final_fact["evidence"]["workspace_diff_inspected"], false);
    assert_eq!(
        final_fact["evidence"]["test_suite_identity_verified"],
        false
    );
    let native_source = final_fact["evidence"]["native_change_source_seq"]
        .as_u64()
        .unwrap();
    let done_source = final_fact["evidence"]["source_seq"].as_u64().unwrap();
    assert!(native_source > 0 && native_source < done_source);
    let listing = artifact_list(&mut connection, &mut reader, &thread_id, 500);
    let diffs = manifests(&listing);
    assert_eq!(
        diffs.len(),
        4,
        "all actual successful native receipts publish manifests: {listing}"
    );
    let mut request_id = 501;
    let mut captured = Vec::new();
    for descriptor in &diffs {
        let bytes = download(
            &mut connection,
            &mut reader,
            &thread_id,
            descriptor,
            &mut request_id,
        );
        let manifest: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(manifest["type"], "native_file_diff_v1");
        assert_eq!(manifest["basis"], "guarded_native_commit");
        assert_eq!(manifest["redaction"], "served_content");
        captured.push((descriptor.clone(), manifest));
    }
    drop(reader);
    drop(connection);
    child.stop();
    let run_id = thread_id.strip_prefix("session-").unwrap();
    let events = iteron_record::load_forked(&scratch.runs(), &RunId(run_id.into())).unwrap();
    assert!(events.iter().any(|event| event.seq.0 == native_source
        && matches!(&event.kind, EventKind::ToolDone { result, tool:Some(tool), effect_id:Some(_)}
            if tool == "write_file" && result.tool_use_id == "diff-create" && !result.is_error)));
    assert!(events.iter().any(|event| event.seq.0 == done_source
        && matches!(&event.kind, EventKind::Done { outcome } if outcome == "Done")));
    let (restarted, token, address) = launch(&scratch, &scratch.repo(), 2, &["--resume", run_id]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    assert_eq!(receive(&mut reader)["session_id"], thread_id);
    let listing = artifact_list(&mut connection, &mut reader, &thread_id, 600);
    assert_eq!(
        manifests(&listing),
        diffs,
        "restart preserves immutable descriptor origin and identity"
    );
    request_id = 601;
    let expected = BTreeMap::from([
        (
            "whole.txt",
            (Some(write_before.as_str()), write_after.as_str()),
        ),
        ("edit.txt", (Some(edit_before), edit_after)),
        (
            "a.txt",
            (
                Some("a header\nbefore\na footer\n"),
                "a header\nafter\na footer\n",
            ),
        ),
        (
            "b.txt",
            (
                Some("b header\nbefore\nb footer\n"),
                "b header\nchanged\nb footer\n",
            ),
        ),
        ("created.txt", (None, "created whole bytes\n")),
    ]);
    let mut seen = BTreeSet::new();
    for (descriptor, manifest) in captured {
        // The public correlation field is scrubbed display text. Bind source evidence through
        // this fixture's known operation/path, never by treating display text as an exact ID.
        let files = manifest["files"].as_array().unwrap();
        let id = match (
            manifest["tool"].as_str().unwrap(),
            files[0]["path"].as_str().unwrap(),
        ) {
            ("write_file", "whole.txt") => "diff-write",
            ("write_file", "created.txt") => "diff-create",
            ("edit", "edit.txt") => "diff-edit",
            ("apply_patch", "a.txt") => "diff-patch",
            other => panic!("unexpected actual native receipt {other:?}"),
        };
        assert_eq!(
            manifest["tool_use_id_display"],
            iteron_record::redact::scrub(id)
        );
        assert!(manifest.get("tool_use_id").is_none());
        let intent = events
            .iter()
            .find(|event| {
                matches!(&event.kind,
            EventKind::EffectIntent {tool_use_id,..} if tool_use_id == id)
            })
            .expect("actual admitted durable intent");
        assert_eq!(descriptor["source_event_seq"], intent.seq.0);
        let restored = download(
            &mut connection,
            &mut reader,
            &thread_id,
            &descriptor,
            &mut request_id,
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&restored).unwrap(),
            manifest
        );
        for file in manifest["files"].as_array().unwrap() {
            let path = file["path"].as_str().unwrap();
            assert!(seen.insert(path.to_owned()));
            let (before, after) = expected[path];
            if let Some(before) = before {
                let bytes = download(
                    &mut connection,
                    &mut reader,
                    &thread_id,
                    &file["before"],
                    &mut request_id,
                );
                assert_eq!(bytes, iteron_record::redact::scrub(before).as_bytes());
                assert!(!String::from_utf8_lossy(&bytes).contains(secret));
            } else {
                assert!(
                    file["before"].is_null(),
                    "creation cannot invent a prior file object"
                );
            }
            let bytes = download(
                &mut connection,
                &mut reader,
                &thread_id,
                &file["after"],
                &mut request_id,
            );
            assert_eq!(bytes, iteron_record::redact::scrub(after).as_bytes());
            assert!(!String::from_utf8_lossy(&bytes).contains(secret));
        }
    }
    assert_eq!(
        seen,
        expected.keys().map(|path| (*path).to_owned()).collect()
    );
    drop(reader);
    drop(connection);
    restarted.stop();
}

#[cfg(all(target_os = "linux", debug_assertions))]
#[test]
fn actual_helper_lost_response_cannot_publish_a_successful_native_diff() {
    let provider = ToolProvider::spawn_for_calls(
        vec![native_call(
            0,
            "diff-unknown",
            "write_file",
            json!({"path":"unknown.txt","content":"effect really happened\n"}),
        )],
        false,
    );
    let scratch = Scratch::new(&provider.api_root);
    let token = fresh_bearer_token();
    let mut command = core_command_with_launch(
        &scratch,
        &scratch.repo(),
        2,
        &["--mode", "accept_edits", "--confine"],
    );
    command.env("ITERON_HELPER_EXIT_AFTER_EFFECT", "1");
    let mut process = spawn_core_command_with_token_input(command, token.as_bytes());
    let address = wait_for_listening(&mut process);
    let child = OwnedCore(Some(process));
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let thread_id = receive(&mut reader)["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    send(
        &mut connection,
        json!({"type":"submit","protocol_version":PROTOCOL_VERSION,
        "op":{"op":"user_input","text":"Create unknown.txt with the specified full contents."}}),
    );
    let terminal = receive_result_within_timeout(&mut reader);
    assert_ne!(terminal["result"]["outcome"], "done", "{terminal}");
    provider.finish();
    assert_eq!(
        fs::read_to_string(scratch.repo().join("unknown.txt")).unwrap(),
        "effect really happened\n"
    );
    let listing = artifact_list(&mut connection, &mut reader, &thread_id, 701);
    assert!(
        manifests(&listing).is_empty(),
        "lost helper response is no successful commit proof: {listing}"
    );
    assert!(
        !listing["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["schema"] == "iteron.file-snapshot.v1")
    );
    drop(reader);
    drop(connection);
    child.stop();
    let run = thread_id.strip_prefix("session-").unwrap();
    let events = iteron_record::load_forked(&scratch.runs(), &RunId(run.into())).unwrap();
    assert!(events.iter().any(
        |event| matches!(&event.kind, EventKind::EffectUnknown { tool,.. } if tool == "write_file")
    ));
}
