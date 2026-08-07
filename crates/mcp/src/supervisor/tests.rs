// Integration-style lifecycle tests live here so the production supervisor remains compact.

#[cfg(unix)]
mod unix {
    use super::super::*;
    use crate::{
        McpError, McpToolOutcome,
        reconnect::{LifecyclePhase, MAX_RECONNECT_ATTEMPTS},
    };
    use serde_json::json;
    use std::{path::Path, process::Stdio, time::Duration};

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "core-mcp-supervisor-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn process_exists(pid: u32) -> bool {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    async fn wait_for_file(path: &Path) -> bool {
        for _ in 0..200 {
            if path.is_file() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    async fn wait_until_gone(pid: u32) -> bool {
        for _ in 0..200 {
            if !process_exists(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    fn supervisor(
        script: &str,
        fixture_args: impl IntoIterator<Item = String>,
        reconnect: ReconnectPolicy,
        timeouts: McpTimeouts,
    ) -> McpSupervisor {
        let mut args = vec!["-c".into(), script.into(), "mcp-test".into()];
        args.extend(fixture_args);
        let launch = McpLaunchConfig::new("/bin/bash".into(), args, "files".into()).unwrap();
        McpSupervisor::deferred(launch, McpToolFilter::default(), reconnect, timeouts).unwrap()
    }

    fn normal_timeouts() -> McpTimeouts {
        McpTimeouts::new(
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn invalid_search_is_rejected_before_lazy_spawn() {
        let marker = temp_path("must-not-spawn");
        let mut server = supervisor(
            "printf spawned > \"$1\"; exec sleep 60",
            [marker.to_string_lossy().into_owned()],
            ReconnectPolicy::default(),
            normal_timeouts(),
        );
        assert_eq!(server.status().phase, LifecyclePhase::Deferred);
        let error = server
            .search_tools(
                &"x".repeat(MAX_MCP_SEARCH_QUERY_BYTES + 1),
                1,
                &McpCancellation::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::InvalidToolSearch { .. }));
        assert!(!marker.exists());
        assert_eq!(server.status().phase, LifecyclePhase::Deferred);
    }

    #[tokio::test]
    async fn first_valid_search_spawns_once_and_stop_reaps_the_process() {
        let pid_path = temp_path("lazy-pid");
        let script = concat!(
            "echo $$ > \"$1\"; ",
            "IFS= read -r init; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
            "IFS= read -r initialized; IFS= read -r list; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"reader\",\"description\":\"read a file\"},{\"name\":\"read\",\"description\":\"exact reader\"},{\"name\":\"grep\",\"description\":\"search text\"}]}}'; ",
            "exec sleep 60"
        );
        let mut server = supervisor(
            script,
            [pid_path.to_string_lossy().into_owned()],
            ReconnectPolicy::default(),
            normal_timeouts(),
        );
        assert!(!pid_path.exists());
        let result = server
            .search_tools("read", 2, &McpCancellation::new())
            .await
            .unwrap();
        let names: Vec<_> = result
            .matches
            .iter()
            .map(|item| item.name.as_str())
            .collect();
        assert_eq!(names, ["files__read", "files__reader"]);
        assert_eq!(result.total_matches, 2);
        assert!(server.status().catalog_current);
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        server.stop().await;
        assert!(wait_until_gone(pid).await);
        let _ = std::fs::remove_file(pid_path);
    }

    #[tokio::test]
    async fn exit_immediately_after_discovery_reconnects_before_search_returns_ready() {
        let count_path = temp_path("post-list-exit-count");
        let pid_path = temp_path("post-list-exit-pids");
        let script = concat!(
            "count=0; test ! -f \"$1\" || count=$(cat \"$1\"); count=$((count + 1)); ",
            "printf '%s' \"$count\" > \"$1\"; echo $$ >> \"$2\"; ",
            "IFS= read -r init; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
            "IFS= read -r initialized; IFS= read -r list; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"read\"}]}}'; ",
            "if test \"$count\" = 1; then exit 0; fi; exec sleep 60"
        );
        let mut server = supervisor(
            script,
            [
                count_path.to_string_lossy().into_owned(),
                pid_path.to_string_lossy().into_owned(),
            ],
            ReconnectPolicy::new(2, 0, 0).unwrap(),
            normal_timeouts(),
        );
        let result = server
            .search_tools("read", 1, &McpCancellation::new())
            .await
            .unwrap();
        assert_eq!(result.generation.get(), 2);
        let status = server.status();
        assert_eq!(status.phase, LifecyclePhase::Ready);
        assert_eq!(status.generation.unwrap().get(), 2);
        assert!(status.catalog_current);
        assert_eq!(std::fs::read_to_string(&count_path).unwrap(), "2");
        let pids: Vec<u32> = std::fs::read_to_string(&pid_path)
            .unwrap()
            .lines()
            .map(|line| line.parse().unwrap())
            .collect();
        assert_eq!(pids.len(), 2);
        assert!(!process_exists(pids[0]), "first generation was not reaped");
        server.stop().await;
        assert!(wait_until_gone(pids[1]).await);
        let _ = std::fs::remove_file(count_path);
        let _ = std::fs::remove_file(pid_path);
    }

    #[tokio::test]
    async fn known_dead_ready_generation_is_noncurrent_and_effect_reconnects_before_dispatch() {
        let count_path = temp_path("known-dead-count");
        let pid_path = temp_path("known-dead-pids");
        let trigger_path = temp_path("known-dead-trigger");
        let script = concat!(
            "count=0; test ! -f \"$1\" || count=$(cat \"$1\"); count=$((count + 1)); ",
            "printf '%s' \"$count\" > \"$1\"; echo $$ >> \"$2\"; ",
            "IFS= read -r init; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
            "IFS= read -r initialized; IFS= read -r list; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"mutate\"}]}}'; ",
            "if test \"$count\" = 1; then while test ! -f \"$3\"; do sleep 0.01; done; exit 0; fi; ",
            "IFS= read -r call; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"generation-two\"}]}}'; exec sleep 60"
        );
        let mut server = supervisor(
            script,
            [
                count_path.to_string_lossy().into_owned(),
                pid_path.to_string_lossy().into_owned(),
                trigger_path.to_string_lossy().into_owned(),
            ],
            ReconnectPolicy::new(2, 0, 0).unwrap(),
            normal_timeouts(),
        );
        let identity = server
            .search_tools("mutate", 1, &McpCancellation::new())
            .await
            .unwrap()
            .matches
            .remove(0)
            .identity;
        std::fs::write(&trigger_path, b"exit").unwrap();
        let mut observed = None;
        for _ in 0..200 {
            let status = server.status();
            if status.phase != LifecyclePhase::Ready {
                observed = Some(status);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let dead = observed.expect("exited generation remained falsely ready");
        assert_eq!(dead.phase, LifecyclePhase::Backoff);
        assert!(!dead.catalog_current);
        assert_eq!(dead.retained_tools, 1);
        let first_pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            !process_exists(first_pid),
            "known-dead child was not reaped"
        );

        let outcome = server
            .call_tool(&identity, json!({}), &McpCancellation::new())
            .await;
        assert!(matches!(
            outcome,
            McpToolOutcome::Completed { ref content, .. } if content == "generation-two\n"
        ));
        let status = server.status();
        assert_eq!(status.generation.unwrap().get(), 2);
        assert!(status.catalog_current);
        assert_eq!(std::fs::read_to_string(&count_path).unwrap(), "2");
        server.stop().await;
        let _ = std::fs::remove_file(count_path);
        let _ = std::fs::remove_file(pid_path);
        let _ = std::fs::remove_file(trigger_path);
    }

    #[tokio::test(start_paused = true)]
    async fn aggregate_budget_bounds_the_max_retry_policy() {
        let launch = McpLaunchConfig::new(
            "/definitely/not/a/real/mcp-server".into(),
            vec![],
            "files".into(),
        )
        .unwrap();
        let timeouts = McpTimeouts::new(
            Duration::from_secs(3_600),
            Duration::from_secs(3_600),
            Duration::from_secs(3_600),
        )
        .unwrap()
        .with_operation_deadline(Duration::from_secs(2))
        .unwrap();
        let mut server = McpSupervisor::deferred(
            launch,
            McpToolFilter::default(),
            ReconnectPolicy::new(MAX_RECONNECT_ATTEMPTS, 60_000, 3_600_000).unwrap(),
            timeouts,
        )
        .unwrap();
        let started = tokio::time::Instant::now();
        let error = server
            .search_tools("", 1, &McpCancellation::new())
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::Deadline { .. }));
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        let status = server.status();
        assert_eq!(status.generation.unwrap().get(), 1);
        assert_eq!(status.reconnect_attempts, 0);
        assert_eq!(status.phase, LifecyclePhase::Backoff);
    }

    #[tokio::test]
    async fn fresh_supervisor_lineage_cannot_inherit_identity_or_spawn() {
        let marker = temp_path("fresh-lineage-must-not-spawn");
        let first_script = concat!(
            "printf spawned > \"$1\"; ",
            "IFS= read -r init; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
            "IFS= read -r initialized; IFS= read -r list; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"read\"}]}}'; exec sleep 60"
        );
        let mut first = supervisor(
            first_script,
            [marker.to_string_lossy().into_owned()],
            ReconnectPolicy::default(),
            normal_timeouts(),
        );
        let identity = first
            .search_tools("read", 1, &McpCancellation::new())
            .await
            .unwrap()
            .matches
            .remove(0)
            .identity;
        first.stop().await;
        assert!(marker.exists());
        std::fs::remove_file(&marker).unwrap();

        let mut other = supervisor(
            first_script,
            [marker.to_string_lossy().into_owned()],
            ReconnectPolicy::default(),
            normal_timeouts(),
        );
        let outcome = other
            .call_tool(&identity, json!({}), &McpCancellation::new())
            .await;
        assert!(matches!(
            outcome,
            McpToolOutcome::FailedDefinite {
                error: McpError::StaleToolIdentity,
                evidence: None
            }
        ));
        assert!(!marker.exists());
        assert_eq!(other.status().phase, LifecyclePhase::Deferred);
    }

    #[tokio::test]
    async fn malformed_frame_is_terminal_and_its_process_is_reaped() {
        let pid_path = temp_path("invalid-frame-pid");
        let script = concat!(
            "echo $$ > \"$1\"; ",
            "IFS= read -r init; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
            "IFS= read -r initialized; IFS= read -r list; printf '\\377\\n'; exec sleep 60"
        );
        let mut server = supervisor(
            script,
            [pid_path.to_string_lossy().into_owned()],
            ReconnectPolicy::new(3, 0, 0).unwrap(),
            normal_timeouts(),
        );
        let error = server
            .search_tools("", 1, &McpCancellation::new())
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::InvalidUtf8));
        assert_eq!(server.status().phase, LifecyclePhase::Failed);
        assert_eq!(server.status().reconnect_attempts, 0);
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(wait_until_gone(pid).await);
        let _ = std::fs::remove_file(pid_path);
    }

    #[tokio::test]
    async fn cancellation_during_handshake_reaps_before_returning() {
        let pid_path = temp_path("cancel-handshake-pid");
        let script = "echo $$ > \"$1\"; IFS= read -r init; exec sleep 60";
        let mut server = supervisor(
            script,
            [pid_path.to_string_lossy().into_owned()],
            ReconnectPolicy::default(),
            normal_timeouts(),
        );
        let cancellation = McpCancellation::new();
        let trigger = cancellation.clone();
        let observed_path = pid_path.clone();
        let canceller = tokio::spawn(async move {
            assert!(wait_for_file(&observed_path).await);
            trigger.cancel();
        });
        let error = server.search_tools("", 1, &cancellation).await.unwrap_err();
        canceller.await.unwrap();
        assert!(matches!(error, McpError::Cancelled { .. }));
        assert_eq!(server.status().phase, LifecyclePhase::Cancelled);
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(wait_until_gone(pid).await);
        let _ = std::fs::remove_file(pid_path);
    }

    #[tokio::test]
    async fn deadline_failure_retries_with_a_new_generation() {
        let counter = temp_path("retry-counter");
        let script = concat!(
            "n=0; test ! -f \"$1\" || n=$(cat \"$1\"); n=$((n+1)); printf '%s' \"$n\" > \"$1\"; ",
            "IFS= read -r init; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
            "IFS= read -r initialized; IFS= read -r list; ",
            "if test \"$n\" = 1; then exec sleep 60; fi; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"read\"}]}}'; exec sleep 60"
        );
        // Exercise a discovery deadline only after the child has completed its handshake. A
        // 30 ms handshake deadline made process scheduling under a parallel workspace run part
        // of the assertion and could also kill the healthy second generation before it started.
        let timeouts = McpTimeouts::new(
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap();
        let mut server = supervisor(
            script,
            [counter.to_string_lossy().into_owned()],
            ReconnectPolicy::new(2, 0, 0).unwrap(),
            timeouts,
        );
        let result = server
            .search_tools("read", 1, &McpCancellation::new())
            .await
            .unwrap();
        assert_eq!(result.generation.get(), 2);
        assert_eq!(server.status().reconnect_attempts, 1);
        assert_eq!(std::fs::read_to_string(&counter).unwrap(), "2");
        server.stop().await;
        let _ = std::fs::remove_file(counter);
    }

    #[tokio::test]
    async fn retry_budget_bounds_total_spawn_attempts() {
        let counter = temp_path("exhaust-counter");
        let script = concat!(
            "n=0; test ! -f \"$1\" || n=$(cat \"$1\"); n=$((n+1)); printf '%s' \"$n\" > \"$1\"; ",
            "IFS= read -r init; exec sleep 60"
        );
        let timeouts = McpTimeouts::new(
            Duration::from_millis(20),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut server = supervisor(
            script,
            [counter.to_string_lossy().into_owned()],
            ReconnectPolicy::new(2, 0, 0).unwrap(),
            timeouts,
        );
        let error = server
            .search_tools("", 1, &McpCancellation::new())
            .await
            .unwrap_err();
        assert!(matches!(error, McpError::Deadline { .. }));
        assert_eq!(server.status().phase, LifecyclePhase::Exhausted);
        assert_eq!(server.status().reconnect_attempts, 2);
        assert_eq!(std::fs::read_to_string(&counter).unwrap(), "3");
        let _ = std::fs::remove_file(counter);
    }

    #[tokio::test]
    async fn unchanged_tool_identity_survives_reconnect_but_effect_is_not_replayed() {
        let counter = temp_path("identity-counter");
        let script = concat!(
            "n=0; test ! -f \"$1\" || n=$(cat \"$1\"); n=$((n+1)); printf '%s' \"$n\" > \"$1\"; ",
            "IFS= read -r init; printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
            "IFS= read -r initialized; IFS= read -r list; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"mutate\",\"inputSchema\":{\"type\":\"object\"}}]}}'; ",
            "IFS= read -r call; if test \"$n\" = 1; then exit 7; fi; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}'; exec sleep 60"
        );
        let mut server = supervisor(
            script,
            [counter.to_string_lossy().into_owned()],
            ReconnectPolicy::new(2, 0, 0).unwrap(),
            normal_timeouts(),
        );
        let identity = server
            .search_tools("mutate", 1, &McpCancellation::new())
            .await
            .unwrap()
            .matches
            .remove(0)
            .identity;
        assert!(matches!(
            server
                .call_tool(&identity, json!({}), &McpCancellation::new())
                .await,
            McpToolOutcome::Unknown { .. }
        ));
        let second = server
            .call_tool(&identity, json!({}), &McpCancellation::new())
            .await;
        assert!(matches!(
            second,
            McpToolOutcome::Completed { ref content, .. } if content == "ok\n"
        ));
        assert_eq!(std::fs::read_to_string(&counter).unwrap(), "2");
        assert_eq!(server.status().reconnect_attempts, 1);
        server.stop().await;
        let _ = std::fs::remove_file(counter);
    }

    #[tokio::test]
    async fn changed_schema_cannot_inherit_a_pre_reconnect_identity() {
        let counter = temp_path("schema-counter");
        let dispatch_marker = temp_path("schema-dispatch");
        let script = concat!(
            "n=0; test ! -f \"$1\" || n=$(cat \"$1\"); n=$((n+1)); printf '%s' \"$n\" > \"$1\"; ",
            "IFS= read -r init; printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
            "IFS= read -r initialized; IFS= read -r list; ",
            "if test \"$n\" = 1; then schema='{\"type\":\"object\"}'; else schema='{\"type\":\"object\",\"required\":[\"path\"]}'; fi; ",
            "printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"mutate\",\"inputSchema\":%s}]}}\\n' \"$schema\"; ",
            "IFS= read -r call; if test \"$n\" = 1; then exit 7; fi; printf dispatched > \"$2\"; exec sleep 60"
        );
        let mut server = supervisor(
            script,
            [
                counter.to_string_lossy().into_owned(),
                dispatch_marker.to_string_lossy().into_owned(),
            ],
            ReconnectPolicy::new(2, 0, 0).unwrap(),
            normal_timeouts(),
        );
        let identity = server
            .search_tools("mutate", 1, &McpCancellation::new())
            .await
            .unwrap()
            .matches
            .remove(0)
            .identity;
        assert!(matches!(
            server
                .call_tool(&identity, json!({}), &McpCancellation::new())
                .await,
            McpToolOutcome::Unknown { .. }
        ));
        assert!(matches!(
            server
                .call_tool(&identity, json!({}), &McpCancellation::new())
                .await,
            McpToolOutcome::FailedDefinite {
                error: McpError::StaleToolIdentity,
                evidence: None
            }
        ));
        assert!(!dispatch_marker.exists());
        server.stop().await;
        let _ = std::fs::remove_file(counter);
    }

    #[tokio::test]
    async fn cancellation_after_dispatch_is_unknown_and_reaps_connection() {
        let call_seen = temp_path("cancel-call-seen");
        let pid_path = temp_path("cancel-call-pid");
        let script = concat!(
            "echo $$ > \"$2\"; IFS= read -r init; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}'; ",
            "IFS= read -r initialized; IFS= read -r list; ",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"mutate\"}]}}'; ",
            "IFS= read -r call; printf seen > \"$1\"; exec sleep 60"
        );
        let mut server = supervisor(
            script,
            [
                call_seen.to_string_lossy().into_owned(),
                pid_path.to_string_lossy().into_owned(),
            ],
            ReconnectPolicy::default(),
            normal_timeouts(),
        );
        let identity = server
            .search_tools("mutate", 1, &McpCancellation::new())
            .await
            .unwrap()
            .matches
            .remove(0)
            .identity;
        let cancellation = McpCancellation::new();
        let trigger = cancellation.clone();
        let marker = call_seen.clone();
        let canceller = tokio::spawn(async move {
            assert!(wait_for_file(&marker).await);
            trigger.cancel();
        });
        let outcome = server.call_tool(&identity, json!({}), &cancellation).await;
        canceller.await.unwrap();
        assert!(matches!(
            outcome,
            McpToolOutcome::Unknown {
                error: McpError::Cancelled { .. },
                ..
            }
        ));
        assert_eq!(server.status().phase, LifecyclePhase::Cancelled);
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(wait_until_gone(pid).await);
        let _ = std::fs::remove_file(call_seen);
        let _ = std::fs::remove_file(pid_path);
    }
}
