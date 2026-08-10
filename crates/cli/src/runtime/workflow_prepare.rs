use super::*;

impl Agent {
    /// Resolve, admit and record a `Workflow` tool call — everything up to, but not including,
    /// starting the run.
    ///
    /// This is the half of the old `launch_workflow` that only needs THIS agent: the script
    /// (inline or read under the workspace sandbox), the durable route children re-record
    /// byte-for-byte, the single `extract_meta` parse, a freshly minted run id, the
    /// [`KernelSpawner`] built from this agent's live route + paths, the aggregate budget, the
    /// degraded sink fanned out with any attached frontend sink, and the re-launchable manifest
    /// `core workflow list|resume|watch` reads. Every failure that must abort the tool call before
    /// anything starts happens here, so a returned [`crate::workflow::PreparedWorkflow`] is an
    /// admitted run with its sidecar already on disk.
    ///
    /// What is deliberately NOT here is everything that is only meaningful once a run exists: the
    /// launch banner, the live card, the interrupt bridge and the join. That is what lets the run be
    /// started by something other than this turn — see [`crate::workflow::WorkflowLauncher`].
    pub(super) fn prepare_workflow(
        &self,
        input: &serde_json::Value,
    ) -> Result<crate::workflow::PreparedWorkflow, String> {
        self.prepare_workflow_with_resume(input, None)
    }

    /// Rebuild a persisted workflow under its existing run id and journal namespace.
    ///
    /// The current session's resolved provider, budgets and authority still construct the child
    /// spawner; only the script, ambient args, display name and resume cache come from the durable
    /// sidecars. This is the in-process equivalent of `core workflow resume <run-id>` used by the
    /// interactive workflow panel.
    pub(crate) fn prepare_workflow_resume(
        &self,
        run_id: &str,
    ) -> Result<crate::workflow::PreparedWorkflow, String> {
        if !crate::workflow::valid_run_id(run_id) {
            return Err("Workflow: invalid run id".into());
        }
        let workflows_dir = self.runtime_state_dir.join("subagents").join("workflows");
        let manifest = crate::workflow::load_manifest(&workflows_dir, run_id)
            .ok_or_else(|| format!("Workflow: run `{run_id}` has no readable manifest"))?;
        if manifest.run_id != run_id {
            return Err(format!(
                "Workflow: run `{run_id}` has a mismatched persisted identity"
            ));
        }
        let script = crate::workflow::load_script(&workflows_dir, run_id)
            .ok_or_else(|| format!("Workflow: run `{run_id}` has no persisted script"))?;
        let input = serde_json::json!({
            "script": script,
            "args": manifest.args,
            "background": true,
        });
        self.prepare_workflow_with_resume(&input, Some(run_id))
    }

    pub(super) fn prepare_workflow_with_resume(
        &self,
        input: &serde_json::Value,
        resume_run_id: Option<&str>,
    ) -> Result<crate::workflow::PreparedWorkflow, String> {
        if self.delegation_depth >= MAX_DELEGATION_DEPTH {
            return Err(KernelError::DelegationDepthExceeded.public_summary());
        }
        // Resolve exactly one workflow selector. Named built-ins are harness-owned source, not a
        // magic agent type exposed to arbitrary scripts; resume recognizes the persisted exact
        // source so it reconstructs the same planner adapter and budget schedule.
        let name = input
            .get("name")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let inline = input
            .get("script")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty());
        let path = input
            .get("scriptPath")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty());
        let selector_count = usize::from(name.is_some())
            .saturating_add(usize::from(inline.is_some()))
            .saturating_add(usize::from(path.is_some()));
        if selector_count != 1 {
            return Err(
                "Workflow: provide exactly one of `name`, `script` (inline ESM), or `scriptPath`"
                    .into(),
            );
        }
        let script = match (name, inline, path) {
            (Some(ULTRACODE_WORKFLOW_NAME), None, None) => ULTRACODE_DYNAMIC_SCRIPT.to_string(),
            (Some(other), None, None) => {
                return Err(format!("Workflow: unknown built-in workflow `{other}`"));
            }
            (None, Some(source), None) => source.to_string(),
            (None, None, Some(rel)) => {
                let full = self.workspace.join(rel);
                std::fs::read_to_string(&full)
                    .map_err(|error| format!("Workflow: cannot read scriptPath `{rel}`: {error}"))?
            }
            _ => unreachable!("selector_count enforces one workflow source"),
        };
        let builtin_ultracode = script.trim() == ULTRACODE_DYNAMIC_SCRIPT.trim();
        let mut args = input
            .get("args")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let ultracode_config = if builtin_ultracode {
            let object = args
                .as_object_mut()
                .ok_or_else(|| "Workflow ultracode: `args` must be an object".to_string())?;
            let task = object
                .get("task")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "Workflow ultracode: `args.task` must be non-empty".to_string())?;
            let task = strict_utf8_head(task, MAX_STEER_BYTES);
            let class = object
                .get("taskClass")
                .cloned()
                .ok_or_else(|| "Workflow ultracode: `args.taskClass` is required".to_string())
                .and_then(|value| {
                    serde_json::from_value::<iteron_agents::TaskClass>(value)
                        .map_err(|_| "Workflow ultracode: `args.taskClass` is invalid".to_string())
                })?;
            if !class.fans_out() {
                return Err("Workflow ultracode: localized tasks do not require a fan".into());
            }
            let requested_leaves = object
                .get("maxLeaves")
                .and_then(|value| value.as_u64())
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(iteron_agents::FAN_CAP)
                .clamp(1, iteron_agents::FAN_CAP);
            object.insert("task".into(), serde_json::Value::String(task));
            object.insert(
                "taskClass".into(),
                serde_json::Value::String(workflow_class_label(class).replace('-', "_")),
            );
            object.insert(
                "coverage".into(),
                serde_json::Value::String(ultracode_coverage(class).into()),
            );
            object.insert("maxLeaves".into(), requested_leaves.into());
            Some((class, requested_leaves))
        } else {
            None
        };
        // A REQUEST to outlive the turn, and since 2026-08-06 the DEFAULT one. Only an installed
        // owner can grant it; see `crate::workflow::PreparedWorkflow::background`.
        //
        // The default flipped because the old one made the decoupling unreachable in practice: a
        // run only left the turn when the model remembered to ask, so the common case was still a
        // conversation frozen behind a fan-out. Detaching is the posture; `background: false` is
        // how a model that genuinely needs the result inside this turn asks to wait for it.
        let background = input
            .get("background")
            .and_then(|value| value.as_bool())
            .unwrap_or(true);

        // Children re-record the parent's exact durable route byte-for-byte; a run before any route
        // selection cannot bind one.
        let Some(route) = self
            .selected_route
            .as_ref()
            .map(|selected| selected.route.clone())
        else {
            return Err("Workflow: no model route is selected yet".into());
        };
        // One parse: `extract_meta` spins up a QuickJS runtime, and the live tree wants the
        // DECLARED phases as well as the name so every phase box exists on the first frame.
        let meta = iteron_workflow::extract_meta(&script);
        let declared_phases = meta
            .as_ref()
            .and_then(|meta| meta.phases.clone())
            .unwrap_or_default();
        let workflow_name = meta
            .and_then(|meta| meta.name)
            .unwrap_or_else(|| "workflow".into());
        // Mint a fresh, time-ordered run id the way the standalone `core workflow run` path does.
        // Deriving it from the turn counter made every `Workflow` tool call in ONE assistant
        // response share an id — hence one journal, one child-rollout namespace, and a second call
        // that silently replayed the first's cached outcomes instead of running.
        let run_id = resume_run_id
            .map(str::to_owned)
            .unwrap_or_else(|| iteron_workflow::RunId::generate().to_string());
        let workflows_dir = self.runtime_state_dir.join("subagents").join("workflows");

        let mut cx = self.kernel_spawner_context(&route, &run_id);

        let remaining_turns = self.remaining_inference_turns();
        if remaining_turns == 0 {
            return Err("Workflow: parent turn budget is exhausted".into());
        }
        let engine_limits = if let Some((class, requested_leaves)) = ultracode_config {
            let remaining_wall = self
                .run_time_remaining()
                .map(|remaining| remaining.as_secs().max(1))
                .unwrap_or(self.budget.max_wall_secs);
            // Planning is a real first child, so reserve its one model turn before dividing the
            // investigation half. The first slice is therefore always planner; fan slices begin
            // at ordinal one and their sum stays within the admitted aggregate.
            let Some(allocation) = allocate_orchestration(
                remaining_turns.saturating_sub(1),
                requested_leaves,
                remaining_wall,
            ) else {
                return Err(
                    "Workflow ultracode: writer-first reserve leaves no bounded planner + fan"
                        .into(),
                );
            };
            let fan_tokens = self
                .remaining_provider_tokens()
                .map(|remaining| remaining / 2);
            if fan_tokens == Some(0) {
                return Err(
                    "Workflow ultracode: no provider-token budget remains for the fan".into(),
                );
            }
            let planner = Budget {
                max_turns: 1,
                max_usd: self.effective_max_usd(),
                max_tokens: fan_tokens.map(|tokens| tokens.min(4_096)),
                max_wall_secs: remaining_wall.clamp(1, 60),
                max_consecutive_tool_errors: 1,
            };
            let fan = Budget {
                max_turns: allocation.fan_turns,
                max_usd: self.effective_max_usd(),
                max_tokens: fan_tokens,
                max_wall_secs: allocation.fan_wall_secs,
                max_consecutive_tool_errors: self.budget.max_consecutive_tool_errors,
            };
            let mut slices = vec![planner];
            slices.extend(fan_budget_slices(
                &fan,
                allocation.active_workers,
                self.effective_max_usd(),
            ));
            cx.budget_slices = Some(slices);
            cx.ultracode_planning = Some(workflow_spawner::UltracodePlanning {
                class,
                max_leaves: allocation.active_workers,
            });
            iteron_workflow::RunLimits::new(
                fan_concurrency_permits(allocation.active_workers),
                allocation.active_workers.saturating_add(1),
            )
            .map_err(|error| format!("Workflow: invalid ultracode engine budget: {error}"))?
        } else {
            cx.budget.max_turns = cx.budget.max_turns.min(remaining_turns).max(1);
            // The same soft halving `iteron_agents::subagent_budget` gives a general workflow child.
            cx.budget.max_tokens = self
                .remaining_provider_tokens()
                .map(|remaining| remaining / 2);
            let kernel_limits = in_turn_workflow_budget()
                .map_err(|error| format!("Workflow: invalid kernel aggregate budget: {error}"))?;
            iteron_workflow::RunLimits::new(
                kernel_limits.max_concurrency(),
                kernel_limits.max_agent_calls(),
            )
            .map_err(|error| format!("Workflow: invalid engine aggregate budget: {error}"))?
        };
        let spawner: std::sync::Arc<dyn iteron_workflow::AgentSpawner> =
            std::sync::Arc::new(KernelSpawner::new(cx));

        let mut spec = iteron_workflow::RunSpec::new(script.clone())
            .with_args(args.clone())
            .with_run_id(iteron_workflow::RunId::new(run_id.clone()))
            .with_workflows_dir(workflows_dir.clone())
            .with_limits(engine_limits);
        if resume_run_id.is_some() {
            spec = spec.with_resume_from(iteron_workflow::RunId::new(run_id.clone()));
        }
        // A degraded agent resolves to JS `null` and the script's `.filter(Boolean)` deletes it, so
        // a discarded sink turned an exhausted budget into a plausibly-short result. Keep the
        // reasons and hand them to the model with the value.
        let degraded = std::sync::Arc::new(crate::workflow::DegradedAgentSink::new());
        // ADR-0001 step 1: the same events also drive the operator's live phase→agent tree when a
        // frontend installed the progress seam. Both sinks are needed at once and the engine takes
        // exactly one, so they are fanned out; with no frontend attached this is the degraded sink
        // alone, byte-for-byte the previous behavior.
        let sink = crate::workflow::in_turn_progress_sink(
            degraded.clone(),
            &run_id,
            self.workflow_progress_tx.clone(),
        );

        // Persist the re-launchable inputs BEFORE the run starts, exactly like the standalone path:
        // the kernel writes its journal into the very directory `core workflow list` enumerates, so
        // without the manifest every model-launched run listed forever as unnamed, model-less and
        // `running`.
        if resume_run_id.is_none()
            && let Err(error) = crate::workflow::persist_inputs(
                &workflows_dir,
                &crate::workflow::RunManifest {
                    run_id: run_id.clone(),
                    name: workflow_name.clone(),
                    args,
                    provider_id: route.provider_id.clone(),
                    model: route.model_id.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|elapsed| elapsed.as_secs())
                        .unwrap_or(0),
                },
                &script,
            )
        {
            return Err(format!("Workflow: cannot persist run inputs: {error}"));
        }

        Ok(crate::workflow::PreparedWorkflow {
            run_id,
            name: workflow_name,
            declared_phases,
            workflows_dir,
            spec,
            spawner,
            sink,
            degraded,
            background,
        })
    }

    /// In-turn `Workflow` tool handler (kernel interception, the workflow analogue of
    /// `spawn_subagent`). [`Self::prepare_workflow`] builds the run from THIS agent's live route +
    /// paths and persists its re-launchable sidecars, the installed
    /// [`crate::workflow::WorkflowLauncher`] (by default the kernel's own, which is exactly
    /// [`iteron_workflow::WorkflowEngine::launch`] — background `RunHandle`, review B3) starts it, and
    /// this method `join`s it within the turn so the model receives the aggregated result. The
    /// launch banner (run id) is emitted as a `Notice`.
    ///
    /// # Detached runs
    ///
    /// A run asks to outlive its turn **by default**; `Workflow({background: false})` is how a model
    /// that needs the result inside this call opts out. The request is granted
    /// only when the installed launcher returns [`crate::workflow::Launched::Detached`] — i.e. only
    /// where a session-scoped owner exists to hold it. When it is granted this method returns a
    /// **receipt**, not a result: the run has no value yet, and saying otherwise would report a
    /// completion that has not happened. The owner settles the card, persists the sidecar and keeps
    /// the summary; the session delivers it through a task notification and `/workflows` retains it.
    ///
    /// When it is NOT granted (no owner installed — every `--output-format` path), the run executes
    /// in-turn exactly as before and the tool result says the request was not granted. A run is
    /// never started by nobody.
    pub(super) async fn launch_workflow(
        &mut self,
        turn_id: TurnId,
        input: serde_json::Value,
    ) -> Result<String, String> {
        // `collect` and `cancel` address a run that already exists, so they are answered before
        // anything is prepared: neither reads a script, mints a run id, or writes a manifest.
        if let Some(run_id) = workflow_run_id_arg(&input, "collect") {
            return self.collected_workflow(self.owned_workflow(&run_id, false));
        }
        if let Some(run_id) = workflow_run_id_arg(&input, "cancel") {
            return self.collected_workflow(self.owned_workflow(&run_id, true));
        }
        let prepared = if let Some(run_id) = workflow_run_id_arg(&input, "resumeFromRunId") {
            if input.get("name").is_some()
                || input.get("script").is_some()
                || input.get("scriptPath").is_some()
            {
                return Err(
                    "Workflow: `resumeFromRunId` cannot be combined with name/script/scriptPath"
                        .into(),
                );
            }
            self.prepare_workflow_resume(&run_id)?
        } else {
            self.prepare_workflow(&input)?
        };
        let background_requested = prepared.background;
        // Kept across the launch: the run's identity for the banner, the card and the terminal
        // sidecar, and the degraded sink whose reasons are only readable once the run settles.
        // `prepared` itself is consumed by the launcher, which may keep it.
        let run_id = prepared.run_id.clone();
        let workflow_name = prepared.name.clone();
        let workflows_dir = prepared.workflows_dir.clone();
        let declared_phases = prepared.declared_phases.clone();
        let degraded = prepared.degraded.clone();

        // The launch banner. It names `core workflow list` — the surface that can show this run
        // AFTER the turn, and from another process. A frontend with the progress seam installed
        // also gets the live tree below; one that does not still gets this line, so the run is never
        // invisible.
        self.emit(
            turn_id,
            EventKind::Notice {
                text: format!(
                    "Workflow `{workflow_name}` launched (run {run_id}); `core workflow list` tracks it"
                ),
            },
        );

        // Open the card BEFORE the engine starts, seeded with the script's declared `meta.phases`,
        // so the first frame already shows the shape of the run instead of growing it phase by
        // phase. The run id is the correlation key for every later event.
        self.workflow_progress(crate::workflow::WorkflowRunUiEvent::Started {
            run_id: run_id.clone(),
            name: workflow_name.clone(),
            phases: declared_phases,
        });

        // Start the run. With no launcher installed this is byte-for-byte the previous line,
        // `WorkflowEngine::launch(spec, spawner, sink)`; the handle is shared rather than owned so a
        // launcher that keeps the run can hold the same `RunHandle` this turn is polling.
        let handle =
            match crate::workflow::launch_prepared(self.workflow_launcher.as_ref(), prepared) {
                crate::workflow::Launched::InTurn(handle) => handle,
                // The owner took it. Everything below this point — the join, the interrupt bridge, the
                // `Finished` card event, `persist_result` and the aggregated summary — is now the
                // owner's obligation, because the owner is the only thing still holding the run. Doing
                // any of it here would race it.
                crate::workflow::Launched::Detached(run) => {
                    return Ok(detached_workflow_receipt(&run));
                }
            };
        // Bridge the parent's stop surfaces onto the run's cancellation token. Without this a
        // multi-minute run ignored Ctrl-C entirely: the operator interrupt reached the parent but
        // never the engine, and `join()` simply blocked the turn until the script finished.
        // Polling is fixed and bounded, exactly like `run_child_with_control`.
        const WORKFLOW_CONTROL_POLL: Duration = Duration::from_millis(25);
        let report = {
            let mut joined = Box::pin(handle.join());
            loop {
                match tokio::time::timeout(WORKFLOW_CONTROL_POLL, &mut joined).await {
                    Ok(report) => break report,
                    Err(_) => {
                        // Drain both stop surfaces through the canonical predicate rather than
                        // reading the out-of-band atomic directly: a queued SQ `Op::Interrupt` on
                        // an embedder that installed no atomic sets only `interrupt_requested`, and
                        // an atomic-only check would leave exactly that operator unable to stop the
                        // run. Drain is deliberately NOT a cancel — like an admitted child, an
                        // admitted run exits at its own safe point.
                        let _ = self.collect_inbound_ops(TurnId(self.seq_turn));
                        if self.requested_control().interrupts() {
                            handle.cancel();
                        }
                    }
                }
            }
        };

        // A run that never produced a report is still a directory `core workflow list` enumerates:
        // `persist_inputs` above already created it. Settling it is the same obligation I-35 names,
        // on the error path — and the journal's new exclusive lock makes that path reachable (a
        // colliding run id is refused here, not silently interleaved). Without this the failure
        // would sit in `/workflows` as `running` forever.
        let report = match report {
            Ok(report) => report,
            Err(error) => {
                let message = format!("Workflow run failed: {error}");
                let failed = crate::workflow::unreported_run(&run_id, &message);
                let _ = crate::workflow::persist_result(&workflows_dir, &run_id, &failed);
                self.workflow_progress(crate::workflow::WorkflowRunUiEvent::Finished {
                    run_id: run_id.clone(),
                    terminal: crate::workflow::WorkflowRunTerminal::Failed,
                });
                return Err(message);
            }
        };

        // `ingest` alone never marks a card finished. Publish exactly one terminal after the
        // authoritative report exists, so lifecycle observers do not infer success merely because
        // the engine future resolved.
        self.workflow_progress(crate::workflow::WorkflowRunUiEvent::Finished {
            run_id: run_id.clone(),
            terminal: if report.stopped {
                crate::workflow::WorkflowRunTerminal::Cancelled
            } else {
                crate::workflow::WorkflowRunTerminal::Completed
            },
        });

        // Record the terminal outcome so the run lists with its name, model and terminal state.
        // This is list metadata, not the result: a sidecar that cannot be written must not destroy
        // a run the operator already paid for, so it degrades to a notice.
        if let Err(error) = crate::workflow::persist_result(&workflows_dir, &run_id, &report) {
            self.emit(
                turn_id,
                EventKind::Notice {
                    text: format!("Workflow: cannot persist run result for {run_id}: {error}"),
                },
            );
        }

        // One rendering, shared with the detached path's `collect`, so an in-turn result and a
        // collected background result cannot drift into two different descriptions of one run.
        let summary = crate::workflow::run_result_summary(
            &workflow_name,
            &run_id,
            &report,
            &degraded.reasons(),
        );
        if background_requested {
            // The model asked for a run it could leave; it got one it had to wait for. Saying so is
            // the difference between "this took a while" and a silently broken assumption about
            // what the rest of the turn was free to do.
            return Ok(format!(
                "NOTE: `background` was requested but this session has no workflow run owner \
                 installed, so the run executed inside the turn and the result below is complete.\n\n{summary}"
            ));
        }
        Ok(summary)
    }
}
