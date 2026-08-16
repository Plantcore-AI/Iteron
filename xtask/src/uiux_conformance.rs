use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;
use syn::visit::{self, Visit};

const CONTRACT_PATH: &str = "governance/uiux-slo.json";
const MAX_CONTRACT_BYTES: u64 = 32 * 1024;
const SCHEMA_ID: &str = "iteron-uiux-slo/1";

const REQUIRED_ACTIVITY_KINDS: &[&str] = &[
    "boot",
    "config",
    "agent_discovery",
    "plugin_verification",
    "provider_refresh",
    "first_paint",
    "history_hydrate",
    "session_index",
    "workflow_rehydrate",
    "submission_admission",
    "context_assembly",
    "hook_gate",
    "route_permit",
    "request_serialization",
    "transport_connect",
    "request_sent",
    "waiting_first_byte",
    "waiting_first_token",
    "reasoning",
    "responding",
    "tool_proposed",
    "tool_hook",
    "tool_approval",
    "tool_queued",
    "tool_running",
    "tool_post_processing",
    "retry_backoff",
    "route_failover",
    "compaction",
    "verification",
    "checkpoint",
    "record_commit",
    "stop_hooks",
    "workflow_result_persist",
    "answer_complete",
    "finalizing",
    "input_ready",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema_id: String,
    measurement_required: bool,
    startup: Startup,
    interaction: Interaction,
    stream: Stream,
    cancellation: Cancellation,
    provider: Provider,
    context: ContextPolicy,
    boundedness: Boundedness,
    render: Render,
    picker: Picker,
    shell: Shell,
    storage: Storage,
    required_activity_kinds: Vec<String>,
}

macro_rules! section {
    ($name:ident { $($field:ident),+ $(,)? }) => {
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $name { $( $field: u64, )+ }
    };
}

section!(Startup {
    warm_first_frame_p50_ms,
    warm_first_frame_p95_ms,
    cold_10000_sessions_p95_ms,
    first_paint_to_initial_submission_p95_ms,
    prepaint_network_requests,
});
section!(Interaction {
    key_handler_p95_ms,
    key_handler_p99_ms,
    key_to_paint_p99_ms,
    activity_visible_after_ms,
    activity_elapsed_after_ms,
    activity_remedy_after_ms,
});
section!(Render {
    target_fps,
    maximum_fps,
    frame_coalesce_ms,
    streaming_frame_p99_ms,
    idle_cpu_milli_percent,
    streaming_single_core_milli_percent,
});
section!(Picker {
    shell_p95_ms,
    warm_first_page_p95_ms,
    cold_first_page_p95_ms,
    page_size,
    prefetch_distance,
});
section!(Shell {
    byte_to_paint_p95_ms,
    foreground_yield_ms,
    nonempty_stdin_wait_ms,
    delta_bytes,
    maximum_deltas,
    exit_tail_grace_ms,
    pipe_drain_ms,
});
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stream {
    event_to_paint_p95_ms: u64,
    event_to_paint_p99_ms: u64,
    provider_terminal_to_answer_complete_p95_ms: u64,
    provider_terminal_to_finalizing_p95_ms: u64,
    final_text_exact: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancellation {
    visual_ack_p95_ms: u64,
    cooperative_observed_p95_ms: u64,
    force_terminal_p95_ms: u64,
    force_requires_stronger_authority: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Provider {
    connect_timeout_ms: u64,
    response_header_timeout_ms: u64,
    stream_idle_timeout_ms: u64,
    first_token_slow_after_ms: u64,
    first_token_stall_after_ms: u64,
    interactive_retry_wait_ceiling_ms: u64,
    default_max_in_flight_per_route: u64,
    http2_required: bool,
    accepted_before_token_required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextPolicy {
    core_tools_eager: bool,
    deferred_tools_monotonic: bool,
    skill_listing_bytes: u64,
    cache_usage_must_be_measured: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundedness {
    all_production_event_queues_bounded: bool,
    all_user_visible_output_bounded: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Storage {
    append_p95_ms: u64,
    turn_barrier_p95_ms: u64,
    asynchronous_index_p95_ms: u64,
    input_ready_waits_for_rebuildable_index: bool,
}

pub fn validate(root: &Path) -> Result<()> {
    let path = root.join(CONTRACT_PATH);
    let metadata =
        std::fs::metadata(&path).with_context(|| format!("cannot inspect {CONTRACT_PATH}"))?;
    if !metadata.is_file() || metadata.len() > MAX_CONTRACT_BYTES {
        bail!("{CONTRACT_PATH} must be a regular file no larger than {MAX_CONTRACT_BYTES} bytes");
    }
    let bytes = std::fs::read(&path).with_context(|| format!("cannot read {CONTRACT_PATH}"))?;
    let contract: Contract =
        serde_json::from_slice(&bytes).with_context(|| format!("cannot parse {CONTRACT_PATH}"))?;
    validate_contract(&contract)?;
    validate_source_bindings(root, &contract)?;
    validate_reqwest_http2(root, &contract)?;
    validate_behavior_test_seams(root)
}

fn validate_contract(c: &Contract) -> Result<()> {
    if c.schema_id != SCHEMA_ID || !c.measurement_required {
        bail!("UI/UX contract must use {SCHEMA_ID} and require real measurement");
    }
    exact("startup warm p50", c.startup.warm_first_frame_p50_ms, 150)?;
    exact("startup warm p95", c.startup.warm_first_frame_p95_ms, 300)?;
    exact(
        "startup cold 10k p95",
        c.startup.cold_10000_sessions_p95_ms,
        500,
    )?;
    exact(
        "first paint to initial submission",
        c.startup.first_paint_to_initial_submission_p95_ms,
        100,
    )?;
    exact("prepaint network", c.startup.prepaint_network_requests, 0)?;
    exact("key handler p95", c.interaction.key_handler_p95_ms, 4)?;
    exact("key handler p99", c.interaction.key_handler_p99_ms, 8)?;
    exact("key to paint", c.interaction.key_to_paint_p99_ms, 50)?;
    exact("event paint p95", c.stream.event_to_paint_p95_ms, 50)?;
    exact("event paint p99", c.stream.event_to_paint_p99_ms, 100)?;
    exact(
        "terminal to answer complete",
        c.stream.provider_terminal_to_answer_complete_p95_ms,
        50,
    )?;
    exact(
        "terminal to finalizing",
        c.stream.provider_terminal_to_finalizing_p95_ms,
        100,
    )?;
    if !c.stream.final_text_exact {
        bail!("terminal assistant text must be exact, not best effort");
    }
    exact("cancel visual ack", c.cancellation.visual_ack_p95_ms, 50)?;
    exact(
        "cooperative cancel",
        c.cancellation.cooperative_observed_p95_ms,
        500,
    )?;
    exact("force cancel", c.cancellation.force_terminal_p95_ms, 1_000)?;
    if !c.cancellation.force_requires_stronger_authority {
        bail!("force-cancel wording requires stronger runtime authority");
    }
    if !c.provider.http2_required || !c.provider.accepted_before_token_required {
        bail!("provider transport must require HTTP/2 negotiation and accepted-before-token state");
    }
    exact("skill listing", c.context.skill_listing_bytes, 6_000)?;
    if !c.context.core_tools_eager
        || !c.context.deferred_tools_monotonic
        || !c.context.cache_usage_must_be_measured
    {
        bail!(
            "context contract requires eager core tools, monotonic discovery, and measured cache usage"
        );
    }
    if !c.boundedness.all_production_event_queues_bounded
        || !c.boundedness.all_user_visible_output_bounded
    {
        bail!("production queues and user-visible output must be bounded");
    }
    exact("target fps", c.render.target_fps, 30)?;
    exact("idle CPU", c.render.idle_cpu_milli_percent, 500)?;
    exact(
        "streaming CPU",
        c.render.streaming_single_core_milli_percent,
        5_000,
    )?;
    exact("picker shell", c.picker.shell_p95_ms, 100)?;
    exact("picker warm page", c.picker.warm_first_page_p95_ms, 300)?;
    exact("picker cold page", c.picker.cold_first_page_p95_ms, 800)?;
    exact("shell paint", c.shell.byte_to_paint_p95_ms, 50)?;
    exact("shell yield", c.shell.foreground_yield_ms, 10_000)?;
    exact("stdin wait", c.shell.nonempty_stdin_wait_ms, 250)?;
    exact("exec delta", c.shell.delta_bytes, 8 * 1024)?;
    exact("exec delta count", c.shell.maximum_deltas, 10_000)?;
    exact("exec tail", c.shell.exit_tail_grace_ms, 100)?;
    exact("exec pipe drain", c.shell.pipe_drain_ms, 2_000)?;
    exact("record append", c.storage.append_p95_ms, 10)?;
    exact("turn barrier", c.storage.turn_barrier_p95_ms, 50)?;
    exact("index update", c.storage.asynchronous_index_p95_ms, 500)?;
    if c.storage.input_ready_waits_for_rebuildable_index {
        bail!("input-ready must not wait for a rebuildable index");
    }

    let actual = c
        .required_activity_kinds
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual.len() != c.required_activity_kinds.len() {
        bail!("required_activity_kinds contains a duplicate");
    }
    let expected = REQUIRED_ACTIVITY_KINDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("activity vocabulary differs: expected {expected:?}, found {actual:?}");
    }
    Ok(())
}

/// Values which are both release requirements and shipped behavior must be bound to production
/// source. Keeping this table at exactly sixteen rows makes adapter drift visible: the three
/// provider adapters intentionally occupy three independent header-timeout rows.
fn validate_source_bindings(root: &Path, c: &Contract) -> Result<()> {
    let provider = source(root, "crates/provider/src/lib.rs")?;
    let openai = source(root, "crates/provider/src/openai.rs")?;
    let anthropic = source(root, "crates/provider/src/anthropic.rs")?;
    let responses = source(root, "crates/provider/src/responses.rs")?;
    let governor = source(root, "crates/provider/src/governor_policy.rs")?;
    let effective_provider = source(
        root,
        "crates/cli/src/runtime_tunables/effective_provider.rs",
    )?;
    let tui = source(root, "crates/cli/src/tui.rs")?;
    let driver = source(root, "crates/cli/src/tui/driver_support.rs")?;
    let picker = source(root, "crates/cli/src/tui/session_picker.rs")?;

    let frame_ms = duration_const_ms(&driver, "FRAME_COALESCE")?;
    let maximum_fps = 1_000_u64.div_ceil(frame_ms);
    let activity_visible = function_duration_ms(&tui, "visible_activity")?;
    let status_thresholds = function_duration_values_ms(&tui, "render_status")?;
    let activity_elapsed = only_named_threshold(&status_thresholds, 1_000, "activity elapsed")?;
    let activity_remedy = only_named_threshold(&status_thresholds, 2_000, "activity remedy")?;
    let route_default = helper_integer_default(
        &governor,
        "provider.governor_policy.default_max_in_flight_per_route",
    )?;
    if !effective_provider_uses_governor_default(&effective_provider)? {
        bail!(
            "effective provider in-flight admission must consume GovernorPolicy::default().max_in_flight_per_route"
        );
    }

    let bindings: [(&str, u64, u64); 16] = [
        (
            "provider connect",
            integer_const(&provider, "TRANSPORT_CONNECT_TLS_SECS")? * 1_000,
            c.provider.connect_timeout_ms,
        ),
        (
            "OpenAI response header",
            duration_const_ms(&openai, "RESPONSE_HEADER_TIMEOUT")?,
            c.provider.response_header_timeout_ms,
        ),
        (
            "Anthropic response header",
            duration_const_ms(&anthropic, "RESPONSE_HEADER_TIMEOUT")?,
            c.provider.response_header_timeout_ms,
        ),
        (
            "Responses response header",
            duration_const_ms(&responses, "RESPONSE_HEADER_TIMEOUT")?,
            c.provider.response_header_timeout_ms,
        ),
        (
            "provider stream idle",
            integer_const(&provider, "TRANSPORT_STREAM_IDLE_SECS")? * 1_000,
            c.provider.stream_idle_timeout_ms,
        ),
        (
            "first-token slow",
            duration_const_ms(&tui, "FIRST_TOKEN_SLOW_AFTER")?,
            c.provider.first_token_slow_after_ms,
        ),
        (
            "first-token stall",
            duration_const_ms(&tui, "FIRST_TOKEN_STALL_AFTER")?,
            c.provider.first_token_stall_after_ms,
        ),
        (
            "interactive retry wait",
            duration_const_ms(&provider, "MAX_INTERACTIVE_RETRY_AFTER")?,
            c.provider.interactive_retry_wait_ceiling_ms,
        ),
        (
            "provider default/effective in-flight",
            route_default,
            c.provider.default_max_in_flight_per_route,
        ),
        ("frame coalesce", frame_ms, c.render.frame_coalesce_ms),
        ("maximum fps", maximum_fps, c.render.maximum_fps),
        (
            "picker page size",
            integer_const(&picker, "SESSION_PICKER_PAGE_SIZE")?,
            c.picker.page_size,
        ),
        (
            "picker prefetch distance",
            integer_const(&picker, "SESSION_PICKER_PREFETCH_DISTANCE")?,
            c.picker.prefetch_distance,
        ),
        (
            "activity visible",
            activity_visible,
            c.interaction.activity_visible_after_ms,
        ),
        (
            "activity elapsed",
            activity_elapsed,
            c.interaction.activity_elapsed_after_ms,
        ),
        (
            "activity remedy",
            activity_remedy,
            c.interaction.activity_remedy_after_ms,
        ),
    ];
    for (label, source_value, contract_value) in bindings {
        if source_value != contract_value {
            bail!(
                "UI/UX source binding '{label}' differs: production={source_value}, contract={contract_value}"
            );
        }
    }
    if c.render.streaming_frame_p99_ms > frame_ms {
        bail!(
            "streaming frame p99 {}ms cannot exceed the production {}ms coalesce ceiling",
            c.render.streaming_frame_p99_ms,
            frame_ms
        );
    }
    Ok(())
}

fn effective_provider_uses_governor_default(source: &str) -> Result<bool> {
    let file = syn::parse_file(source).context("cannot parse effective-provider Rust source")?;
    let mut binding = EffectiveProviderBinding(false);
    binding.visit_file(&file);
    Ok(binding.0)
}

struct EffectiveProviderBinding(bool);

impl<'ast> Visit<'ast> for EffectiveProviderBinding {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let syn::Pat::Ident(binding) = &local.pat else {
            visit::visit_local(self, local);
            return;
        };
        if binding.ident != "max_in_flight_per_route" {
            visit::visit_local(self, local);
            return;
        }
        let Some(initializer) = &local.init else {
            return;
        };
        let syn::Expr::Field(field) = initializer.expr.as_ref() else {
            return;
        };
        let syn::Member::Named(member) = &field.member else {
            return;
        };
        let syn::Expr::Call(call) = field.base.as_ref() else {
            return;
        };
        let syn::Expr::Path(function) = call.func.as_ref() else {
            return;
        };
        self.0 = member == "max_in_flight_per_route"
            && function
                .path
                .segments
                .last()
                .is_some_and(|part| part.ident == "default")
            && function
                .path
                .segments
                .iter()
                .any(|part| part.ident == "GovernorPolicy");
    }
}

fn source(root: &Path, relative: &str) -> Result<String> {
    std::fs::read_to_string(root.join(relative)).with_context(|| format!("cannot read {relative}"))
}

fn integer_const(source: &str, name: &str) -> Result<u64> {
    let file = syn::parse_file(source).context("cannot parse bound Rust source")?;
    let mut values = file.items.iter().filter_map(|item| match item {
        syn::Item::Const(item) if item.ident == name && production_attrs(&item.attrs) => {
            plain_integer(&item.expr)
        }
        _ => None,
    });
    let value = values
        .next()
        .with_context(|| format!("production integer constant {name} is missing or non-literal"))?;
    if values.next().is_some() {
        bail!("production integer constant {name} is repeated");
    }
    Ok(value)
}

fn duration_const_ms(source: &str, name: &str) -> Result<u64> {
    let file = syn::parse_file(source).context("cannot parse bound Rust source")?;
    let mut values = file.items.iter().filter_map(|item| match item {
        syn::Item::Const(item) if item.ident == name && production_attrs(&item.attrs) => {
            duration_expr_ms(&item.expr)
        }
        _ => None,
    });
    let value = values.next().with_context(|| {
        format!("production duration constant {name} is missing or non-literal")
    })?;
    if values.next().is_some() {
        bail!("production duration constant {name} is repeated");
    }
    Ok(value)
}

fn production_attrs(attrs: &[syn::Attribute]) -> bool {
    !attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg"))
}

fn plain_integer(expression: &syn::Expr) -> Option<u64> {
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(value),
        ..
    }) = expression
    else {
        return None;
    };
    value.base10_parse().ok()
}

fn duration_expr_ms(expression: &syn::Expr) -> Option<u64> {
    let syn::Expr::Call(call) = expression else {
        return None;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return None;
    };
    let constructor = function.path.segments.last()?.ident.to_string();
    let value = plain_integer(call.args.first()?)?;
    match constructor.as_str() {
        "from_millis" => Some(value),
        "from_secs" => value.checked_mul(1_000),
        _ => None,
    }
}

struct FunctionDurations<'a> {
    function: &'a str,
    depth: usize,
    values: Vec<u64>,
}

impl<'ast> Visit<'ast> for FunctionDurations<'_> {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if item.sig.ident == self.function && production_attrs(&item.attrs) {
            self.depth += 1;
            visit::visit_block(self, &item.block);
            self.depth -= 1;
        }
    }

    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        if self.depth > 0
            && let Some(value) = duration_expr_ms(expression)
        {
            self.values.push(value);
        }
        visit::visit_expr(self, expression);
    }
}

fn function_duration_values_ms(source: &str, function: &str) -> Result<Vec<u64>> {
    let file = syn::parse_file(source).context("cannot parse bound Rust source")?;
    let mut visitor = FunctionDurations {
        function,
        depth: 0,
        values: Vec::new(),
    };
    visitor.visit_file(&file);
    if visitor.values.is_empty() {
        bail!("production function {function} contains no duration threshold");
    }
    Ok(visitor.values)
}

fn function_duration_ms(source: &str, function: &str) -> Result<u64> {
    let values = function_duration_values_ms(source, function)?;
    if values.len() != 1 {
        bail!("production function {function} must contain exactly one duration threshold");
    }
    Ok(values[0])
}

fn only_named_threshold(values: &[u64], expected: u64, label: &str) -> Result<u64> {
    let count = values.iter().filter(|value| **value == expected).count();
    if count != 1 {
        bail!("production {label} threshold must occur exactly once, found {count}");
    }
    Ok(expected)
}

struct HelperDefault<'a> {
    id: &'a str,
    values: Vec<u64>,
}

impl<'ast> Visit<'ast> for HelperDefault<'_> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let syn::Expr::Path(function) = call.func.as_ref() else {
            visit::visit_expr_call(self, call);
            return;
        };
        if function
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "param_integer")
        {
            visit::visit_expr_call(self, call);
            return;
        }
        let mut args = call.args.iter();
        let Some(syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(id),
            ..
        })) = args.next()
        else {
            visit::visit_expr_call(self, call);
            return;
        };
        if id.value() == self.id
            && let Some(value) = args.next().and_then(plain_integer)
        {
            self.values.push(value);
        }
        visit::visit_expr_call(self, call);
    }
}

fn helper_integer_default(source: &str, id: &str) -> Result<u64> {
    let file = syn::parse_file(source).context("cannot parse helper-bound Rust source")?;
    let mut visitor = HelperDefault {
        id,
        values: Vec::new(),
    };
    visitor.visit_file(&file);
    if visitor.values.len() != 1 {
        bail!(
            "runtime helper {id} must have exactly one literal production default, found {}",
            visitor.values.len()
        );
    }
    Ok(visitor.values[0])
}

fn validate_reqwest_http2(root: &Path, c: &Contract) -> Result<()> {
    if !c.provider.http2_required {
        return Ok(());
    }
    let manifest = source(root, "Cargo.toml")?;
    let manifest: toml::Value = toml::from_str(&manifest).context("cannot parse Cargo.toml")?;
    let features = manifest
        .get("workspace")
        .and_then(|value| value.get("dependencies"))
        .and_then(|value| value.get("reqwest"))
        .and_then(|value| value.get("features"))
        .and_then(toml::Value::as_array)
        .context("workspace reqwest dependency must declare a feature array")?;
    if !features
        .iter()
        .any(|feature| feature.as_str() == Some("http2"))
    {
        bail!("provider contract requires Cargo workspace reqwest feature 'http2'");
    }
    Ok(())
}

fn validate_behavior_test_seams(root: &Path) -> Result<()> {
    let required = [
        (
            "crates/cli/src/providers.rs",
            "a_launch_paints_before_any_provider_network_settles",
        ),
        (
            "crates/cli/src/runtime/frontend_tests.rs",
            "same_task_structural_saturation_returns_instead_of_waiting_for_its_consumer",
        ),
        (
            "crates/cli/src/app_server.rs",
            "a_saturated_sq_applies_backpressure_within_a_fixed_bound",
        ),
        (
            "crates/cli/tests/tui_pty.rs",
            "ctrl_c_interrupts_a_running_bash_tool_and_kills_its_descendants",
        ),
        (
            "crates/cli/tests/tui_pty.rs",
            "input_ready_does_not_wait_for_rebuildable_session_index",
        ),
    ];
    for (path, test) in required {
        let source = source(root, path)?;
        let file = syn::parse_file(&source).with_context(|| format!("cannot parse {path}"))?;
        let mut finder = TestFinder {
            name: test,
            found: false,
        };
        finder.visit_file(&file);
        if !finder.found {
            bail!("required UI/UX behavior test {path}::{test} is missing");
        }
    }
    Ok(())
}

struct TestFinder<'a> {
    name: &'a str,
    found: bool,
}

impl<'ast> Visit<'ast> for TestFinder<'_> {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if function.sig.ident == self.name
            && function.attrs.iter().any(|attribute| {
                attribute
                    .path()
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "test")
            })
        {
            self.found = true;
        }
        visit::visit_item_fn(self, function);
    }
}

fn exact(label: &str, actual: u64, expected: u64) -> Result<()> {
    if actual != expected {
        bail!("{label} must be {expected}, found {actual}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_uiux_contract_is_exact() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has repository parent");
        super::validate(root).expect("UI/UX contract must validate");
    }

    #[test]
    fn source_extractors_ignore_comments_and_bind_duration_constructors() {
        let source = r#"
            // const LIMIT: u64 = 999;
            const LIMIT: u64 = 10;
            const WINDOW: Duration = Duration::from_secs(3);
        "#;
        assert_eq!(integer_const(source, "LIMIT").unwrap(), 10);
        assert_eq!(duration_const_ms(source, "WINDOW").unwrap(), 3_000);
        assert!(integer_const("// const LIMIT: u64 = 10;", "LIMIT").is_err());
    }

    #[test]
    fn maximum_fps_uses_ceiling_division_for_the_real_frame_interval() {
        assert_eq!(1_000_u64.div_ceil(16), 63);
    }
}
