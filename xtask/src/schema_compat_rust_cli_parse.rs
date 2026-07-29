pub(super) use super::cli_parse_scan::{
    balanced_rust_object_end, skip_rust_non_code, skip_rust_trivia,
};
pub(super) use super::cli_parse_tokens::{cli_nested_literal_fields, outer_json_object_shape};
use super::cli_parse_tokens::{compact_rust, json_entry_values, validate_json_value_blocks};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;

pub(super) fn cli_machine_record_shapes(
    source: &[u8],
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let source = std::str::from_utf8(source).context("CLI machine output source is not UTF-8")?;
    let file = parse_cli_output_source(source)?;
    let mut shapes = BTreeMap::new();
    let mut macros = 0usize;
    let mut producers = vec![("stream_event", true), ("final_result", true)];
    if file.items.iter().any(
        |item| matches!(item, syn::Item::Fn(function) if function.sig.ident == "input_attachment_event"),
    ) {
        producers.insert(1, ("input_attachment_event", false));
    }
    for (name, public) in producers {
        let function = unique_value_function(&file, name, public)?;
        if name == "stream_event" {
            validate_stream_event_patterns(function)?;
        }
        let mut objects = Vec::new();
        collect_direct_return_json_objects(function_tail(function)?, &mut objects)?;
        for object in objects {
            let close = balanced_rust_object_end(&object, 0, object.len())?;
            if close + 1 != object.len() {
                bail!("CLI machine producer json! object has trailing tokens");
            }
            let (record_type, fields) = outer_json_object_shape(&object, 0, close, "type")?;
            if shapes.insert(record_type.clone(), fields).is_some() {
                bail!("CLI machine producers repeat literal type '{record_type}'");
            }
            macros = macros.saturating_add(1);
        }
    }
    if macros == 0 || shapes.len() != macros {
        bail!(
            "CLI machine source must contain distinct outer json! producers; found {macros} invocations and {} selectors",
            shapes.len()
        );
    }
    Ok(shapes)
}

pub(super) fn parse_cli_output_source(source: &str) -> Result<syn::File> {
    let file =
        syn::parse_file(source).context("CLI machine output source does not parse as Rust")?;
    if file
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        bail!("CLI machine output source has an active crate/module attribute");
    }
    for item in &file.items {
        match item {
            syn::Item::Macro(_) | syn::Item::ExternCrate(_) => {
                bail!("CLI machine output source contains a top-level macro/extern binding")
            }
            syn::Item::Use(item)
                if item
                    .attrs
                    .iter()
                    .any(|attribute| !attribute.path().is_ident("doc")) =>
            {
                bail!("CLI machine output import has an active or conditional attribute")
            }
            _ => {}
        }
    }
    reject_local_root_shadowing(&file, "serde_json")?;
    require_import(&file, "json", &["serde_json", "json"])?;
    require_import(&file, "Value", &["serde_json", "Value"])?;
    require_import(&file, "Write", &["std", "io", "Write"])?;
    Ok(file)
}

fn reject_local_root_shadowing(file: &syn::File, root: &str) -> Result<()> {
    for item in &file.items {
        match item {
            syn::Item::Mod(module) if module.ident == root => {
                bail!("CLI machine source shadows trusted crate '{root}' with a module");
            }
            syn::Item::ExternCrate(extern_crate)
                if extern_crate.ident == root
                    || extern_crate
                        .rename
                        .as_ref()
                        .is_some_and(|(_, rename)| rename == root) =>
            {
                bail!("CLI machine source has an explicit extern-crate binding for '{root}'");
            }
            syn::Item::Use(import) => {
                let mut bindings = Vec::new();
                flatten_use(&import.tree, &mut Vec::new(), &mut bindings)?;
                if bindings.iter().any(|(binding, origin)| {
                    binding == root
                        && !(origin.len() == 1 && origin.first().is_some_and(|value| value == root))
                }) {
                    bail!("CLI machine source shadows trusted crate '{root}' with an import");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn require_import(file: &syn::File, binding: &str, expected: &[&str]) -> Result<()> {
    let mut bindings = Vec::new();
    for item in &file.items {
        if let syn::Item::Use(item) = item {
            flatten_use(&item.tree, &mut Vec::new(), &mut bindings)?;
        }
    }
    let origins = bindings
        .iter()
        .filter(|(name, _)| name == binding)
        .map(|(_, origin)| origin)
        .collect::<Vec<_>>();
    if origins.len() != 1
        || origins[0].len() != expected.len()
        || origins[0]
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual != expected)
    {
        bail!("CLI machine source does not bind '{binding}' from its exact trusted import");
    }
    Ok(())
}

fn flatten_use(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    bindings: &mut Vec<(String, Vec<String>)>,
) -> Result<()> {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use(&path.tree, prefix, bindings)?;
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut origin = prefix.clone();
            origin.push(name.ident.to_string());
            bindings.push((name.ident.to_string(), origin));
        }
        syn::UseTree::Rename(rename) => {
            let mut origin = prefix.clone();
            origin.push(rename.ident.to_string());
            bindings.push((rename.rename.to_string(), origin));
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                flatten_use(item, prefix, bindings)?;
            }
        }
        syn::UseTree::Glob(_) => bail!("CLI machine source uses an unprovable glob import"),
    }
    Ok(())
}

pub(super) fn unique_value_function<'a>(
    file: &'a syn::File,
    name: &str,
    public: bool,
) -> Result<&'a syn::ItemFn> {
    let mut functions = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    });
    let function = functions
        .next()
        .with_context(|| format!("CLI machine source lacks function '{name}'"))?;
    if functions.next().is_some() {
        bail!("CLI machine source repeats function '{name}'");
    }
    let visibility_matches = matches!(
        (public, &function.vis),
        (true, syn::Visibility::Public(_)) | (false, syn::Visibility::Inherited)
    );
    if !visibility_matches
        || function
            .attrs
            .iter()
            .any(|attribute| !attribute.path().is_ident("doc"))
        || function.sig.constness.is_some()
        || function.sig.asyncness.is_some()
        || function.sig.unsafety.is_some()
        || function.sig.abi.is_some()
        || !function.sig.generics.params.is_empty()
        || function.sig.generics.where_clause.is_some()
    {
        bail!("CLI machine function '{name}' no longer has its direct ordinary function authority");
    }
    let syn::ReturnType::Type(_, output) = &function.sig.output else {
        bail!("CLI machine function '{name}' does not return Value");
    };
    let syn::Type::Path(output) = output.as_ref() else {
        bail!("CLI machine function '{name}' does not return Value");
    };
    if output.qself.is_some()
        || output.path.leading_colon.is_some()
        || output.path.segments.len() != 1
        || output.path.segments[0].ident != "Value"
        || !matches!(output.path.segments[0].arguments, syn::PathArguments::None)
    {
        bail!("CLI machine function '{name}' does not return the trusted imported Value type");
    }
    Ok(function)
}

pub(super) fn function_tail(function: &syn::ItemFn) -> Result<&syn::Expr> {
    if function.block.stmts.len() != 1 {
        bail!(
            "CLI machine function '{}' must consist solely of its direct tail producer",
            function.sig.ident
        );
    }
    block_tail(&function.block).with_context(|| {
        format!(
            "CLI machine function '{}' lacks one tail expression",
            function.sig.ident
        )
    })
}

fn block_tail(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.last() {
        Some(syn::Stmt::Expr(expression, None)) => Some(expression),
        _ => None,
    }
}

pub(super) fn direct_json_macro(expression: &syn::Expr) -> Result<&syn::Macro> {
    let expression = peel_expression(expression);
    let syn::Expr::Macro(expression) = expression else {
        bail!("CLI machine match arm does not directly return one json! object");
    };
    if !expression.attrs.is_empty() {
        bail!("CLI machine json! return has an active attribute");
    }
    validate_json_macro(&expression.mac)?;
    Ok(&expression.mac)
}

pub(super) fn collect_direct_return_json_objects(
    expression: &syn::Expr,
    objects: &mut Vec<Vec<u8>>,
) -> Result<()> {
    match peel_expression(expression) {
        syn::Expr::Macro(_) => {
            objects.push(json_macro_object(direct_json_macro(expression)?)?);
        }
        syn::Expr::Match(expression) => {
            let mut probe = ForbiddenPrelude::default();
            probe.visit_expr(&expression.expr);
            if probe.forbidden {
                bail!("CLI machine match selector contains a macro or control-flow escape");
            }
            if expression.arms.is_empty() {
                bail!("CLI machine producer has an empty match");
            }
            for arm in &expression.arms {
                if !arm.attrs.is_empty() || arm.guard.is_some() {
                    bail!("CLI machine producer match arms cannot carry attributes or guards");
                }
                collect_direct_return_json_objects(&arm.body, objects)?;
            }
        }
        syn::Expr::Block(expression) => {
            if !expression.attrs.is_empty() || expression.label.is_some() {
                bail!("CLI machine producer return block cannot carry attributes or a label");
            }
            let tail = block_tail(&expression.block)
                .context("CLI machine producer return block lacks one tail expression")?;
            let prelude = expression
                .block
                .stmts
                .iter()
                .take(expression.block.stmts.len().saturating_sub(1))
                .collect::<Vec<_>>();
            if !(prelude.is_empty() || prelude.len() == 1 && is_exact_turn_increment(prelude[0])) {
                bail!("CLI machine producer return block has an untrusted prelude");
            }
            for statement in prelude {
                if matches!(statement, syn::Stmt::Item(_) | syn::Stmt::Macro(_)) {
                    bail!("CLI machine producer prelude contains an item or statement macro");
                }
                let mut probe = ForbiddenPrelude::default();
                probe.visit_stmt(statement);
                if probe.forbidden {
                    bail!("CLI machine producer prelude creates JSON or escapes control flow");
                }
            }
            collect_direct_return_json_objects(tail, objects)?;
        }
        _ => bail!("CLI machine producer does not return JSON directly on every branch"),
    }
    Ok(())
}

fn peel_expression(mut expression: &syn::Expr) -> &syn::Expr {
    loop {
        expression = match expression {
            syn::Expr::Group(group) => &group.expr,
            syn::Expr::Paren(paren) => &paren.expr,
            _ => return expression,
        };
    }
}

#[derive(Default)]
struct ForbiddenPrelude {
    forbidden: bool,
}

impl<'ast> Visit<'ast> for ForbiddenPrelude {
    fn visit_macro(&mut self, _node: &'ast syn::Macro) {
        self.forbidden = true;
    }

    fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
        self.forbidden = true;
    }

    fn visit_expr_try(&mut self, _node: &'ast syn::ExprTry) {
        self.forbidden = true;
    }

    fn visit_expr_break(&mut self, _node: &'ast syn::ExprBreak) {
        self.forbidden = true;
    }
}

fn validate_json_macro(mac: &syn::Macro) -> Result<()> {
    if mac.path.leading_colon.is_some()
        || mac.path.segments.len() != 1
        || mac.path.segments[0].ident != "json"
        || !matches!(mac.delimiter, syn::MacroDelimiter::Paren(_))
    {
        bail!("CLI machine producer must directly invoke trusted json!(...)");
    }
    Ok(())
}

pub(super) fn json_macro_object(mac: &syn::Macro) -> Result<Vec<u8>> {
    validate_json_macro(mac)?;
    let rendered = mac.tokens.to_string();
    let bytes = rendered.into_bytes();
    if bytes.first() != Some(&b'{') {
        bail!("CLI machine json! invocation is not one object literal");
    }
    let close = balanced_rust_object_end(&bytes, 0, bytes.len())?;
    if close + 1 != bytes.len() {
        bail!("CLI machine json! object has trailing tokens");
    }
    validate_json_value_blocks(&bytes, 0, close)?;
    Ok(bytes)
}

fn validate_stream_event_patterns(function: &syn::ItemFn) -> Result<()> {
    let syn::Expr::Match(top) = peel_expression(function_tail(function)?) else {
        bail!("CLI stream_event must directly match its UiEvent selector");
    };
    if !expression_path_exact(&top.expr, &["event"]) {
        bail!("CLI stream_event selector must be exactly its event parameter");
    }
    let mut observed = BTreeMap::new();
    for arm in &top.arms {
        let variant = exact_pattern_variant(&arm.pat, "UiEvent")?;
        if variant == "Workflow" {
            let syn::Expr::Match(workflow) = peel_expression(&arm.body) else {
                bail!("CLI Workflow UiEvent must directly match its nested event");
            };
            if !workflow_pattern_binds_event(&arm.pat)
                || !expression_path_exact(&workflow.expr, &["event"])
            {
                bail!("CLI workflow selector is not its exact bound WorkflowUiEvent");
            }
            for nested in &workflow.arms {
                let nested_variant = exact_pattern_variant(&nested.pat, "WorkflowUiEvent")?;
                insert_pattern_record(&mut observed, &nested_variant, &nested.body)?;
            }
        } else {
            insert_pattern_record(&mut observed, &variant, &arm.body)?;
        }
    }
    let expected = BTreeMap::from([
        (
            "AgentActivity".to_owned(),
            "workflow_agent_activity".to_owned(),
        ),
        ("AgentFinished".to_owned(), "workflow_agent_end".to_owned()),
        ("AgentStarted".to_owned(), "workflow_agent_start".to_owned()),
        ("ApprovalRequest".to_owned(), "approval_request".to_owned()),
        ("Done".to_owned(), "run_done".to_owned()),
        ("Notice".to_owned(), "notice".to_owned()),
        ("Phase".to_owned(), "phase".to_owned()),
        ("PhaseChanged".to_owned(), "workflow_phase".to_owned()),
        ("PlanReady".to_owned(), "workflow_plan".to_owned()),
        ("RunFinished".to_owned(), "workflow_end".to_owned()),
        ("RunStarted".to_owned(), "workflow_start".to_owned()),
        ("SteerApplied".to_owned(), "steer_applied".to_owned()),
        ("Text".to_owned(), "assistant_text".to_owned()),
        ("Thinking".to_owned(), "thinking".to_owned()),
        ("ToolEnd".to_owned(), "tool_end".to_owned()),
        ("ToolStart".to_owned(), "tool_start".to_owned()),
        ("TurnEnd".to_owned(), "turn_end".to_owned()),
    ]);
    if observed != expected {
        bail!("CLI UiEvent/WorkflowUiEvent pattern-to-record mapping changed: {observed:?}");
    }
    Ok(())
}

fn insert_pattern_record(
    observed: &mut BTreeMap<String, String>,
    variant: &str,
    body: &syn::Expr,
) -> Result<()> {
    let mut objects = Vec::new();
    collect_direct_return_json_objects(body, &mut objects)?;
    let [object] = objects.as_slice() else {
        bail!("CLI event pattern '{variant}' does not produce exactly one record");
    };
    let close = balanced_rust_object_end(object, 0, object.len())?;
    let (record, _) = outer_json_object_shape(object, 0, close, "type")?;
    if record == "tool_end" {
        let values = json_entry_values(object, 0, close)?;
        let diff = values
            .get("diff")
            .context("CLI tool_end producer lacks its diff value")?;
        if compact_rust(diff) != b"scrub_json(serde_json::to_value(diff).unwrap_or(Value::Null))" {
            bail!("CLI tool_end diff no longer comes from its typed scrubbed FileDiff value");
        }
    }
    if observed.insert(variant.to_owned(), record).is_some() {
        bail!("CLI machine producer repeats event pattern '{variant}'");
    }
    Ok(())
}

fn exact_pattern_variant(pattern: &syn::Pat, root: &str) -> Result<String> {
    let path = match pattern {
        syn::Pat::Path(pattern) => &pattern.path,
        syn::Pat::Struct(pattern) => &pattern.path,
        syn::Pat::TupleStruct(pattern) => &pattern.path,
        _ => bail!("CLI machine producer arm is not one exact enum-variant pattern"),
    };
    if path.leading_colon.is_some() || path.segments.len() != 2 || path.segments[0].ident != root {
        bail!("CLI machine producer pattern is not rooted at {root}");
    }
    Ok(path.segments[1].ident.to_string())
}

fn workflow_pattern_binds_event(pattern: &syn::Pat) -> bool {
    matches!(pattern,
        syn::Pat::TupleStruct(pattern)
            if pattern.elems.len() == 1
                && matches!(&pattern.elems[0], syn::Pat::Ident(binding)
                    if binding.ident == "event"
                        && binding.by_ref.is_none()
                        && binding.mutability.is_none()
                        && binding.subpat.is_none()))
}

fn expression_path_exact(expression: &syn::Expr, expected: &[&str]) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.ident == expected)
}

fn is_exact_turn_increment(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::Assign(assignment), Some(_)) = statement else {
        return false;
    };
    let syn::Expr::Unary(left) = assignment.left.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(right) = assignment.right.as_ref() else {
        return false;
    };
    matches!(left.op, syn::UnOp::Deref(_))
        && expression_path_exact(&left.expr, &["turn"])
        && expression_path_exact(&right.receiver, &["turn"])
        && right.method == "saturating_add"
        && right.args.len() == 1
        && matches!(&right.args[0], syn::Expr::Lit(literal)
            if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_digits() == "1"))
}
