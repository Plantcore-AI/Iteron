use super::super::manifest::read_bounded;
use super::MAX_SOURCE_BYTES;
use super::cli_parse::parse_cli_output_source;
use super::cli_writer_ast::*;
use anyhow::{Context, Result, bail};
use std::path::Path;
use syn::visit::Visit;

pub(super) fn validate_cli_writer_dataflow(root: &Path, source: &[u8]) -> Result<()> {
    let source = std::str::from_utf8(source).context("CLI output source is not UTF-8")?;
    let file = parse_cli_output_source(source)?;
    super::cli_exact::validate(&file)?;
    validate_json_line_writer(&file)?;
    validate_stream_writer(&file)?;
    validate_result_writer(&file)?;

    let main = read_bounded(root, "crates/cli/src/main.rs", MAX_SOURCE_BYTES)?;
    let main = std::str::from_utf8(&main).context("CLI main source is not UTF-8")?;
    super::cli_main::validate(main)?;
    validate_final_result_call(main)
}

fn validate_json_line_writer(file: &syn::File) -> Result<()> {
    let function = root_function(file, "write_json_line")?;
    if !matches!(function.vis, syn::Visibility::Inherited)
        || !function.attrs.is_empty()
        || function.block.stmts.len() != 3
        || !has_exact_writer_signature(&function.sig)
        || !has_shared_value_parameter(&function.sig, "value")
    {
        bail!("CLI JSON line writer no longer has its exact immutable Value boundary");
    }
    let first = try_expression(&function.block.stmts[0])?;
    let syn::Expr::Call(call) = first else {
        bail!("CLI JSON line writer does not call serde_json::to_writer directly");
    };
    if !expression_path_is(&call.func, &["serde_json", "to_writer"])
        || call.args.len() != 2
        || !is_reference_to(&call.args[0], "writer", true)
        || !expression_path_is(&call.args[1], &["value"])
    {
        bail!("CLI JSON line writer transforms the producer Value before serialization");
    }

    let second = try_expression(&function.block.stmts[1])?;
    let syn::Expr::MethodCall(write) = second else {
        bail!("CLI JSON line writer lacks its exact newline write");
    };
    if write.method != "write_all"
        || !expression_path_is(&write.receiver, &["writer"])
        || write.args.len() != 1
        || !matches!(&write.args[0], syn::Expr::Lit(literal) if matches!(&literal.lit, syn::Lit::ByteStr(bytes) if bytes.value() == b"\n"))
    {
        bail!("CLI JSON line writer does not append exactly one newline");
    }
    let tail = statement_expression(&function.block.stmts[2], false)?;
    let syn::Expr::MethodCall(flush) = tail else {
        bail!("CLI JSON line writer lacks its exact flush tail");
    };
    if flush.method != "flush"
        || !expression_path_is(&flush.receiver, &["writer"])
        || !flush.args.is_empty()
    {
        bail!("CLI JSON line writer has an unexpected tail operation");
    }
    Ok(())
}

fn validate_stream_writer(file: &syn::File) -> Result<()> {
    let method = emitter_method(file, "write_stream_event")?;
    if !matches!(method.vis, syn::Visibility::Inherited)
        || !method.attrs.is_empty()
        || method.block.stmts.len() != 2
    {
        bail!("CLI stream writer no longer has its exact two-step producer-to-writer flow");
    }
    let syn::Stmt::Local(local) = &method.block.stmts[0] else {
        bail!("CLI stream writer does not bind the producer Value directly");
    };
    let syn::Pat::Ident(binding) = &local.pat else {
        bail!("CLI stream writer uses an unsupported Value binding");
    };
    let Some(initializer) = &local.init else {
        bail!("CLI stream writer Value binding lacks an initializer");
    };
    let syn::Expr::Call(call) = initializer.expr.as_ref() else {
        bail!("CLI stream writer does not invoke stream_event directly");
    };
    if binding.ident != "value"
        || binding.mutability.is_some()
        || binding.by_ref.is_some()
        || binding.subpat.is_some()
        || initializer.diverge.is_some()
        || !expression_path_is(&call.func, &["stream_event"])
        || call.args.len() != 2
        || !expression_path_is(&call.args[0], &["event"])
        || !is_mutable_self_field_reference(&call.args[1], "stream_turn")
    {
        bail!("CLI stream writer can transform or substitute the stream_event Value");
    }
    validate_write_json_line_call(
        statement_expression(&method.block.stmts[1], false)?,
        "value",
        true,
    )
    .context("CLI stream writer sink changed")
}

fn validate_result_writer(file: &syn::File) -> Result<()> {
    let method = emitter_method(file, "result")?;
    if !matches!(method.vis, syn::Visibility::Public(_))
        || !method.attrs.is_empty()
        || method.block.stmts.len() != 3
        || !has_shared_value_parameter(&method.sig, "value")
    {
        bail!("CLI final writer no longer accepts one immutable producer Value");
    }
    validate_result_prelude(statement_expression(&method.block.stmts[0], false)?)?;
    let machine = statement_expression(&method.block.stmts[1], false)?;
    let syn::Expr::If(machine) = machine else {
        bail!("CLI final writer lacks its exact machine-format branch");
    };
    if machine.else_branch.is_some() || !is_machine_condition(&machine.cond) {
        bail!("CLI final writer machine-format condition changed");
    }
    if machine.then_branch.stmts.len() != 1 {
        bail!("CLI final writer machine branch is not one direct write");
    }
    validate_write_json_line_call(
        try_expression(&machine.then_branch.stmts[0])?,
        "value",
        false,
    )
    .context("CLI final writer sink changed")?;
    if !is_ok_unit(statement_expression(&method.block.stmts[2], false)?) {
        bail!("CLI final writer has an unexpected tail");
    }
    Ok(())
}

fn validate_result_prelude(expression: &syn::Expr) -> Result<()> {
    let syn::Expr::Match(expression) = expression else {
        bail!("CLI final writer prelude is not its exact format match");
    };
    if !is_self_field(&expression.expr, "format") || expression.arms.len() != 3 {
        bail!("CLI final writer format match changed");
    }
    let mut seen = std::collections::BTreeSet::new();
    for arm in &expression.arms {
        if !arm.attrs.is_empty() || arm.guard.is_some() {
            bail!("CLI final writer format arm has an attribute or guard");
        }
        let variant = pattern_variant(&arm.pat, "OutputFormat")?;
        if !seen.insert(variant.clone()) {
            bail!("CLI final writer repeats a format arm");
        }
        let syn::Expr::Block(body) = arm.body.as_ref() else {
            bail!("CLI final writer format arm is not a block");
        };
        match variant.as_str() {
            "Text" => validate_single_flush(&body.block, "flush_text_output", true)?,
            "StreamJson" => validate_single_flush(&body.block, "flush_stream_text", false)?,
            "Json" if body.block.stmts.is_empty() => {}
            _ => bail!("CLI final writer has an unknown or transformed format arm"),
        }
    }
    if seen
        != std::collections::BTreeSet::from([
            "Json".to_owned(),
            "StreamJson".to_owned(),
            "Text".to_owned(),
        ])
    {
        bail!("CLI final writer format arms are incomplete");
    }
    Ok(())
}

fn validate_single_flush(block: &syn::Block, method: &str, boolean: bool) -> Result<()> {
    if block.stmts.len() != 1 {
        bail!("CLI final writer '{method}' arm has extra operations");
    }
    let expression = try_expression(&block.stmts[0])?;
    let syn::Expr::MethodCall(call) = expression else {
        bail!("CLI final writer '{method}' arm is not one method call");
    };
    let args_match = if boolean {
        call.args.len() == 1
            && matches!(&call.args[0], syn::Expr::Lit(literal) if matches!(&literal.lit, syn::Lit::Bool(value) if value.value))
    } else {
        call.args.is_empty()
    };
    if call.method != method || !expression_path_is(&call.receiver, &["self"]) || !args_match {
        bail!("CLI final writer '{method}' arm changed");
    }
    Ok(())
}

fn validate_final_result_call(source: &str) -> Result<()> {
    let file = syn::parse_file(source).context("CLI main source does not parse as Rust")?;
    let function = root_function(&file, "run_cli")?;
    let mut binding_index = None;
    for (index, statement) in function.block.stmts.iter().enumerate() {
        let syn::Stmt::Local(local) = statement else {
            continue;
        };
        let syn::Pat::Ident(binding) = &local.pat else {
            continue;
        };
        let Some(initializer) = &local.init else {
            continue;
        };
        let syn::Expr::Call(call) = initializer.expr.as_ref() else {
            continue;
        };
        if expression_path_is(&call.func, &["output", "final_result"])
            && (binding_index.replace(index).is_some()
                || binding.ident != "result"
                || binding.mutability.is_some()
                || binding.by_ref.is_some()
                || binding.subpat.is_some()
                || initializer.diverge.is_some())
        {
            bail!("CLI main final_result binding is mutable or ambiguous");
        }
    }
    let index = binding_index.context("CLI main lacks one direct final_result binding")?;
    let emitter_index = function
        .block
        .stmts
        .iter()
        .position(is_emitter_binding)
        .context("CLI main lacks its one-shot Emitter binding")?;
    if emitter_index >= index {
        bail!("CLI main constructs its Emitter after the final result");
    }
    let mut bypass = StdoutBypassProbe::default();
    for statement in function
        .block
        .stmts
        .iter()
        .skip(emitter_index + 1)
        .take(index.saturating_sub(emitter_index))
    {
        bypass.visit_stmt(statement);
    }
    if bypass.found {
        bail!("CLI one-shot machine path contains a direct stdout bypass around Emitter");
    }
    let sink = function
        .block
        .stmts
        .get(index + 1)
        .context("CLI main does not immediately forward final_result")?;
    validate_final_sink_statement(sink)?;
    let mut later = ResultPathProbe::default();
    for statement in function.block.stmts.iter().skip(index + 2) {
        later.visit_stmt(statement);
    }
    if later.result_paths != 0 {
        bail!("CLI main reuses final_result after its direct sink");
    }
    Ok(())
}

fn is_emitter_binding(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Local(local) = statement else {
        return false;
    };
    let syn::Pat::Ident(binding) = &local.pat else {
        return false;
    };
    let Some(initializer) = &local.init else {
        return false;
    };
    let syn::Expr::Call(call) = initializer.expr.as_ref() else {
        return false;
    };
    binding.ident == "emitter"
        && binding.mutability.is_some()
        && expression_path_is(&call.func, &["Emitter", "new"])
}

#[derive(Default)]
struct StdoutBypassProbe {
    found: bool,
}

impl<'ast> Visit<'ast> for StdoutBypassProbe {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "print" | "println" | "write" | "writeln"
            )
        }) {
            self.found = true;
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if expression_path_is(&node.func, &["stdout"])
            || expression_path_is(&node.func, &["std", "io", "stdout"])
        {
            self.found = true;
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn validate_final_sink_statement(statement: &syn::Stmt) -> Result<()> {
    let expression = statement_expression(statement, false)?;
    let syn::Expr::If(expression) = expression else {
        bail!("CLI main final_result sink is not its exact error-tracking branch");
    };
    if expression.else_branch.is_some() || expression.then_branch.stmts.len() != 1 {
        bail!("CLI main final_result sink has an extra branch or operation");
    }
    let syn::Expr::Binary(condition) = expression.cond.as_ref() else {
        bail!("CLI main final_result sink condition changed");
    };
    if !matches!(condition.op, syn::BinOp::And(_))
        || !is_no_output_error(&condition.left)
        || !is_emitter_result_let(&condition.right)
    {
        bail!("CLI main final_result sink no longer forwards directly to Emitter");
    }
    let assignment = statement_expression(&expression.then_branch.stmts[0], true)?;
    let syn::Expr::Assign(assignment) = assignment else {
        bail!("CLI main final_result sink error assignment changed");
    };
    let syn::Expr::Call(some) = assignment.right.as_ref() else {
        bail!("CLI main final_result sink does not retain the write error");
    };
    if !expression_path_is(&assignment.left, &["output_error"])
        || !expression_path_is(&some.func, &["Some"])
        || some.args.len() != 1
        || !expression_path_is(&some.args[0], &["error"])
    {
        bail!("CLI main final_result sink has an unexpected side effect");
    }
    Ok(())
}

fn is_no_output_error(expression: &syn::Expr) -> bool {
    matches!(expression, syn::Expr::MethodCall(call) if call.method == "is_none" && call.args.is_empty() && expression_path_is(&call.receiver, &["output_error"]))
}

fn is_emitter_result_let(expression: &syn::Expr) -> bool {
    let syn::Expr::Let(expression) = expression else {
        return false;
    };
    let syn::Pat::TupleStruct(pattern) = expression.pat.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(call) = expression.expr.as_ref() else {
        return false;
    };
    pattern.path.is_ident("Err")
        && pattern.elems.len() == 1
        && matches!(&pattern.elems[0], syn::Pat::Ident(binding) if binding.ident == "error" && binding.mutability.is_none() && binding.by_ref.is_none() && binding.subpat.is_none())
        && call.method == "result"
        && expression_path_is(&call.receiver, &["emitter"])
        && call.args.len() == 1
        && is_reference_to(&call.args[0], "result", false)
}

#[derive(Default)]
struct ResultPathProbe {
    result_paths: usize,
}

impl<'ast> Visit<'ast> for ResultPathProbe {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.path.is_ident("result") {
            self.result_paths = self.result_paths.saturating_add(1);
        }
        syn::visit::visit_expr_path(self, node);
    }
}
