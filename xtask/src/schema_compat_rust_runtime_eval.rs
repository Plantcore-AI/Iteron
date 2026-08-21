use super::{parse, require_function, require_trait_method};
use anyhow::{Context, Result, bail};
use std::path::Path;
use syn::visit::Visit;

pub(super) fn validate(root: &Path) -> Result<()> {
    let contract = parse(root, "crates/eval/src/contract.rs")?;
    validate_contract(&contract)?;
    validate_strict_json(root)?;
    validate_runner(root)
}

fn validate_contract(contract: &syn::File) -> Result<()> {
    reject_root_shadowing(contract)?;
    require_exact_import(
        contract,
        "parse_json_no_duplicates",
        &["crate", "strict_json", "parse_json_no_duplicates"],
    )?;
    require_function(
        contract,
        "admit_type_version",
        r#"fn admit_type_version(kind: &str, actual: u32) -> Result<(), ContractError> {
            if !SUPPORTED_ITERON_CLI_SCHEMA_VERSIONS.contains(&actual) {
                return Err(ContractError::SchemaVersion {
                    actual,
                    expected: ITERON_CLI_SCHEMA_VERSION,
                });
            }
            if !SUPPORTED_ITERON_CLI_TYPE_VERSIONS.contains(&(kind, actual)) {
                return Err(ContractError::TypeVersion {
                    kind: kind.to_owned(),
                    actual,
                });
            }
            Ok(())
        }"#,
    )?;
    require_function(
        contract,
        "parse_machine_record",
        r#"pub fn parse_machine_record(bytes: &[u8]) -> Result<CliMachineRecord, ContractError> {
            let value = parse_json_no_duplicates(bytes)
                .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
            let kind = value
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| ContractError::MalformedJson("missing string field `type`".into()))?;
            if kind == "result" {
                let result: CliFinalResult = serde_json::from_value(value)
                    .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
                admit_type_version("result", result.schema_version)?;
                return Ok(CliMachineRecord::Result(result));
            }
            let event: CliStreamEvent = serde_json::from_value(value)
                .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
            let (schema_version, kind) = event.schema_and_kind();
            admit_type_version(kind.as_str(), schema_version)?;
            Ok(CliMachineRecord::Event {
                schema_version,
                kind,
            })
        }"#,
    )?;
    require_function(
        contract,
        "parse_machine_record_payload",
        r#"fn parse_machine_record_payload(bytes: &[u8]) -> Result<ParsedCliMachineRecord, ContractError> {
            let value = parse_json_no_duplicates(bytes)
                .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
            let kind = value
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| ContractError::MalformedJson("missing string field `type`".into()))?;
            if kind == "result" {
                let result: CliFinalResult = serde_json::from_value(value)
                    .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
                admit_type_version("result", result.schema_version)?;
                return Ok(ParsedCliMachineRecord::Result(result));
            }
            let event: CliStreamEvent = serde_json::from_value(value)
                .map_err(|error| ContractError::MalformedJson(error.to_string()))?;
            let (schema_version, kind) = event.schema_and_kind();
            admit_type_version(kind.as_str(), schema_version)?;
            if let CliStreamEvent::TurnEnd { context, .. } = &event {
                match (schema_version >= 6, context.components.is_some()) {
                    (true, false) => {
                        return Err(ContractError::MalformedJson(
                            "schema v6 turn_end lacks `context.components`".into(),
                        ));
                    }
                    (false, true) => {
                        return Err(ContractError::MalformedJson(
                            "pre-v6 turn_end unexpectedly carries `context.components`".into(),
                        ));
                    }
                    (true, true) | (false, false) => {}
                }
            }
            Ok(ParsedCliMachineRecord::Event(event))
        }"#,
    )?;
    require_function(
        contract,
        "parse_final_result",
        r#"pub fn parse_final_result(
            stdout: &[u8],
            process_exit: i32,
        ) -> Result<CliFinalResult, ContractError> {
            let result = match parse_machine_record(stdout)? {
                CliMachineRecord::Result(result) => result,
                CliMachineRecord::Event { kind, .. } => {
                    return Err(ContractError::WrongType(kind.as_str().into()));
                }
            };
            if result.schema_version >= 5 && result.kernel_tax.is_none() {
                return Err(ContractError::MalformedJson(
                    "schema v5 result lacks `kernel_tax`".into(),
                ));
            }
            if result.exit_code != process_exit {
                return Err(ContractError::ExitMismatch {
                    process: process_exit,
                    result: result.exit_code,
                });
            }
            if result.success != matches!(result.outcome.as_str(), "done" | "drained") {
                return Err(ContractError::OutcomeMismatch);
            }
            // Validate cost truth eagerly; a malformed cost must classify the cell as a harness error.
            let _ = result.cost()?;
            Ok(result)
        }"#,
    )?;
    require_function(
        contract,
        "parse_run_output",
        r#"pub(crate) fn parse_run_output(
            stdout: &[u8],
            process_exit: i32,
        ) -> Result<CliRunOutput, ContractError> {
            let mut result = None;
            let mut usage = None::<CliUsage>;
            let mut optimization = OptimizationAccumulator::default();
            for line in stdout
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            {
                match parse_machine_record_payload(line)? {
                    ParsedCliMachineRecord::Event(event) => {
                        if result.is_some() {
                            return Err(ContractError::EventAfterResult);
                        }
                        if let CliStreamEvent::TurnEnd { usage: sample, .. } = &event {
                            usage = Some(match usage {
                                Some(total) => total
                                    .checked_add(*sample)
                                    .ok_or(ContractError::UsageOverflow)?,
                                None => *sample,
                            });
                        }
                        optimization.observe(&event)?;
                    }
                    ParsedCliMachineRecord::Result(observed) => {
                        if result.replace(observed).is_some() {
                            return Err(ContractError::TerminalResultCardinality);
                        }
                    }
                }
            }
            let result = result.ok_or(ContractError::TerminalResultCardinality)?;
            Ok(CliRunOutput {
                result: validate_final_result(result, process_exit)?,
                usage: usage.map(CliUsage::into_usage),
                optimization: optimization.finish(),
            })
        }"#,
    )?;
    require_function(
        contract,
        "validate_final_result",
        r#"fn validate_final_result(
            result: CliFinalResult,
            process_exit: i32,
        ) -> Result<CliFinalResult, ContractError> {
            if result.schema_version >= 5 && result.kernel_tax.is_none() {
                return Err(ContractError::MalformedJson(
                    "schema v5 result lacks `kernel_tax`".into(),
                ));
            }
            if result.exit_code != process_exit {
                return Err(ContractError::ExitMismatch {
                    process: process_exit,
                    result: result.exit_code,
                });
            }
            if result.success != matches!(result.outcome.as_str(), "done" | "drained") {
                return Err(ContractError::OutcomeMismatch);
            }
            // Validate cost truth eagerly; a malformed cost must classify the cell as a harness error.
            let _ = result.cost()?;
            Ok(result)
        }"#,
    )
}

fn validate_strict_json(root: &Path) -> Result<()> {
    let file = parse(root, "crates/eval/src/strict_json.rs")?;
    validate_strict_file(&file)
}

fn validate_strict_file(file: &syn::File) -> Result<()> {
    reject_root_shadowing(file)?;
    require_function(
        file,
        "parse_json_no_duplicates",
        r#"pub(crate) fn parse_json_no_duplicates(bytes: &[u8]) -> serde_json::Result<Value> {
            let mut deserializer = serde_json::Deserializer::from_slice(bytes);
            let value = MachineValueSeed.deserialize(&mut deserializer)?;
            deserializer.end()?;
            Ok(value)
        }"#,
    )?;
    require_trait_method(
        file,
        "MachineValueVisitor",
        "Visitor",
        "visit_map",
        r#"fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut keys = BTreeSet::new();
            let mut values = serde_json::Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if !keys.insert(key.clone()) {
                    return Err(A::Error::custom(format!(
                        "duplicate JSON object key '{key}'"
                    )));
                }
                values.insert(key, map.next_value_seed(MachineValueSeed)?);
            }
            Ok(Value::Object(values))
        }"#,
    )?;
    require_trait_method(
        file,
        "MachineValueVisitor",
        "Visitor",
        "visit_seq",
        r#"fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element_seed(MachineValueSeed)? {
                values.push(value);
            }
            Ok(Value::Array(values))
        }"#,
    )
}

fn reject_root_shadowing(file: &syn::File) -> Result<()> {
    for item in &file.items {
        match item {
            item if item_defines_type_binding(item, "serde")
                || item_defines_type_binding(item, "serde_json") =>
            {
                bail!("eval schema source shadows serde/serde_json with a local type or module")
            }
            syn::Item::ExternCrate(item)
                if matches!(item.ident.to_string().as_str(), "serde" | "serde_json")
                    || item.rename.as_ref().is_some_and(|(_, rename)| {
                        matches!(rename.to_string().as_str(), "serde" | "serde_json")
                    }) =>
            {
                bail!("eval schema source redirects serde/serde_json with extern crate")
            }
            syn::Item::Use(item) => {
                let mut bindings = Vec::new();
                collect_root_bindings(&item.tree, &mut Vec::new(), &mut bindings)?;
                if bindings.iter().any(|(binding, origin)| {
                    matches!(binding.as_str(), "serde" | "serde_json")
                        && (origin.len() != 1 || origin[0] != *binding)
                }) {
                    bail!("eval schema source redirects serde/serde_json with an import");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn item_defines_type_binding(item: &syn::Item, binding: &str) -> bool {
    match item {
        syn::Item::Enum(item) => item.ident == binding,
        syn::Item::Mod(item) => item.ident == binding,
        syn::Item::Struct(item) => item.ident == binding,
        syn::Item::Trait(item) => item.ident == binding,
        syn::Item::TraitAlias(item) => item.ident == binding,
        syn::Item::Type(item) => item.ident == binding,
        syn::Item::Union(item) => item.ident == binding,
        _ => false,
    }
}

fn collect_root_bindings(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    bindings: &mut Vec<(String, Vec<String>)>,
) -> Result<()> {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_root_bindings(&path.tree, prefix, bindings)?;
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            if name.ident == "self" {
                let binding = prefix
                    .last()
                    .context("eval import has root-level `self`")?
                    .clone();
                bindings.push((binding, prefix.clone()));
            } else {
                let mut origin = prefix.clone();
                origin.push(name.ident.to_string());
                bindings.push((name.ident.to_string(), origin));
            }
        }
        syn::UseTree::Rename(rename) => {
            let mut origin = prefix.clone();
            if rename.ident != "self" {
                origin.push(rename.ident.to_string());
            }
            bindings.push((rename.rename.to_string(), origin));
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_root_bindings(tree, prefix, bindings)?;
            }
        }
        syn::UseTree::Glob(_) => bail!("eval schema source uses a glob import"),
    }
    Ok(())
}

fn validate_runner(root: &Path) -> Result<()> {
    let file = parse(root, "crates/eval/src/runner.rs")?;
    validate_runner_file(&file)
}

fn validate_runner_file(file: &syn::File) -> Result<()> {
    require_exact_import(
        file,
        "parse_run_output",
        &["crate", "contract", "parse_run_output"],
    )?;
    let function = unique_function(file, "run_cell")?;
    if !function.attrs.is_empty() || function.sig.asyncness.is_none() {
        bail!("eval run_cell is conditional or no longer asynchronous");
    }
    let mut probe = RunOutputProbe::default();
    probe.visit_block(&function.block);
    if probe.exact_bindings != 1 || probe.other_bindings != 0 {
        bail!("eval run_cell no longer binds stdout through parse_run_output exactly once");
    }
    Ok(())
}

#[cfg(test)]
#[path = "schema_compat_rust_runtime_eval_tests.rs"]
mod tests;

fn unique_function<'a>(file: &'a syn::File, name: &str) -> Result<&'a syn::ItemFn> {
    let mut functions = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    });
    let function = functions
        .next()
        .with_context(|| format!("eval source lacks function '{name}'"))?;
    if functions.next().is_some() {
        bail!("eval source repeats function '{name}'");
    }
    Ok(function)
}

#[derive(Default)]
struct RunOutputProbe {
    exact_bindings: usize,
    other_bindings: usize,
}

impl<'ast> Visit<'ast> for RunOutputProbe {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "parsed_output") {
            let exact = local.init.as_ref().is_some_and(|initializer| {
                initializer.diverge.is_none()
                    && matches!(initializer.expr.as_ref(), syn::Expr::Match(expression)
                        if is_parse_run_output_call(&expression.expr))
            });
            if exact {
                self.exact_bindings = self.exact_bindings.saturating_add(1);
            } else {
                self.other_bindings = self.other_bindings.saturating_add(1);
            }
        }
        syn::visit::visit_local(self, local);
    }
}

fn is_parse_run_output_call(expression: &syn::Expr) -> bool {
    let syn::Expr::Call(call) = expression else {
        return false;
    };
    call.args.len() == 2
        && expr_path(&call.func, &["parse_run_output"])
        && matches!(&call.args[0], syn::Expr::Reference(reference)
            if reference.mutability.is_none()
                && matches!(reference.expr.as_ref(), syn::Expr::Field(field)
                    if expr_path(&field.base, &["output"])
                        && matches!(&field.member, syn::Member::Named(name) if name == "stdout")))
        && matches!(&call.args[1], syn::Expr::Field(field)
            if expr_path(&field.base, &["output"])
                && matches!(&field.member, syn::Member::Named(name) if name == "exit_code"))
}

fn require_exact_import(file: &syn::File, binding: &str, expected: &[&str]) -> Result<()> {
    let mut origins = Vec::new();
    for item in &file.items {
        let syn::Item::Use(item) = item else {
            continue;
        };
        let before = origins.len();
        flatten_use(&item.tree, &mut Vec::new(), binding, &mut origins)?;
        if origins.len() != before
            && item
                .attrs
                .iter()
                .any(|attribute| !attribute.path().is_ident("doc"))
        {
            bail!("eval trusted import has an active or conditional attribute");
        }
    }
    if origins.len() != 1
        || origins[0].len() != expected.len()
        || origins[0]
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual != expected)
    {
        bail!("eval source redirects trusted import '{binding}'");
    }
    Ok(())
}

fn flatten_use(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    target: &str,
    origins: &mut Vec<Vec<String>>,
) -> Result<()> {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use(&path.tree, prefix, target, origins)?;
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            if name.ident == target {
                let mut origin = prefix.clone();
                origin.push(name.ident.to_string());
                origins.push(origin);
            }
        }
        syn::UseTree::Rename(rename) => {
            if rename.rename == target {
                let mut origin = prefix.clone();
                origin.push(rename.ident.to_string());
                origins.push(origin);
            }
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use(tree, prefix, target, origins)?;
            }
        }
        syn::UseTree::Glob(_) => bail!("eval source uses a glob import"),
    }
    Ok(())
}

fn expr_path(expression: &syn::Expr, expected: &[&str]) -> bool {
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
