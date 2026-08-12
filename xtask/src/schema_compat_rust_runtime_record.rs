use super::parse;
use anyhow::{Context, Result, bail};
use std::path::Path;
use syn::visit::Visit;

pub(super) fn validate(root: &Path) -> Result<()> {
    let file = parse(root, "crates/record/src/lib.rs")?;
    reject_json_shadowing(&file)?;
    validate_append(&file)?;
    validate_replay(&file)?;
    // Every replay path, not just the canonical one. `replay_timed` decodes the same payload for
    // the timeline reader (#104); a second reader that skipped the seq stamp or dropped an event
    // would produce a timeline that disagreed with the transcript for the same rollout, which is
    // precisely the divergence this gate exists to make impossible.
    // Validated only when present. The invariant is "every replay path binds the payload
    // honestly", not "this particular helper exists" -- and a bootstrap fixture built from an
    // older record snapshot legitimately has no `replay_timed` to check.
    if file
        .items
        .iter()
        .any(|item| matches!(item, syn::Item::Fn(function) if function.sig.ident == "replay_timed"))
    {
        validate_replay_named(&file, "replay_timed")?;
    }
    Ok(())
}

fn validate_append(file: &syn::File) -> Result<()> {
    let method = unique_method(file, "Rollout", "append")?;
    if method
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        bail!("Rollout::append cannot be conditional or attributed");
    }
    let mut probe = AppendProbe::default();
    probe.visit_block(&method.block);
    if probe.event_payloads != 1
        || probe.other_payloads != 0
        || probe.chain_payloads != 1
        || probe.other_chain_payloads != 0
    {
        bail!(
            "Rollout::append no longer binds Event -> serde_json::to_value -> ChainLine.payload exactly"
        );
    }
    Ok(())
}

fn validate_replay(file: &syn::File) -> Result<()> {
    validate_replay_named(file, "replay")
}

fn validate_replay_named(file: &syn::File, name: &str) -> Result<()> {
    let function = unique_function(file, name)?;
    if function
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        bail!("record replay cannot be conditional or attributed");
    }
    let mut probe = ReplayProbe::default();
    probe.visit_block(&function.block);
    let direct_decode = probe.chain_payload_decodes == 1
        && probe.hydrated_payload_decodes == 0
        && probe.payload_moves == 0
        && probe.hydrate_calls == 0;
    let gated_decode = probe.chain_payload_decodes == 0
        && probe.hydrated_payload_decodes == 1
        && probe.payload_moves == 1
        && probe.hydrate_calls == 1;
    if !(direct_decode || gated_decode)
        || probe.other_payload_moves != 0
        || probe.other_hydrate_calls != 0
        || probe.other_event_bindings != 0
        || probe.seq_stamps != 1
        || probe.event_pushes != 1
        || probe.other_pushes != 0
    {
        bail!(
            "record {name} no longer binds ChainLine.payload -> optional exact revocation hydration -> Event -> authoritative seq -> output exactly"
        );
    }
    Ok(())
}

fn reject_json_shadowing(file: &syn::File) -> Result<()> {
    for item in &file.items {
        match item {
            item if item_defines_type_binding(item, "serde_json") => {
                bail!("record source shadows canonical serde_json with a local type or module")
            }
            syn::Item::ExternCrate(item)
                if item.ident == "serde_json"
                    || item
                        .rename
                        .as_ref()
                        .is_some_and(|(_, rename)| rename == "serde_json") =>
            {
                bail!("record source redirects canonical serde_json")
            }
            syn::Item::Use(item) => {
                if item
                    .attrs
                    .iter()
                    .any(|attribute| !attribute.path().is_ident("doc"))
                {
                    bail!("record import has an active or conditional attribute");
                }
                if use_binds_serde_json(&item.tree, &mut Vec::new())? {
                    bail!("record source shadows canonical serde_json through an import");
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

fn use_binds_serde_json(tree: &syn::UseTree, prefix: &mut Vec<String>) -> Result<bool> {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            let found = use_binds_serde_json(&path.tree, prefix)?;
            prefix.pop();
            Ok(found)
        }
        syn::UseTree::Name(name) if name.ident == "self" => Ok(prefix
            .last()
            .is_some_and(|binding| binding == "serde_json" && prefix.len() != 1)),
        syn::UseTree::Name(name) => Ok(name.ident == "serde_json" && !prefix.is_empty()),
        syn::UseTree::Rename(rename) => Ok(rename.rename == "serde_json"),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                if use_binds_serde_json(tree, prefix)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        syn::UseTree::Glob(_) => bail!("record source uses a glob import"),
    }
}

fn unique_function<'a>(file: &'a syn::File, name: &str) -> Result<&'a syn::ItemFn> {
    let mut functions = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    });
    let function = functions
        .next()
        .with_context(|| format!("record source lacks function '{name}'"))?;
    if functions.next().is_some() {
        bail!("record source repeats function '{name}'");
    }
    Ok(function)
}

fn unique_method<'a>(file: &'a syn::File, target: &str, name: &str) -> Result<&'a syn::ImplItemFn> {
    let mut methods = Vec::new();
    for item in &file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        if !item.attrs.is_empty() && type_path(&item.self_ty, &[target]) {
            bail!("record impl '{target}' is conditional");
        }
        if item.trait_.is_some() || !type_path(&item.self_ty, &[target]) {
            continue;
        }
        for member in &item.items {
            if let syn::ImplItem::Fn(method) = member
                && method.sig.ident == name
            {
                methods.push(method);
            }
        }
    }
    let [method] = methods.as_slice() else {
        bail!("record source requires exactly one method '{target}::{name}'");
    };
    Ok(method)
}

#[derive(Default)]
struct AppendProbe {
    event_payloads: usize,
    other_payloads: usize,
    chain_payloads: usize,
    other_chain_payloads: usize,
}

impl<'ast> Visit<'ast> for AppendProbe {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "payload") {
            let exact = local.init.as_ref().is_some_and(|initializer| {
                initializer.diverge.is_none()
                    && matches!(initializer.expr.as_ref(), syn::Expr::Try(expression)
                        if matches!(expression.expr.as_ref(), syn::Expr::Call(call)
                            if expr_path(&call.func, &["serde_json", "to_value"])
                                && call.args.len() == 1
                                && expr_path(&call.args[0], &["event"])))
            });
            if exact {
                self.event_payloads = self.event_payloads.saturating_add(1);
            } else {
                self.other_payloads = self.other_payloads.saturating_add(1);
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        if expression.path.is_ident("ChainLine") {
            for field in &expression.fields {
                if matches!(&field.member, syn::Member::Named(name) if name == "payload") {
                    if expr_path(&field.expr, &["payload"]) {
                        self.chain_payloads = self.chain_payloads.saturating_add(1);
                    } else {
                        self.other_chain_payloads = self.other_chain_payloads.saturating_add(1);
                    }
                }
            }
        }
        syn::visit::visit_expr_struct(self, expression);
    }
}

/// `TimedEvent { ts_us, event }` where `event` is exactly the decoded binding, shorthand or not.
fn timed_event_wrapper(expression: &syn::Expr) -> bool {
    let syn::Expr::Struct(literal) = expression else {
        return false;
    };
    if !literal.path.is_ident("TimedEvent") || literal.rest.is_some() || literal.fields.len() != 2 {
        return false;
    }
    literal.fields.iter().any(|field| {
        matches!(&field.member, syn::Member::Named(name) if name == "event")
            && expr_path(&field.expr, &["event"])
    })
}

#[derive(Default)]
struct ReplayProbe {
    chain_payload_decodes: usize,
    hydrated_payload_decodes: usize,
    payload_moves: usize,
    other_payload_moves: usize,
    hydrate_calls: usize,
    other_hydrate_calls: usize,
    other_event_bindings: usize,
    seq_stamps: usize,
    event_pushes: usize,
    other_pushes: usize,
}

impl<'ast> Visit<'ast> for ReplayProbe {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if event_pattern(&local.pat) {
            let source = local.init.as_ref().and_then(|initializer| {
                if initializer.diverge.is_some() {
                    return None;
                }
                let syn::Expr::Try(expression) = initializer.expr.as_ref() else {
                    return None;
                };
                let syn::Expr::Call(call) = expression.expr.as_ref() else {
                    return None;
                };
                if !expr_path(&call.func, &["serde_json", "from_value"]) || call.args.len() != 1 {
                    return None;
                }
                Some(&call.args[0])
            });
            if source.is_some_and(|source| is_field(source, "cl", "payload")) {
                self.chain_payload_decodes = self.chain_payload_decodes.saturating_add(1);
            } else if source.is_some_and(|source| expr_path(source, &["payload"])) {
                self.hydrated_payload_decodes = self.hydrated_payload_decodes.saturating_add(1);
            } else {
                self.other_event_bindings = self.other_event_bindings.saturating_add(1);
            }
        }
        if matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "payload") {
            let exact = matches!(&local.pat, syn::Pat::Ident(binding) if binding.mutability.is_some())
                && local.init.as_ref().is_some_and(|initializer| {
                    initializer.diverge.is_none()
                        && is_field(initializer.expr.as_ref(), "cl", "payload")
                });
            if exact {
                self.payload_moves = self.payload_moves.saturating_add(1);
            } else {
                self.other_payload_moves = self.other_payload_moves.saturating_add(1);
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if expr_path(&call.func, &["content_store", "hydrate_event_payload"]) {
            if exact_hydrate_call(call) {
                self.hydrate_calls = self.hydrate_calls.saturating_add(1);
            } else {
                self.other_hydrate_calls = self.other_hydrate_calls.saturating_add(1);
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
        if is_field(&assignment.left, "event", "seq")
            && matches!(assignment.right.as_ref(), syn::Expr::Call(call)
                if expr_path(&call.func, &["Seq"])
                    && call.args.len() == 1
                    && is_field(&call.args[0], "cl", "seq"))
        {
            self.seq_stamps = self.seq_stamps.saturating_add(1);
        }
        syn::visit::visit_expr_assign(self, assignment);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if expr_path(&call.receiver, &["events"]) && call.method == "push" {
            // Either the decoded event itself, or that same binding wrapped verbatim in a
            // `TimedEvent` beside its chain-line offset (#104). The wrapper is admitted ONLY when
            // the event field is the untouched `event` binding, so a reader still cannot push
            // something it built from anything other than the decoded payload.
            if call.args.len() == 1
                && (expr_path(&call.args[0], &["event"]) || timed_event_wrapper(&call.args[0]))
            {
                self.event_pushes = self.event_pushes.saturating_add(1);
            } else {
                self.other_pushes = self.other_pushes.saturating_add(1);
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn exact_hydrate_call(call: &syn::ExprCall) -> bool {
    call.args.len() == 3
        && expr_path(&call.args[0], &["runs_dir"])
        && tenant_from_chain(&call.args[1])
        && matches!(&call.args[2], syn::Expr::Reference(reference)
            if reference.mutability.is_some() && expr_path(&reference.expr, &["payload"]))
}

fn tenant_from_chain(expression: &syn::Expr) -> bool {
    let syn::Expr::Reference(reference) = expression else {
        return false;
    };
    let syn::Expr::Call(call) = reference.expr.as_ref() else {
        return false;
    };
    if !expr_path(&call.func, &["TenantId"]) || call.args.len() != 1 {
        return false;
    }
    matches!(&call.args[0], syn::Expr::MethodCall(method)
        if method.method == "clone"
            && method.args.is_empty()
            && is_field(&method.receiver, "cl", "tenant"))
}

fn event_pattern(pattern: &syn::Pat) -> bool {
    matches!(pattern, syn::Pat::Type(pattern)
        if type_path(&pattern.ty, &["Event"])
            && matches!(pattern.pat.as_ref(), syn::Pat::Ident(binding)
                if binding.ident == "event" && binding.mutability.is_some()))
}

fn is_field(expression: &syn::Expr, base: &str, member: &str) -> bool {
    matches!(expression, syn::Expr::Field(field)
        if expr_path(&field.base, &[base])
            && matches!(&field.member, syn::Member::Named(name) if name == member))
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

fn type_path(ty: &syn::Type, expected: &[&str]) -> bool {
    let syn::Type::Path(path) = ty else {
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

#[cfg(test)]
#[path = "schema_compat_rust_runtime_record_tests.rs"]
mod tests;
