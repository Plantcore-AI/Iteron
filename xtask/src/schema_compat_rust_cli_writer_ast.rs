use anyhow::{Context, Result, bail};

pub(super) fn root_function<'a>(file: &'a syn::File, name: &str) -> Result<&'a syn::ItemFn> {
    let mut matches = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    });
    let function = matches
        .next()
        .with_context(|| format!("CLI source lacks function '{name}'"))?;
    if matches.next().is_some() {
        bail!("CLI source repeats function '{name}'");
    }
    Ok(function)
}

pub(super) fn emitter_method<'a>(file: &'a syn::File, name: &str) -> Result<&'a syn::ImplItemFn> {
    let mut matches = Vec::new();
    for item in &file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        let self_is_emitter =
            type_path_last_ident(&item.self_ty).is_some_and(|ident| ident == "Emitter");
        if self_is_emitter
            && (!item.attrs.is_empty()
                || item.defaultness.is_some()
                || item.unsafety.is_some()
                || !item.generics.params.is_empty()
                || item.generics.where_clause.is_some())
        {
            bail!("CLI Emitter impl has conditional or non-ordinary authority");
        }
        if item.trait_.is_some() || !type_path_is(&item.self_ty, &["Emitter"]) {
            continue;
        }
        for member in &item.items {
            if let syn::ImplItem::Fn(method) = member
                && method.sig.ident == name
            {
                matches.push(method);
            }
        }
    }
    let [method] = matches.as_slice() else {
        bail!("CLI Emitter must contain one method '{name}'");
    };
    Ok(method)
}

pub(super) fn type_path_last_ident(ty: &syn::Type) -> Option<&syn::Ident> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path.segments.last().map(|segment| &segment.ident)
}

pub(super) fn statement_expression(statement: &syn::Stmt, semicolon: bool) -> Result<&syn::Expr> {
    match statement {
        syn::Stmt::Expr(expression, punctuation) if punctuation.is_some() == semicolon => {
            Ok(expression)
        }
        _ => bail!("CLI writer statement has an unexpected form"),
    }
}

pub(super) fn try_expression(statement: &syn::Stmt) -> Result<&syn::Expr> {
    let expression = statement_expression(statement, true)?;
    let syn::Expr::Try(expression) = expression else {
        bail!("CLI writer fallible operation no longer propagates errors directly");
    };
    Ok(&expression.expr)
}

pub(super) fn validate_write_json_line_call(
    expression: &syn::Expr,
    value: &str,
    reference: bool,
) -> Result<()> {
    let syn::Expr::Call(call) = expression else {
        bail!("CLI writer does not invoke write_json_line directly");
    };
    if call.args.len() != 2 {
        bail!("CLI writer invokes write_json_line with the wrong arity");
    }
    let value_matches = if reference {
        is_reference_to(&call.args[1], value, false)
    } else {
        expression_path_is(&call.args[1], &[value])
    };
    if !expression_path_is(&call.func, &["write_json_line"])
        || !is_stdout_lock(&call.args[0])
        || !value_matches
    {
        bail!("CLI writer transforms or redirects the producer Value");
    }
    Ok(())
}

pub(super) fn has_shared_value_parameter(signature: &syn::Signature, name: &str) -> bool {
    signature.inputs.iter().any(|argument| {
        let syn::FnArg::Typed(argument) = argument else {
            return false;
        };
        let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
            return false;
        };
        let syn::Type::Reference(reference) = argument.ty.as_ref() else {
            return false;
        };
        binding.ident == name
            && binding.mutability.is_none()
            && binding.by_ref.is_none()
            && reference.mutability.is_none()
            && type_path_is(&reference.elem, &["Value"])
    })
}

pub(super) fn has_exact_writer_signature(signature: &syn::Signature) -> bool {
    if signature.inputs.len() != 2
        || signature.constness.is_some()
        || signature.asyncness.is_some()
        || signature.unsafety.is_some()
        || signature.abi.is_some()
        || signature.variadic.is_some()
        || !signature.generics.params.is_empty()
        || signature.generics.where_clause.is_some()
    {
        return false;
    }
    let Some(syn::FnArg::Typed(argument)) = signature.inputs.first() else {
        return false;
    };
    let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
        return false;
    };
    let syn::Type::ImplTrait(writer) = argument.ty.as_ref() else {
        return false;
    };
    let mut bounds = writer.bounds.iter();
    let exact_bound = matches!(bounds.next(), Some(syn::TypeParamBound::Trait(bound))
        if bound.lifetimes.is_none()
            && matches!(bound.modifier, syn::TraitBoundModifier::None)
            && bound.path.leading_colon.is_none()
            && bound.path.is_ident("Write"));
    binding.ident == "writer"
        && binding.mutability.is_some()
        && binding.by_ref.is_none()
        && binding.subpat.is_none()
        && exact_bound
        && bounds.next().is_none()
}

pub(super) fn expression_path_is(expression: &syn::Expr, expected: &[&str]) -> bool {
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

pub(super) fn type_path_is(ty: &syn::Type, expected: &[&str]) -> bool {
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

pub(super) fn is_reference_to(expression: &syn::Expr, name: &str, mutable: bool) -> bool {
    matches!(expression, syn::Expr::Reference(reference) if reference.mutability.is_some() == mutable && expression_path_is(&reference.expr, &[name]))
}

pub(super) fn is_mutable_self_field_reference(expression: &syn::Expr, field: &str) -> bool {
    let syn::Expr::Reference(reference) = expression else {
        return false;
    };
    reference.mutability.is_some() && is_self_field(&reference.expr, field)
}

pub(super) fn is_self_field(expression: &syn::Expr, field: &str) -> bool {
    matches!(expression, syn::Expr::Field(field_expr) if expression_path_is(&field_expr.base, &["self"]) && matches!(&field_expr.member, syn::Member::Named(name) if name == field))
}

pub(super) fn is_stdout_lock(expression: &syn::Expr) -> bool {
    let syn::Expr::MethodCall(lock) = expression else {
        return false;
    };
    let syn::Expr::Call(stdout) = lock.receiver.as_ref() else {
        return false;
    };
    lock.method == "lock"
        && lock.args.is_empty()
        && stdout.args.is_empty()
        && expression_path_is(&stdout.func, &["std", "io", "stdout"])
}

pub(super) fn is_machine_condition(expression: &syn::Expr) -> bool {
    matches!(expression, syn::Expr::MethodCall(call) if call.method == "is_machine" && call.args.is_empty() && is_self_field(&call.receiver, "format"))
}

pub(super) fn pattern_variant(pattern: &syn::Pat, root: &str) -> Result<String> {
    let syn::Pat::Path(pattern) = pattern else {
        bail!("CLI writer format arm is not a plain variant pattern");
    };
    if pattern.qself.is_some()
        || pattern.path.leading_colon.is_some()
        || pattern.path.segments.len() != 2
        || pattern.path.segments[0].ident != root
    {
        bail!("CLI writer format arm has an unexpected pattern path");
    }
    Ok(pattern.path.segments[1].ident.to_string())
}

pub(super) fn is_ok_unit(expression: &syn::Expr) -> bool {
    let syn::Expr::Call(call) = expression else {
        return false;
    };
    call.args.len() == 1
        && expression_path_is(&call.func, &["Ok"])
        && matches!(&call.args[0], syn::Expr::Tuple(tuple) if tuple.elems.is_empty())
}
