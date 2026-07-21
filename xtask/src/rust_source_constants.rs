use anyhow::{Context, Result, bail};

pub(crate) fn public_decimal_const(source: &[u8], name: &str, ty: &str) -> Result<u32> {
    let source = std::str::from_utf8(source).context("Rust constant source is not UTF-8")?;
    let file = syn::parse_file(source).context("Rust constant source does not parse")?;
    let mut matched = None;
    for item in file.items {
        let syn::Item::Const(item) = item else {
            continue;
        };
        if item.ident != name {
            continue;
        }
        if matched.is_some() {
            bail!("Rust source repeats public constant '{name}'");
        }
        if !matches!(item.vis, syn::Visibility::Public(_)) {
            bail!("Rust constant '{name}' is not public");
        }
        if item
            .attrs
            .iter()
            .any(|attribute| !attribute.path().is_ident("doc"))
        {
            bail!("Rust constant '{name}' has an active or unsupported attribute");
        }
        let syn::Type::Path(item_type) = item.ty.as_ref() else {
            bail!("Rust constant '{name}' does not use primitive type '{ty}'");
        };
        if item_type.qself.is_some()
            || item_type.path.leading_colon.is_some()
            || item_type.path.segments.len() != 1
            || item_type.path.segments[0].ident != ty
            || !matches!(
                item_type.path.segments[0].arguments,
                syn::PathArguments::None
            )
        {
            bail!("Rust constant '{name}' does not use primitive type '{ty}'");
        }
        let syn::Expr::Lit(expression) = item.expr.as_ref() else {
            bail!("Rust constant '{name}' is not one plain decimal literal");
        };
        let syn::Lit::Int(literal) = &expression.lit else {
            bail!("Rust constant '{name}' is not one plain decimal literal");
        };
        let spelling = literal.to_string();
        if !literal.suffix().is_empty()
            || spelling.is_empty()
            || !spelling.bytes().all(|byte| byte.is_ascii_digit())
        {
            bail!("Rust constant '{name}' is not one plain unsuffixed decimal literal");
        }
        matched = Some(
            spelling
                .parse::<u32>()
                .context("Rust decimal constant does not fit u32")?,
        );
    }
    matched.with_context(|| format!("public Rust constant '{name}' is missing"))
}

pub(crate) fn public_decimal_slice_const(
    source: &[u8],
    name: &str,
    element_ty: &str,
) -> Result<Vec<u32>> {
    let source = std::str::from_utf8(source).context("Rust constant source is not UTF-8")?;
    let file = syn::parse_file(source).context("Rust constant source does not parse")?;
    let mut matched = None;
    for item in file.items {
        let syn::Item::Const(item) = item else {
            continue;
        };
        if item.ident != name {
            continue;
        }
        if matched.is_some() {
            bail!("Rust source repeats public constant '{name}'");
        }
        validate_public_doc_only_const(&item, name)?;
        let syn::Type::Reference(reference) = item.ty.as_ref() else {
            bail!("Rust constant '{name}' is not a shared slice reference");
        };
        let syn::Type::Slice(slice) = reference.elem.as_ref() else {
            bail!("Rust constant '{name}' is not a shared slice reference");
        };
        if reference.mutability.is_some()
            || reference.lifetime.is_some()
            || !is_primitive_type(&slice.elem, element_ty)
        {
            bail!("Rust constant '{name}' does not use exact type '&[{element_ty}]'");
        }
        let syn::Expr::Reference(reference) = item.expr.as_ref() else {
            bail!("Rust constant '{name}' is not one borrowed literal slice");
        };
        let syn::Expr::Array(array) = reference.expr.as_ref() else {
            bail!("Rust constant '{name}' is not one borrowed literal slice");
        };
        if reference.mutability.is_some() || array.elems.is_empty() {
            bail!("Rust constant '{name}' is not one non-empty borrowed literal slice");
        }
        let values = array
            .elems
            .iter()
            .map(|expression| plain_decimal_expression(expression, name))
            .collect::<Result<Vec<_>>>()?;
        if values.windows(2).any(|window| window[0] >= window[1]) {
            bail!("Rust constant '{name}' must be strictly increasing without duplicates");
        }
        matched = Some(values);
    }
    matched.with_context(|| format!("public Rust constant '{name}' is missing"))
}

pub(crate) fn public_string_array_const(source: &[u8], name: &str) -> Result<Vec<String>> {
    let source = std::str::from_utf8(source).context("Rust constant source is not UTF-8")?;
    let file = syn::parse_file(source).context("Rust constant source does not parse")?;
    let mut matched = None;
    for item in file.items {
        let syn::Item::Const(item) = item else {
            continue;
        };
        if item.ident != name {
            continue;
        }
        if matched.is_some() {
            bail!("Rust source repeats public constant '{name}'");
        }
        validate_public_doc_only_const(&item, name)?;
        let syn::Type::Array(array_type) = item.ty.as_ref() else {
            bail!("Rust constant '{name}' is not one string array");
        };
        let syn::Type::Reference(reference) = array_type.elem.as_ref() else {
            bail!("Rust constant '{name}' is not one string array");
        };
        if reference.mutability.is_some()
            || reference.lifetime.is_some()
            || !is_primitive_type(&reference.elem, "str")
        {
            bail!("Rust constant '{name}' is not one shared string array");
        }
        let declared_len = plain_decimal_expression(&array_type.len, name)? as usize;
        let syn::Expr::Array(array) = item.expr.as_ref() else {
            bail!("Rust constant '{name}' is not one literal array");
        };
        let mut values = Vec::new();
        for expression in &array.elems {
            let syn::Expr::Lit(expression) = expression else {
                bail!("Rust constant '{name}' contains a non-literal string");
            };
            let syn::Lit::Str(literal) = &expression.lit else {
                bail!("Rust constant '{name}' contains a non-string element");
            };
            values.push(literal.value());
        }
        if values.len() != declared_len
            || values.is_empty()
            || values.windows(2).any(|pair| pair[0] >= pair[1])
        {
            bail!("Rust constant '{name}' must be a non-empty sorted unique string array");
        }
        matched = Some(values);
    }
    matched.with_context(|| format!("public Rust constant '{name}' is missing"))
}

pub(crate) fn public_string_u32_tuple_slice_const(
    source: &[u8],
    name: &str,
) -> Result<Vec<(String, u32)>> {
    let source = std::str::from_utf8(source).context("Rust constant source is not UTF-8")?;
    let file = syn::parse_file(source).context("Rust constant source does not parse")?;
    let mut matched = None;
    for item in file.items {
        let syn::Item::Const(item) = item else {
            continue;
        };
        if item.ident != name {
            continue;
        }
        if matched.is_some() {
            bail!("Rust source repeats public constant '{name}'");
        }
        validate_public_doc_only_const(&item, name)?;
        validate_string_u32_tuple_slice_type(&item.ty, name)?;
        let syn::Expr::Reference(reference) = item.expr.as_ref() else {
            bail!("Rust constant '{name}' is not one borrowed tuple slice");
        };
        let syn::Expr::Array(array) = reference.expr.as_ref() else {
            bail!("Rust constant '{name}' is not one borrowed tuple slice");
        };
        if reference.mutability.is_some() || array.elems.is_empty() {
            bail!("Rust constant '{name}' is not one non-empty borrowed tuple slice");
        }
        let mut values = Vec::new();
        for expression in &array.elems {
            let syn::Expr::Tuple(tuple) = expression else {
                bail!("Rust constant '{name}' contains a non-tuple element");
            };
            if tuple.elems.len() != 2 {
                bail!("Rust constant '{name}' contains a tuple with the wrong arity");
            }
            let syn::Expr::Lit(label) = &tuple.elems[0] else {
                bail!("Rust constant '{name}' tuple label is not literal");
            };
            let syn::Lit::Str(label) = &label.lit else {
                bail!("Rust constant '{name}' tuple label is not a string");
            };
            values.push((
                label.value(),
                plain_decimal_expression(&tuple.elems[1], name)?,
            ));
        }
        if values.windows(2).any(|pair| pair[0] >= pair[1]) {
            bail!("Rust constant '{name}' must be strictly sorted without duplicate tuples");
        }
        matched = Some(values);
    }
    matched.with_context(|| format!("public Rust constant '{name}' is missing"))
}

fn validate_string_u32_tuple_slice_type(ty: &syn::Type, name: &str) -> Result<()> {
    let syn::Type::Reference(reference) = ty else {
        bail!("Rust constant '{name}' does not use type '&[(&str, u32)]'");
    };
    let syn::Type::Slice(slice) = reference.elem.as_ref() else {
        bail!("Rust constant '{name}' does not use type '&[(&str, u32)]'");
    };
    let syn::Type::Tuple(tuple) = slice.elem.as_ref() else {
        bail!("Rust constant '{name}' does not use type '&[(&str, u32)]'");
    };
    if reference.mutability.is_some()
        || reference.lifetime.is_some()
        || tuple.elems.len() != 2
        || !matches!(&tuple.elems[0], syn::Type::Reference(string) if string.mutability.is_none() && string.lifetime.is_none() && is_primitive_type(&string.elem, "str"))
        || !is_primitive_type(&tuple.elems[1], "u32")
    {
        bail!("Rust constant '{name}' does not use type '&[(&str, u32)]'");
    }
    Ok(())
}

fn validate_public_doc_only_const(item: &syn::ItemConst, name: &str) -> Result<()> {
    if !matches!(item.vis, syn::Visibility::Public(_)) {
        bail!("Rust constant '{name}' is not public");
    }
    if item
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        bail!("Rust constant '{name}' has an active or unsupported attribute");
    }
    Ok(())
}

fn is_primitive_type(ty: &syn::Type, expected: &str) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && path.path.segments[0].ident == expected
        && matches!(path.path.segments[0].arguments, syn::PathArguments::None)
}

fn plain_decimal_expression(expression: &syn::Expr, name: &str) -> Result<u32> {
    let syn::Expr::Lit(expression) = expression else {
        bail!("Rust constant '{name}' contains a non-literal slice element");
    };
    let syn::Lit::Int(literal) = &expression.lit else {
        bail!("Rust constant '{name}' contains a non-integer slice element");
    };
    let spelling = literal.to_string();
    if !literal.suffix().is_empty()
        || spelling.is_empty()
        || !spelling.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("Rust constant '{name}' contains a non-decimal or suffixed slice element");
    }
    spelling
        .parse::<u32>()
        .context("Rust decimal slice element does not fit u32")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_decimal_constant_is_ast_bound_and_exact() {
        assert_eq!(
            public_decimal_const(b"/// docs\npub const VERSION: u32 = 4;", "VERSION", "u32")
                .unwrap(),
            4
        );
        for source in [
            "/* pub const VERSION: u32 = 9; */",
            "include!(\"version.rs\");",
            "#[cfg(any())] pub const VERSION: u32 = 4;",
            "const VERSION: u32 = 4;",
            "pub const VERSION: u64 = 4;",
            "pub const VERSION: u32 = 0x4;",
            "pub const VERSION: u32 = 4u32;",
            "pub const VERSION: u32 = 3 + 1;",
        ] {
            assert!(public_decimal_const(source.as_bytes(), "VERSION", "u32").is_err());
        }
    }
}
