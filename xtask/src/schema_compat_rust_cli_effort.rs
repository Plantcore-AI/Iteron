use super::cli_parse::{
    direct_json_macro, function_tail, json_macro_object, outer_json_object_shape,
    parse_cli_output_source, unique_value_function,
};
use super::parse::serde_snake_case;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn cli_effort_output_shapes(
    source: &[u8],
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let source = std::str::from_utf8(source).context("CLI output source is not UTF-8")?;
    let file = parse_cli_output_source(source)?;
    let function = unique_value_function(&file, "effort_application_json", false)?;
    let expression = peel_expression(function_tail(function)?);
    let syn::Expr::Match(expression) = expression else {
        bail!("CLI effort producer does not directly return a match");
    };
    if !matches!(peel_expression(&expression.expr), syn::Expr::Path(path) if path.path.is_ident("application"))
    {
        bail!("CLI effort producer does not match directly on 'application'");
    }
    let mut variants = BTreeSet::new();
    let mut shapes = BTreeMap::new();
    for arm in &expression.arms {
        if !arm.attrs.is_empty() || arm.guard.is_some() {
            bail!("CLI effort match arm cannot carry attributes or a guard");
        }
        let syn::Pat::Struct(pattern) = &arm.pat else {
            bail!("CLI effort match arm is not one named EffortApplication variant");
        };
        if pattern.path.leading_colon.is_some()
            || pattern.path.segments.len() != 2
            || pattern.path.segments[0].ident != "EffortApplication"
            || pattern.rest.is_some()
        {
            bail!("CLI effort match arm has an unsupported variant pattern");
        }
        let variant = pattern.path.segments[1].ident.to_string();
        if !variants.insert(variant.clone()) {
            bail!("CLI effort output repeats variant '{variant}'");
        }
        let mac = direct_json_macro(&arm.body)?;
        let object = json_macro_object(mac)?;
        let close = object.len().saturating_sub(1);
        let (enforcement, fields) = outer_json_object_shape(&object, 0, close, "enforcement")?;
        let expected = serde_snake_case(&variant);
        if enforcement != expected {
            bail!("CLI effort variant '{variant}' emits '{enforcement}' instead of '{expected}'");
        }
        if shapes.insert(enforcement.clone(), fields).is_some() {
            bail!("CLI effort output repeats enforcement '{enforcement}'");
        }
    }
    if variants.is_empty() || shapes.len() != variants.len() {
        bail!("CLI effort output must bind every match variant to one distinct json! object");
    }
    Ok(shapes)
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

#[cfg(test)]
pub(super) fn cli_effort_enforcements(source: &[u8]) -> Result<BTreeSet<String>> {
    Ok(cli_effort_output_shapes(source)?.into_keys().collect())
}

#[cfg(test)]
mod tests {
    use super::super::super::manifest::read_bounded;
    use super::super::{CLI_MACHINE_OUTPUT_SOURCE, MAX_SOURCE_BYTES};
    use super::*;
    use std::path::Path;

    #[test]
    fn d13_14_effort_binding_ignores_comment_spoofs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let source = read_bounded(root, CLI_MACHINE_OUTPUT_SOURCE, MAX_SOURCE_BYTES).unwrap();
        let source = std::str::from_utf8(&source).unwrap();
        let spoofed = source.replacen(
            "match application {",
            "match application { /* EffortApplication::Spoof => json!({\"enforcement\": \"spoof\"}), */",
            1,
        );
        assert_eq!(
            cli_effort_output_shapes(spoofed.as_bytes()).unwrap(),
            cli_effort_output_shapes(source.as_bytes()).unwrap()
        );
    }
}
