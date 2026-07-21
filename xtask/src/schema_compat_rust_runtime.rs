#[path = "schema_compat_rust_runtime_eval.rs"]
mod eval;
#[path = "schema_compat_rust_runtime_protocol.rs"]
mod protocol;
#[path = "schema_compat_rust_runtime_record.rs"]
mod record;

use super::super::manifest::read_bounded;
use super::MAX_SOURCE_BYTES;
use anyhow::{Context, Result, bail};
use quote::ToTokens;
use std::path::Path;

pub(super) fn validate(root: &Path) -> Result<()> {
    protocol::validate(root)?;
    eval::validate(root)?;
    record::validate(root)
}

pub(super) fn parse(root: &Path, relative: &str) -> Result<syn::File> {
    let bytes = read_bounded(root, relative, MAX_SOURCE_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("runtime schema source '{relative}' is not UTF-8"))?;
    syn::parse_file(text)
        .with_context(|| format!("runtime schema source '{relative}' does not parse"))
}

pub(super) fn require_function(file: &syn::File, name: &str, expected: &str) -> Result<()> {
    let mut functions = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    });
    let actual = functions
        .next()
        .with_context(|| format!("runtime schema source lacks function '{name}'"))?;
    if functions.next().is_some() {
        bail!("runtime schema source repeats function '{name}'");
    }
    let expected = syn::parse_str::<syn::ItemFn>(expected)
        .with_context(|| format!("trusted function witness '{name}' is invalid"))?;
    let actual_tokens = function_tokens(actual);
    let expected_tokens = function_tokens(&expected);
    if actual_tokens != expected_tokens {
        bail!("runtime schema function '{name}' differs from its trusted dataflow witness");
    }
    Ok(())
}

pub(super) fn require_method(
    file: &syn::File,
    target: &str,
    name: &str,
    expected: &str,
) -> Result<()> {
    let mut methods = Vec::new();
    for item in &file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        if type_name(&item.self_ty).as_deref() != Some(target) || item.trait_.is_some() {
            continue;
        }
        if !item.attrs.is_empty()
            || item.defaultness.is_some()
            || item.unsafety.is_some()
            || !item.generics.params.is_empty()
            || item.generics.where_clause.is_some()
        {
            bail!("runtime schema impl '{target}' is conditional or non-ordinary");
        }
        for member in &item.items {
            if let syn::ImplItem::Fn(method) = member
                && method.sig.ident == name
            {
                methods.push(method);
            }
        }
    }
    let [actual] = methods.as_slice() else {
        bail!("runtime schema requires exactly one method '{target}::{name}'");
    };
    let wrapper = format!("impl {target} {{ {expected} }}");
    let expected = syn::parse_str::<syn::ItemImpl>(&wrapper)
        .with_context(|| format!("trusted method witness '{target}::{name}' is invalid"))?;
    let Some(syn::ImplItem::Fn(expected)) = expected.items.first() else {
        bail!("trusted method witness '{target}::{name}' is not a method");
    };
    if method_tokens(actual) != method_tokens(expected) {
        bail!("runtime schema method '{target}::{name}' differs from its trusted dataflow witness");
    }
    Ok(())
}

pub(super) fn require_trait_method(
    file: &syn::File,
    target: &str,
    trait_name: &str,
    name: &str,
    expected: &str,
) -> Result<()> {
    let mut methods = Vec::new();
    for item in &file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        let Some((_, trait_path, _)) = &item.trait_ else {
            continue;
        };
        if type_name(&item.self_ty).as_deref() != Some(target)
            || trait_path
                .segments
                .last()
                .is_none_or(|segment| segment.ident != trait_name)
        {
            continue;
        }
        if !item.attrs.is_empty() || item.defaultness.is_some() || item.unsafety.is_some() {
            bail!("runtime schema trait impl '{trait_name} for {target}' is conditional");
        }
        for member in &item.items {
            if let syn::ImplItem::Fn(method) = member
                && method.sig.ident == name
            {
                methods.push(method);
            }
        }
    }
    let [actual] = methods.as_slice() else {
        bail!("runtime schema requires exactly one '{trait_name}::{name}' for '{target}'");
    };
    let wrapper = format!("impl {target} {{ {expected} }}");
    let expected = syn::parse_str::<syn::ItemImpl>(&wrapper)
        .with_context(|| format!("trusted trait-method witness '{target}::{name}' is invalid"))?;
    let Some(syn::ImplItem::Fn(expected)) = expected.items.first() else {
        bail!("trusted trait-method witness '{target}::{name}' is not a method");
    };
    if method_tokens(actual) != method_tokens(expected) {
        bail!("runtime schema trait method '{target}::{name}' differs from its trusted witness");
    }
    Ok(())
}

fn function_tokens(function: &syn::ItemFn) -> String {
    let mut function = function.clone();
    function
        .attrs
        .retain(|attribute| !attribute.path().is_ident("doc"));
    function.into_token_stream().to_string()
}

fn method_tokens(method: &syn::ImplItemFn) -> String {
    let mut method = method.clone();
    method
        .attrs
        .retain(|attribute| !attribute.path().is_ident("doc"));
    method.into_token_stream().to_string()
}

fn type_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() || path.path.leading_colon.is_some() || path.path.segments.len() != 1 {
        return None;
    }
    Some(path.path.segments[0].ident.to_string())
}
