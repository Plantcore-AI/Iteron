use super::graph::{
    SourceView, file_attribute_fingerprints, import_fingerprints, module_fingerprints,
    semantic_item,
};
use anyhow::{Context, Result, bail};
use quote::ToTokens;

struct FreeFunctions {
    path: &'static str,
    names: &'static [&'static str],
}

struct Methods {
    path: &'static str,
    target: &'static str,
    names: &'static [&'static str],
}

struct Types {
    path: &'static str,
    names: &'static [&'static str],
}

const FREE_FUNCTIONS: &[FreeFunctions] = &[
    FreeFunctions {
        path: "crates/protocol/src/wire.rs",
        names: &["require_current"],
    },
    FreeFunctions {
        path: "crates/record/src/lib.rs",
        names: &["replay"],
    },
    FreeFunctions {
        path: "crates/eval/src/contract.rs",
        names: &[
            "admit_type_version",
            "parse_machine_record",
            "parse_final_result",
        ],
    },
    FreeFunctions {
        path: "crates/eval/src/runner.rs",
        names: &["run_cell"],
    },
    FreeFunctions {
        path: "crates/eval/src/main.rs",
        names: &["main"],
    },
    FreeFunctions {
        path: "crates/cli/src/output.rs",
        names: &[
            "outcome_exit_code",
            "outcome_name",
            "outcome_reason",
            "phase_name",
            "effort_application_json",
            "scrub",
            "scrub_json",
            "is_token_boundary",
            "stream_event",
            "final_result",
            "write_json_line",
        ],
    },
    FreeFunctions {
        path: "crates/cli/src/main.rs",
        names: &["main", "run_cli"],
    },
];

const WHOLE_FILES: &[&str] = &["crates/eval/src/strict_json.rs"];

const METHODS: &[Methods] = &[
    Methods {
        path: "crates/protocol/src/wire.rs",
        target: "SqEnvelope",
        names: &["current", "into_current"],
    },
    Methods {
        path: "crates/protocol/src/wire.rs",
        target: "EqEnvelope",
        names: &["current", "into_current"],
    },
    Methods {
        path: "crates/record/src/lib.rs",
        target: "Rollout",
        names: &["append"],
    },
    Methods {
        path: "crates/cli/src/output.rs",
        target: "OutputFormat",
        names: &["is_machine"],
    },
    Methods {
        path: "crates/cli/src/output.rs",
        target: "Emitter",
        names: &[
            "new",
            "write_text_delta",
            "flush_text_output",
            "write_stream_event",
            "flush_stream_text",
            "event",
            "result",
        ],
    },
    Methods {
        path: "crates/cli/src/output.rs",
        target: "StreamingScrubber",
        names: &["push", "finish"],
    },
    Methods {
        path: "crates/obs/src/lib.rs",
        target: "CostState",
        names: &["usd", "status", "reason"],
    },
    Methods {
        path: "crates/obs/src/lib.rs",
        target: "CostUnknownReason",
        names: &["code"],
    },
];

const TYPES: &[Types] = &[
    Types {
        path: "crates/kernel/src/lib.rs",
        names: &[
            "UiEvent",
            "WorkflowTaskUi",
            "WorkflowExecutionModeUi",
            "WorkflowPhaseUi",
            "WorkflowAgentOutcomeUi",
            "WorkflowRunOutcomeUi",
            "WorkflowUiEvent",
        ],
    },
    Types {
        path: "crates/provider/src/lib.rs",
        names: &["EffortApplication"],
    },
    Types {
        path: "crates/ctx/src/compact.rs",
        names: &["ContextEstimate"],
    },
    Types {
        path: "crates/obs/src/lib.rs",
        names: &["CostState", "CostUnknownReason"],
    },
];

pub(super) fn compare_critical_functions(
    base_view: SourceView<'_>,
    candidate_view: SourceView<'_>,
) -> Result<()> {
    let mut loaded = std::collections::BTreeMap::new();
    for path in FREE_FUNCTIONS
        .iter()
        .map(|group| group.path)
        .chain(METHODS.iter().map(|group| group.path))
        .chain(TYPES.iter().map(|group| group.path))
        .chain(WHOLE_FILES.iter().copied())
    {
        if loaded.contains_key(path) {
            continue;
        }
        let base = base_view.parse_file(path)?;
        let current = candidate_view.parse_file(path)?;
        if import_fingerprints(&base) != import_fingerprints(&current) {
            bail!("critical schema source '{path}' changed its import bindings");
        }
        if module_fingerprints(&base) != module_fingerprints(&current) {
            bail!("critical schema source '{path}' changed its module declarations");
        }
        if file_attribute_fingerprints(&base) != file_attribute_fingerprints(&current) {
            bail!("critical schema source '{path}' changed its file-level attributes");
        }
        loaded.insert(path, (base, current));
    }

    for group in FREE_FUNCTIONS {
        let (base, current) = loaded
            .get(group.path)
            .expect("every critical source was loaded");
        for name in group.names {
            let old = free_function(base, name)?;
            let new = free_function(current, name)?;
            if function_fingerprint(old) != function_fingerprint(new) {
                bail!(
                    "critical schema function '{}::{name}' changed from the trusted base",
                    group.path
                );
            }
        }
    }
    for group in METHODS {
        let (base, current) = loaded
            .get(group.path)
            .expect("every critical source was loaded");
        for name in group.names {
            let (old_impl, old) = method(base, group.target, name)?;
            let (new_impl, new) = method(current, group.target, name)?;
            if impl_header_fingerprint(old_impl) != impl_header_fingerprint(new_impl)
                || method_fingerprint(old) != method_fingerprint(new)
            {
                bail!(
                    "critical schema method '{}::{}::{name}' changed from the trusted base",
                    group.path,
                    group.target
                );
            }
        }
    }
    for path in WHOLE_FILES {
        let (base, current) = loaded
            .get(path)
            .expect("every critical whole source was loaded");
        if file_fingerprint(base) != file_fingerprint(current) {
            bail!("critical schema source '{path}' changed from the trusted base");
        }
    }
    for group in TYPES {
        let (base, current) = loaded
            .get(group.path)
            .expect("every critical source was loaded");
        for name in group.names {
            let old = named_type(base, name)?;
            let new = named_type(current, name)?;
            if semantic_item(old) != semantic_item(new) {
                bail!(
                    "critical schema type '{}::{name}' changed from the trusted base",
                    group.path
                );
            }
        }
    }
    Ok(())
}

fn named_type<'a>(file: &'a syn::File, name: &str) -> Result<&'a syn::Item> {
    let mut items = file.items.iter().filter(|item| match item {
        syn::Item::Enum(item) => item.ident == name,
        syn::Item::Struct(item) => item.ident == name,
        syn::Item::Type(item) => item.ident == name,
        _ => false,
    });
    let item = items
        .next()
        .with_context(|| format!("critical schema source lacks type '{name}'"))?;
    if items.next().is_some() {
        bail!("critical schema source repeats type '{name}'");
    }
    Ok(item)
}

fn free_function<'a>(file: &'a syn::File, name: &str) -> Result<&'a syn::ItemFn> {
    let mut functions = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    });
    let function = functions
        .next()
        .with_context(|| format!("critical schema source lacks function '{name}'"))?;
    if functions.next().is_some() {
        bail!("critical schema source repeats function '{name}'");
    }
    Ok(function)
}

fn method<'a>(
    file: &'a syn::File,
    target: &str,
    name: &str,
) -> Result<(&'a syn::ItemImpl, &'a syn::ImplItemFn)> {
    let mut methods = file.items.iter().filter_map(|item| {
        let syn::Item::Impl(item) = item else {
            return None;
        };
        if item.trait_.is_some() || self_type_name(&item.self_ty).as_deref() != Some(target) {
            return None;
        }
        item.items.iter().find_map(|member| match member {
            syn::ImplItem::Fn(function) if function.sig.ident == name => Some((item, function)),
            _ => None,
        })
    });
    let method = methods.next().with_context(|| {
        format!("critical schema source lacks inherent method '{target}::{name}'")
    })?;
    if methods.next().is_some() {
        bail!("critical schema source repeats inherent method '{target}::{name}'");
    }
    Ok(method)
}

fn self_type_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn function_fingerprint(function: &syn::ItemFn) -> String {
    let mut function = function.clone();
    function
        .attrs
        .retain(|attribute| !attribute.path().is_ident("doc"));
    function.into_token_stream().to_string()
}

fn method_fingerprint(function: &syn::ImplItemFn) -> String {
    let mut function = function.clone();
    function
        .attrs
        .retain(|attribute| !attribute.path().is_ident("doc"));
    function.into_token_stream().to_string()
}

fn impl_header_fingerprint(item: &syn::ItemImpl) -> String {
    let mut item = item.clone();
    item.attrs
        .retain(|attribute| !attribute.path().is_ident("doc"));
    item.items.clear();
    item.into_token_stream().to_string()
}

fn file_fingerprint(file: &syn::File) -> String {
    let mut file = file.clone();
    file.attrs
        .retain(|attribute| !attribute.path().is_ident("doc"));
    for item in &mut file.items {
        strip_item_docs(item);
    }
    file.into_token_stream().to_string()
}

fn strip_item_docs(item: &mut syn::Item) {
    match item {
        syn::Item::Fn(item) => item
            .attrs
            .retain(|attribute| !attribute.path().is_ident("doc")),
        syn::Item::Struct(item) => {
            item.attrs
                .retain(|attribute| !attribute.path().is_ident("doc"));
            for field in &mut item.fields {
                field
                    .attrs
                    .retain(|attribute| !attribute.path().is_ident("doc"));
            }
        }
        syn::Item::Impl(item) => {
            item.attrs
                .retain(|attribute| !attribute.path().is_ident("doc"));
            for member in &mut item.items {
                if let syn::ImplItem::Fn(function) = member {
                    function
                        .attrs
                        .retain(|attribute| !attribute.path().is_ident("doc"));
                }
            }
        }
        syn::Item::Use(item) => item
            .attrs
            .retain(|attribute| !attribute.path().is_ident("doc")),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_function_fingerprint_ignores_docs_but_not_the_body() {
        let first: syn::ItemFn = syn::parse_quote! {
            /// old words
            fn gate(value: u32) -> bool { value == 1 }
        };
        let docs_only: syn::ItemFn = syn::parse_quote! {
            /// new words
            fn gate(value: u32) -> bool { value == 1 }
        };
        let changed: syn::ItemFn = syn::parse_quote! {
            fn gate(value: u32) -> bool { value <= 1 }
        };
        assert_eq!(
            function_fingerprint(&first),
            function_fingerprint(&docs_only)
        );
        assert_ne!(function_fingerprint(&first), function_fingerprint(&changed));
    }
}
