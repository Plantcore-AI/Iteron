use super::graph::{
    ScopeBinding, SourceView, file_attribute_fingerprints, identifier_occurrences, import_bindings,
    module_bindings, semantic_item,
};
use anyhow::{Context, Result, bail};
use quote::ToTokens;
use std::collections::BTreeSet;

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
        // `main` is the immutable dispatch root. `run_cli` is intentionally validated by the
        // dedicated AST authorities in `schema_compat_rust_cli_main` and
        // `schema_compat_rust_cli_writer`: freezing its entire orchestration body made a
        // result-byte-preserving client/transport refactor indistinguishable from a schema
        // mutation. Those authorities retain the exact Emitter construction, two event drains,
        // direct final_result binding/sink, and stdout-exclusivity checks.
        names: &["main"],
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
        path: "crates/cli/src/runtime.rs",
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
        loaded.insert(path, (base, current));
    }

    for (path, (base, current)) in &loaded {
        compare_frozen_scope(path, base, current)?;
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

/// Compare the file-scope bindings that can affect this file's frozen items.
///
/// Freezing an item's token fingerprint only means something while the names inside those tokens
/// keep resolving to the same things, so imports and module declarations have to be compared too.
///
/// Frozen executable code keeps every import compared. A trait import can change `value.method()`
/// resolution without the trait's own name appearing in the function tokens, so name-only import
/// filtering is not sound there. Plain module declarations remain name-filtered: an
/// attribute-free `mod image_input;` cannot affect an item that never names `image_input`.
/// Type-only files use the narrower name-aware comparison for both. Unknown-name declarations
/// (glob/anonymous imports and active `macro_use`/conditional declarations) remain compared
/// unconditionally.
fn compare_frozen_scope(path: &str, base: &syn::File, current: &syn::File) -> Result<()> {
    let referenced = frozen_identifiers(path, base, current)?;
    match scope_drift_with_import_mode(
        base,
        current,
        referenced.as_ref(),
        path_has_frozen_executable(path),
    ) {
        Some(ScopeDrift::Import) => {
            bail!(
                "critical schema source '{path}' changed an import binding its frozen items rely on"
            )
        }
        Some(ScopeDrift::Module) => {
            bail!(
                "critical schema source '{path}' changed a module declaration its frozen items rely on"
            )
        }
        Some(ScopeDrift::FileAttribute) => {
            bail!("critical schema source '{path}' changed its file-level attributes")
        }
        None => Ok(()),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ScopeDrift {
    Import,
    Module,
    FileAttribute,
}

/// Which facet of the file scope drifted, considering only bindings `referenced` can name.
///
/// `referenced` of `None` compares every binding, for whole-file freezes.
#[cfg(test)]
fn scope_drift(
    base: &syn::File,
    current: &syn::File,
    referenced: Option<&BTreeSet<String>>,
) -> Option<ScopeDrift> {
    scope_drift_with_import_mode(base, current, referenced, false)
}

fn scope_drift_with_import_mode(
    base: &syn::File,
    current: &syn::File,
    referenced: Option<&BTreeSet<String>>,
    compare_all_imports: bool,
) -> Option<ScopeDrift> {
    let retain = |bindings: Vec<ScopeBinding>, compare_all: bool| -> Vec<String> {
        bindings
            .into_iter()
            .filter(|binding| {
                compare_all || referenced.is_none_or(|referenced| binding.reaches(referenced))
            })
            .map(|binding| binding.fingerprint)
            .collect()
    };

    // Imports keep set semantics: re-ordering `use` items never changes what they bind.
    let imports = |file| {
        retain(import_bindings(file), compare_all_imports)
            .into_iter()
            .collect::<BTreeSet<_>>()
    };
    if imports(base) != imports(current) {
        return Some(ScopeDrift::Import);
    }
    // An attribute-free `mod image_input;` cannot affect a frozen item that never names
    // `image_input`. Attributed declarations remain unconditional ScopeBindings, so macro-use and
    // conditional module sources are still compared even in this name-filtered path.
    if retain(module_bindings(base), false) != retain(module_bindings(current), false) {
        return Some(ScopeDrift::Module);
    }
    // File-level attributes stay compared whole: `#![cfg_attr(...)]` and friends can re-shape any
    // item in the file, so no frozen item can be shown independent of them.
    if file_attribute_fingerprints(base) != file_attribute_fingerprints(current) {
        return Some(ScopeDrift::FileAttribute);
    }
    None
}

/// Every identifier named by the frozen items in `path`, across both revisions.
///
/// `None` means "compare every binding" for a whole-file freeze. Frozen functions and methods still
/// collect their identifiers for module-declaration filtering, but
/// [`path_has_frozen_executable`] separately forces every import to remain compared because trait
/// imports participate in method resolution without being named in the frozen tokens. Both
/// revisions contribute because an item that gained a reference must have the binding behind that
/// reference compared as well — the item-level comparison that rejects the change runs later.
fn frozen_identifiers(
    path: &str,
    base: &syn::File,
    current: &syn::File,
) -> Result<Option<BTreeSet<String>>> {
    if WHOLE_FILES.contains(&path) {
        return Ok(None);
    }
    let mut names = BTreeSet::new();
    for file in [base, current] {
        for group in FREE_FUNCTIONS.iter().filter(|group| group.path == path) {
            for name in group.names {
                identifier_occurrences(
                    &function_fingerprint(free_function(file, name)?),
                    &mut names,
                );
            }
        }
        for group in METHODS.iter().filter(|group| group.path == path) {
            for name in group.names {
                let (item_impl, function) = method(file, group.target, name)?;
                identifier_occurrences(&impl_header_fingerprint(item_impl), &mut names);
                identifier_occurrences(&method_fingerprint(function), &mut names);
            }
        }
        for group in TYPES.iter().filter(|group| group.path == path) {
            for name in group.names {
                identifier_occurrences(&semantic_item(named_type(file, name)?), &mut names);
            }
        }
    }
    Ok(Some(names))
}

fn path_has_frozen_executable(path: &str) -> bool {
    FREE_FUNCTIONS.iter().any(|group| group.path == path)
        || METHODS.iter().any(|group| group.path == path)
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

    fn referenced(tokens: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        identifier_occurrences(tokens, &mut names);
        names
    }

    #[test]
    fn type_only_churn_no_frozen_token_can_name_is_admitted() {
        let base: syn::File = syn::parse_quote! {
            use core_protocol::Phase;
            mod pricing;
            pub enum Frozen { Step(Phase) }
        };
        let current: syn::File = syn::parse_quote! {
            use core_protocol::Phase;
            use core_ctx::ContextPort;
            mod pricing;
            mod strategy_runtime;
            pub enum Frozen { Step(Phase) }
        };
        // Exactly the two shapes that rejected #66 and #67: a new import and a new module
        // declaration, neither of which the frozen item's tokens mention.
        assert_eq!(
            scope_drift(
                &base,
                &current,
                Some(&referenced("pub enum Frozen { Step (Phase) }"))
            ),
            None
        );
        // ...and the whole-file freeze still refuses both.
        assert_eq!(scope_drift(&base, &current, None), Some(ScopeDrift::Import));
    }

    #[test]
    fn executable_freezes_compare_named_trait_imports_even_when_tokens_do_not_name_them() {
        let base: syn::File = syn::parse_quote! {
            use std::io::Write;
            mod pricing;
        };
        let redirected: syn::File = syn::parse_quote! {
            use crate::EvilWrite;
            mod pricing;
        };
        let unrelated_module: syn::File = syn::parse_quote! {
            use std::io::Write;
            mod pricing;
            mod image_input;
        };
        // `Rollout::append` contains `self.file.write_all(...)`, but its tokens do not contain the
        // trait name `Write`. A local `EvilWrite for File` can therefore redirect that exact method
        // call while leaving the frozen method byte-for-byte unchanged.
        let names = referenced("self.file.write_all(line.as_bytes())");
        assert!(path_has_frozen_executable("crates/record/src/lib.rs"));
        assert_eq!(
            scope_drift(&base, &redirected, Some(&names)),
            None,
            "the name-only filter demonstrates why executable imports need their own mode"
        );
        assert_eq!(
            scope_drift_with_import_mode(&base, &redirected, Some(&names), true),
            Some(ScopeDrift::Import)
        );
        assert_eq!(
            scope_drift_with_import_mode(&base, &unrelated_module, Some(&names), true),
            None,
            "full import comparison must not make plain unrelated modules global"
        );
    }

    #[test]
    fn anonymous_trait_imports_are_always_compared() {
        let base: syn::File = syn::parse_quote! {
            use trusted::Extension as _;
            pub struct Frozen;
        };
        let redirected: syn::File = syn::parse_quote! {
            use attacker::Extension as _;
            pub struct Frozen;
        };
        assert_eq!(
            scope_drift(&base, &redirected, Some(&referenced("pub struct Frozen ;"))),
            Some(ScopeDrift::Import)
        );
        assert_eq!(
            import_bindings(&base)[0].names,
            None,
            "an anonymous trait import affects method resolution without binding a name"
        );
    }

    #[test]
    fn active_macro_sources_are_always_compared() {
        let base_extern: syn::File = syn::parse_quote! {
            #[macro_use]
            extern crate trusted;
            pub struct Frozen;
        };
        let redirected_extern: syn::File = syn::parse_quote! {
            #[macro_use]
            extern crate attacker;
            pub struct Frozen;
        };
        assert_eq!(
            scope_drift(
                &base_extern,
                &redirected_extern,
                Some(&referenced("pub struct Frozen ;"))
            ),
            Some(ScopeDrift::Import)
        );

        let base_module: syn::File = syn::parse_quote! {
            #[macro_use]
            mod trusted {}
            pub struct Frozen;
        };
        let redirected_module: syn::File = syn::parse_quote! {
            #[macro_use]
            mod attacker {}
            pub struct Frozen;
        };
        assert_eq!(
            scope_drift(
                &base_module,
                &redirected_module,
                Some(&referenced("pub struct Frozen ;"))
            ),
            Some(ScopeDrift::Module)
        );
    }

    #[test]
    fn raw_identifier_bindings_match_the_frozen_tokens_that_name_them() {
        let base: syn::File = syn::parse_quote! {
            use trusted::r#type;
            pub struct Frozen(r#type);
        };
        let redirected: syn::File = syn::parse_quote! {
            use attacker::r#type;
            pub struct Frozen(r#type);
        };
        let names = referenced("pub struct Frozen (r#type) ;");
        assert!(names.contains("type"));
        assert_eq!(
            scope_drift(&base, &redirected, Some(&names)),
            Some(ScopeDrift::Import)
        );
    }

    #[test]
    fn redirecting_a_binding_a_frozen_item_names_is_still_rejected() {
        let base: syn::File = syn::parse_quote! {
            use core_protocol::Phase;
            pub enum Frozen { Step(Phase) }
        };
        let redirected: syn::File = syn::parse_quote! {
            use attacker::Phase;
            pub enum Frozen { Step(Phase) }
        };
        let renamed: syn::File = syn::parse_quote! {
            use attacker::Other as Phase;
            pub enum Frozen { Step(Phase) }
        };
        let names = referenced("pub enum Frozen { Step (Phase) }");
        assert_eq!(
            scope_drift(&base, &redirected, Some(&names)),
            Some(ScopeDrift::Import)
        );
        assert_eq!(
            scope_drift(&base, &renamed, Some(&names)),
            Some(ScopeDrift::Import)
        );
    }

    #[test]
    fn a_module_a_frozen_item_names_is_still_compared() {
        let base: syn::File = syn::parse_quote! {
            mod wire;
            pub struct Frozen(wire::Envelope);
        };
        let narrowed: syn::File = syn::parse_quote! {
            pub(crate) mod wire;
            pub struct Frozen(wire::Envelope);
        };
        assert_eq!(
            scope_drift(
                &base,
                &narrowed,
                Some(&referenced("pub struct Frozen (wire :: Envelope) ;"))
            ),
            Some(ScopeDrift::Module)
        );
    }

    #[test]
    fn a_glob_import_can_never_be_shown_irrelevant() {
        let base: syn::File = syn::parse_quote! {
            use core_protocol::*;
            pub struct Frozen(Unrelated);
        };
        let current: syn::File = syn::parse_quote! {
            use attacker::*;
            pub struct Frozen(Unrelated);
        };
        // `Unrelated` names neither glob, yet a glob may supply it, so the change stays fatal.
        assert_eq!(
            scope_drift(
                &base,
                &current,
                Some(&referenced("pub struct Frozen (Unrelated) ;"))
            ),
            Some(ScopeDrift::Import)
        );
    }

    #[test]
    fn import_bindings_name_what_each_form_puts_in_scope() {
        let file: syn::File = syn::parse_quote! {
            use a::b;
            use a::c as d;
            use a::e::{self, f};
            use a::*;
            extern crate g as h;
        };
        let bound = |index: usize| import_bindings(&file)[index].names.clone();
        assert_eq!(bound(0), Some(BTreeSet::from(["b".to_owned()])));
        assert_eq!(bound(1), Some(BTreeSet::from(["d".to_owned()])));
        // `self` in a group binds the parent segment, not the literal `self`.
        assert_eq!(
            bound(2),
            Some(BTreeSet::from(["e".to_owned(), "f".to_owned()]))
        );
        assert_eq!(bound(3), None, "a glob binds unknowable names");
        assert_eq!(bound(4), Some(BTreeSet::from(["h".to_owned()])));
    }

    #[test]
    fn a_derive_a_frozen_type_carries_keeps_its_import_compared() {
        let base: syn::File = syn::parse_quote! {
            use serde::Serialize;
            #[derive(Serialize)]
            pub struct Frozen;
        };
        let current: syn::File = syn::parse_quote! {
            use attacker::Serialize;
            #[derive(Serialize)]
            pub struct Frozen;
        };
        // The derive path lives in the item's attribute tokens, so the scan reaches it.
        assert_eq!(
            scope_drift(
                &base,
                &current,
                Some(&referenced("#[derive(Serialize)] pub struct Frozen ;"))
            ),
            Some(ScopeDrift::Import)
        );
    }

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
