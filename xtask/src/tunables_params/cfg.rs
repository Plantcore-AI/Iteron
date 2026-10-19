//! Shared production eligibility for the parameter catalog and source census. Platform/feature
//! predicates stay symbolic except the explicit `test-fixtures` development-only feature.
//! Only configurations proven absent without tests/fixtures are excluded.
use syn::parse::Parser as _;

pub(crate) fn has_cfg_test(attributes: &[syn::Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| excludes_production(&attribute.meta, 0))
}

/// Out-of-line fixture sources need their declaring module's cfg; scanning a file alone loses
/// that proof. Only these newly shared fixture owners are admitted here, and removing/redirecting
/// their cfg makes them production candidates again instead of silently hiding declarations.
pub(crate) fn is_fixture_source(root: &std::path::Path, relative: &str) -> anyhow::Result<bool> {
    let parent = match relative {
        "crates/host/src/app_server/fixtures.rs" => "crates/host/src/app_server.rs",
        "crates/host/src/client_effects/experiment_lab/fixtures.rs" => {
            "crates/host/src/client_effects/experiment_lab.rs"
        }
        "crates/host/src/client_effects/tunables_simulation/fixtures.rs" => {
            "crates/host/src/client_effects/tunables_simulation.rs"
        }
        _ => return Ok(false),
    };
    let source = std::fs::read_to_string(root.join(parent))?;
    let syntax = syn::parse_file(&source)?;
    let modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.ident == "fixtures" => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    Ok(modules.len() == 1
        && modules[0].content.is_none()
        && modules[0]
            .attrs
            .iter()
            .all(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("doc"))
        && has_cfg_test(&modules[0].attrs))
}

fn arguments(
    list: &syn::MetaList,
) -> Option<syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>> {
    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()
}

fn excludes_production(meta: &syn::Meta, depth: usize) -> bool {
    if depth > 64 {
        // Insufficient evidence cannot silently erase an advertised production control.
        return false;
    }
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("cfg") => list
            .parse_args::<syn::Meta>()
            .ok()
            .is_some_and(|condition| non_test_value(&condition, depth + 1) == Some(false)),
        syn::Meta::List(list) if list.path.is_ident("cfg_attr") => {
            let Some(arguments) = arguments(list) else {
                return false;
            };
            let mut arguments = arguments.iter();
            let Some(condition) = arguments.next() else {
                return false;
            };
            non_test_value(condition, depth + 1) == Some(true)
                && arguments.any(|attribute| excludes_production(attribute, depth + 1))
        }
        _ => false,
    }
}

fn non_test_value(meta: &syn::Meta, depth: usize) -> Option<bool> {
    if depth > 64 {
        return None;
    }
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => Some(false),
        syn::Meta::NameValue(value)
            if value.path.is_ident("feature")
                && matches!(&value.value, syn::Expr::Lit(literal)
                if matches!(&literal.lit, syn::Lit::Str(feature) if feature.value() == "test-fixtures")) =>
        {
            Some(false)
        }
        syn::Meta::List(list) => {
            let arguments = arguments(list)?;
            let values: Vec<_> = arguments
                .iter()
                .map(|argument| non_test_value(argument, depth + 1))
                .collect();
            if list.path.is_ident("all") {
                if values.contains(&Some(false)) {
                    Some(false)
                } else if values.iter().all(|value| *value == Some(true)) {
                    Some(true)
                } else {
                    None
                }
            } else if list.path.is_ident("any") {
                if values.contains(&Some(true)) {
                    Some(true)
                } else if values.iter().all(|value| *value == Some(false)) {
                    Some(false)
                } else {
                    None
                }
            } else if list.path.is_ident("not") && values.len() == 1 {
                values[0].map(|value| !value)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    fn excluded(attribute: &str) -> bool {
        let item: syn::ItemFn = syn::parse_str(&format!("{attribute} fn candidate() {{}}"))
            .expect("real Rust attribute fixture");
        super::has_cfg_test(&item.attrs)
    }

    #[test]
    fn catalog_and_census_drop_only_proven_test_or_inactive_configurations() {
        for attribute in [
            "#[test]",
            "#[cfg(test)]",
            "#[cfg(feature = \"test-fixtures\")]",
            "#[cfg(any(test, feature = \"test-fixtures\"))]",
            "#[cfg(all(unix, any(test, feature = \"test-fixtures\")))]",
            "#[cfg(all(test, unix))]",
            "#[cfg(any(test, all(test, feature = \"optional\")))]",
            "#[cfg(any())]",
            "#[cfg(all(not(test), test))]",
            "#[cfg_attr(not(test), cfg(test))]",
            "#[cfg_attr(all(), cfg(any()))]",
        ] {
            assert!(excluded(attribute), "must exclude {attribute}");
        }
        for attribute in [
            "",
            "#[cfg(not(test))]",
            "#[cfg(any(not(windows), test))]",
            "#[cfg(any(feature = \"script-workflows\", test))]",
            "#[cfg(all(unix, any(test, feature = \"optional\")))]",
            "#[cfg(any(not(test), test))]",
            "#[cfg(feature = \"contest\")]",
            "#[cfg(any(feature = \"production\", feature = \"test-fixtures\"))]",
            "#[cfg(feature = \"test-fixtures-extra\")]",
            "#[cfg_attr(test, cfg(any()))]",
            "#[cfg_attr(feature = \"optional\", cfg(test))]",
            "#[cfg_attr(not(test), allow(dead_code))]",
            "#[cfg_attr(not(test), cfg_attr(test, cfg(any())))]",
        ] {
            assert!(
                !excluded(attribute),
                "must retain possible production {attribute}"
            );
        }
    }

    #[test]
    fn shared_fixture_files_require_the_actual_nonproduction_module_gate() {
        let root = std::env::temp_dir().join(format!(
            "iteron-census-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("crates/host/src")).unwrap();
        let parent = root.join("crates/host/src/app_server.rs");
        let fixture = "crates/host/src/app_server/fixtures.rs";
        std::fs::write(
            &parent,
            r#"#[cfg(any(test, feature = "test-fixtures"))] mod fixtures;"#,
        )
        .unwrap();
        assert!(super::is_fixture_source(&root, fixture).unwrap());
        for source in [
            "mod fixtures;",
            r#"#[cfg(any(test, feature = "production"))] mod fixtures;"#,
            r#"#[cfg(test)] #[path = "other.rs"] mod fixtures;"#,
            "#[cfg(test)] mod fixtures; mod fixtures;",
        ] {
            std::fs::write(&parent, source).unwrap();
            assert!(
                !super::is_fixture_source(&root, fixture).unwrap(),
                "{source}"
            );
        }
        assert!(!super::is_fixture_source(&root, "crates/other/src/fixtures.rs").unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multiple_cfg_attributes_preserve_conjunction_semantics() {
        assert!(excluded("#[cfg(unix)] #[cfg(test)]"));
        assert!(excluded(
            "#[cfg(any(unix, test))] #[cfg(all(test, feature = \"x\"))]"
        ));
        assert!(!excluded("#[cfg(unix)] #[cfg(any(test, feature = \"x\"))]"));
    }
}
