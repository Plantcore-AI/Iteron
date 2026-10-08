//! Shared production eligibility for the parameter catalog and source census. Platform/feature
//! predicates stay symbolic; only configurations proven absent with `test = false` are excluded.
use syn::parse::Parser as _;

pub(crate) fn has_cfg_test(attributes: &[syn::Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| excludes_production(&attribute.meta, 0))
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
    fn multiple_cfg_attributes_preserve_conjunction_semantics() {
        assert!(excluded("#[cfg(unix)] #[cfg(test)]"));
        assert!(excluded(
            "#[cfg(any(unix, test))] #[cfg(all(test, feature = \"x\"))]"
        ));
        assert!(!excluded("#[cfg(unix)] #[cfg(any(test, feature = \"x\"))]"));
    }
}
