use anyhow::Result;
use quote::ToTokens;

pub(super) fn attributes(attributes: &[syn::Attribute]) -> Vec<String> {
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("serde"))
        .map(|attribute| attribute.to_token_stream().to_string())
        .collect()
}

pub(super) fn rename(attributes: &[syn::Attribute]) -> Result<Option<String>> {
    let mut rename = None;
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("serde"))
    {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                let value: syn::LitStr = meta.value()?.parse()?;
                if rename.replace(value.value()).is_some() {
                    return Err(meta.error("serde rename is repeated"));
                }
            } else if meta.input.peek(syn::Token![=]) {
                let _: syn::Expr = meta.value()?.parse()?;
            }
            Ok(())
        })?;
    }
    Ok(rename)
}

pub(super) fn flag(attributes: &[syn::Attribute], expected: &str) -> Result<bool> {
    let mut found = false;
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("serde"))
    {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident(expected) {
                found = true;
            } else if meta.input.peek(syn::Token![=]) {
                let _: syn::Expr = meta.value()?.parse()?;
            }
            Ok(())
        })?;
    }
    Ok(found)
}

pub(super) fn snake_case(value: &str) -> String {
    let mut output = String::new();
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    #[test]
    fn serde_acronym_rename_matches_derive_rule() {
        assert_eq!(super::snake_case("RUNStart"), "r_u_n_start");
    }
}
