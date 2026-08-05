use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn tagged_enum_fields(
    source: &[u8],
    signature: &str,
    tag_field: &str,
    expected_other_variants: usize,
    newtype_fields: &BTreeMap<String, BTreeSet<String>>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let source = std::str::from_utf8(source)?;
    crate::rust_source::tagged_enum_wire_fields(
        source,
        signature,
        tag_field,
        expected_other_variants,
        newtype_fields,
    )
}

pub(super) fn validate_wire_identifier(kind: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("invalid {kind} `{value}`");
    }
    Ok(())
}

pub(super) fn serde_snake_case(value: &str) -> String {
    let mut result = String::new();
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() {
            // This deliberately matches serde_derive's pinned RenameRule::SnakeCase: every
            // uppercase character after the first gets its own underscore, including acronyms.
            if index > 0 {
                result.push('_');
            }
            result.push(character.to_ascii_lowercase());
        } else {
            result.push(character);
        }
    }
    result
}

pub(super) fn named_struct_fields(source: &str, signature: &str) -> Result<BTreeSet<String>> {
    crate::rust_source::named_struct_wire_fields(source, signature)
}

pub(super) fn decimal_constant(source: &[u8], name: &str, ty: &str) -> Result<u32> {
    crate::rust_source::public_decimal_const(source, name, ty)
}

#[cfg(test)]
mod tests {
    use super::super::super::manifest::read_bounded;
    use super::super::{
        EVENT_KIND_SIGNATURE, EVENT_SOURCE, MAX_SOURCE_BYTES, OP_SIGNATURE, OP_SOURCE,
    };
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    #[test]
    fn d13_14_rust_shape_parser_rejects_duplicate_or_ambiguous_contracts() {
        assert_eq!(serde_snake_case("RUNStart"), "r_u_n_start");
        let source = "pub struct Wire {\n    pub version: u32,\n    #[serde(rename = \"wire_value\")]\n    value: String,\n}\n";
        assert_eq!(
            named_struct_fields(source, "pub struct Wire {").unwrap(),
            BTreeSet::from(["version".to_owned(), "wire_value".to_owned()])
        );
        assert!(named_struct_fields("pub struct Wire {}", "pub struct Wire {").is_err());
        assert!(named_struct_fields(&format!("{source}{source}"), "pub struct Wire {").is_err());

        let multiline = "pub struct Wire {\n    #[serde(\n        default,\n        rename = \"wire_value\"\n    )]\n    value: String,\n}\n";
        assert_eq!(
            named_struct_fields(multiline, "pub struct Wire {").unwrap(),
            BTreeSet::from(["wire_value".to_owned()])
        );
        let incomplete = "pub struct Wire {\n    #[serde(\n        rename = \"wire_value\"\n    value: String,\n}\n";
        assert!(named_struct_fields(incomplete, "pub struct Wire {").is_err());
        let flattened = "pub struct Wire {\n    #[serde(flatten)]\n    value: Nested,\n}\n";
        assert!(named_struct_fields(flattened, "pub struct Wire {").is_err());
        let conditional = "pub struct Wire {\n    #[serde(skip_serializing_if = \"Option::is_none\")]\n    value: Option<String>,\n}\n";
        assert_eq!(
            named_struct_fields(conditional, "pub struct Wire {").unwrap(),
            BTreeSet::from(["value".to_owned()])
        );
        let alias =
            "pub struct Wire {\n    #[serde(alias = \"old_value\")]\n    value: String,\n}\n";
        assert!(named_struct_fields(alias, "pub struct Wire {").is_err());
        let separated_container = "#[serde(rename_all = \"camelCase\")]\n\n/// docs\npub struct Wire {\n    value: String,\n}\n";
        assert!(named_struct_fields(separated_container, "pub struct Wire {").is_err());
        let wrapped = "#[cfg_attr(any(), serde(rename_all = \"camelCase\"))]\npub struct Wire {\n    value: String,\n}\n";
        assert!(named_struct_fields(wrapped, "pub struct Wire {").is_err());
        let comment_spoof =
            "pub struct Wire {\n    role: /* Role,\n    content: Vec<Block>, */ Evil,\n}\n";
        assert_eq!(
            named_struct_fields(comment_spoof, "pub struct Wire {").unwrap(),
            BTreeSet::from(["role".to_owned()])
        );
        let attribute_macro = "#[rewrite_wire]\npub struct Wire { value: String }";
        assert!(named_struct_fields(attribute_macro, "pub struct Wire {").is_err());
    }

    #[test]
    fn d13_14_event_kind_source_inventory_is_exhaustive_and_direct() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let source = read_bounded(root, EVENT_SOURCE, MAX_SOURCE_BYTES).unwrap();
        let shapes =
            tagged_enum_fields(&source, EVENT_KIND_SIGNATURE, "kind", 1, &BTreeMap::new()).unwrap();
        // 29 original tags + `effect_done` and `effect_failed`, the two purely additive terminals
        // the universal effect boundary (#16) introduced for non-registry classes, + the
        // `artifact_produced` declaration a run makes about a product it wrote (#78), + the
        // `tunables_snapshot` run-genesis companion (#187). Every one is a purely additive
        // top-level tag under abi.md §4.3(b)2, so none bumped PROTOCOL_VERSION.
        assert_eq!(shapes.len(), 33);
        assert_eq!(
            shapes["notice"],
            BTreeSet::from(["kind".to_owned(), "text".to_owned()])
        );
        assert_eq!(
            shapes["approval"],
            BTreeSet::from([
                "arguments".to_owned(),
                "capability".to_owned(),
                "id".to_owned(),
                "kind".to_owned(),
                "tool".to_owned(),
                "tool_use_id".to_owned(),
                "verdict".to_owned(),
                "workspace".to_owned(),
            ])
        );
        assert!(shapes.contains_key("tunables_snapshot"));
        assert!(shapes.contains_key("subagent_finished_v2"));
        assert!(!shapes.contains_key("unknown"));
    }

    #[test]
    fn d13_14_protocol_op_source_inventory_is_exhaustive_and_direct() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let source = read_bounded(root, OP_SOURCE, MAX_SOURCE_BYTES).unwrap();
        let shapes = tagged_enum_fields(&source, OP_SIGNATURE, "op", 1, &BTreeMap::new()).unwrap();
        // Six original tags plus `user_input_v3`, the file-attachment tag (UX-6). Additive: it
        // declares its own compatibility surface and fixtures, and every tag below is unchanged.
        assert_eq!(shapes.len(), 7);
        assert_eq!(
            shapes["user_input"],
            BTreeSet::from(["op".to_owned(), "text".to_owned()])
        );
        assert_eq!(
            shapes["user_input_v2"],
            BTreeSet::from(["op".to_owned(), "segments".to_owned()])
        );
        assert_eq!(
            shapes["user_input_v3"],
            BTreeSet::from([
                "op".to_owned(),
                "text".to_owned(),
                "images".to_owned(),
                "files".to_owned(),
            ])
        );
        assert_eq!(
            shapes["approval_response"],
            BTreeSet::from([
                "approved".to_owned(),
                "id".to_owned(),
                "op".to_owned(),
                "remember".to_owned(),
            ])
        );
        assert!(shapes.contains_key("steer"));
        assert!(shapes.contains_key("interrupt"));
        assert!(shapes.contains_key("drain"));
        assert!(!shapes.contains_key("unknown"));
    }

    #[test]
    fn d13_14_tagged_parser_expands_only_known_newtypes_and_counts_other() {
        let source = b"#[serde(tag = \"type\", rename_all = \"snake_case\")]\npub enum Wire {\n    Named { value: String },\n    Wrapped(Known),\n}\n";
        let newtypes = BTreeMap::from([(
            "Known".to_owned(),
            BTreeSet::from(["left".to_owned(), "right".to_owned()]),
        )]);
        let shapes = tagged_enum_fields(source, "pub enum Wire {", "type", 0, &newtypes).unwrap();
        assert_eq!(
            shapes["wrapped"],
            BTreeSet::from(["left".to_owned(), "right".to_owned(), "type".to_owned(),])
        );
        assert!(tagged_enum_fields(source, "pub enum Wire {", "type", 1, &newtypes).is_err());

        let unknown = source
            .as_slice()
            .windows(b"Known".len())
            .position(|window| window == b"Known")
            .unwrap();
        let mut unknown_source = source.to_vec();
        unknown_source.splice(unknown..unknown + b"Known".len(), b"Other".iter().copied());
        assert!(
            tagged_enum_fields(&unknown_source, "pub enum Wire {", "type", 0, &newtypes,).is_err()
        );

        let sentinel = b"#[serde(tag = \"type\", rename_all = \"snake_case\")]\npub enum Wire {\n    Named,\n    #[serde(other)]\n    Unknown,\n}\n";
        assert!(
            tagged_enum_fields(sentinel, "pub enum Wire {", "type", 1, &BTreeMap::new(),).is_ok()
        );
        assert!(
            tagged_enum_fields(sentinel, "pub enum Wire {", "type", 0, &BTreeMap::new(),).is_err()
        );
    }
}
