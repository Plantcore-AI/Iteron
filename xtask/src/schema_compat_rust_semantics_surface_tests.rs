use super::*;

fn named(source: &str) -> NamedShape {
    let item = syn::parse_str::<syn::ItemStruct>(source).unwrap();
    named_shape(&syn::Item::Struct(item)).unwrap()
}

#[test]
fn retained_field_semantics_bind_types_and_every_serde_attribute() {
    let string = named("struct Wire { value: String }");
    let boolean = named("struct Wire { value: bool }");
    assert_ne!(string.fields["value"], boolean.fields["value"]);

    let defaulted = named("struct Wire { #[serde(default)] value: String }");
    let skipped =
        named("struct Wire { #[serde(skip_serializing_if = \"String::is_empty\")] value: String }");
    let custom = named("struct Wire { #[serde(deserialize_with = \"evil\")] value: String }");
    assert_ne!(string.fields["value"], defaulted.fields["value"]);
    assert_ne!(defaulted.fields["value"], skipped.fields["value"]);
    assert_ne!(skipped.fields["value"], custom.fields["value"]);
}

#[test]
fn enum_semantics_preserve_unit_and_newtype_forms() {
    let unit = syn::parse_str::<syn::ItemEnum>("enum Tag { Add }").unwrap();
    let data = syn::parse_str::<syn::ItemEnum>("enum Tag { Add { evil: String } }").unwrap();
    let unit = enum_shape(&syn::Item::Enum(unit)).unwrap();
    let data = enum_shape(&syn::Item::Enum(data)).unwrap();
    assert!(matches!(unit.variants["add"].fields, VariantFields::Unit));
    assert!(matches!(
        data.variants["add"].fields,
        VariantFields::Named(_)
    ));
}
