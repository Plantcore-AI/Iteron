#[path = "rust_source_attrs.rs"]
mod attrs;
#[path = "rust_source_constants.rs"]
mod constants;
#[path = "rust_source_expected.rs"]
mod expected;
#[path = "rust_source_items.rs"]
mod items;

pub(crate) use constants::{
    public_decimal_const, public_decimal_slice_const, public_string_array_const,
    public_string_u32_tuple_slice_const,
};
pub(crate) use items::{
    SerdeAuthority, enum_variant_names, named_struct_wire_fields, require_serde_authority,
    require_serde_container_flag, tagged_enum_wire_fields, unit_enum_variant_names,
};
