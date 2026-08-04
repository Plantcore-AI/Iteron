use crate::ValueSchema;

mod first;
mod second;
mod third;

pub(super) const fn value_schema(ordinal: u16) -> ValueSchema {
    match ordinal {
        1..=30 => first::VALUE_SCHEMAS[ordinal as usize - 1],
        31..=60 => second::VALUE_SCHEMAS[ordinal as usize - 31],
        61..=85 => third::VALUE_SCHEMAS[ordinal as usize - 61],
        _ => panic!("current tunable ordinal is outside 1..=85"),
    }
}
