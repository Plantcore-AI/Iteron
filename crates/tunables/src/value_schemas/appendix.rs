use crate::ValueSchema;

mod first;
mod second;
mod third;

pub(super) const fn value_schema(ordinal: u16) -> ValueSchema {
    match ordinal {
        86..=110 => first::VALUE_SCHEMAS[ordinal as usize - 86],
        111..=135 => second::VALUE_SCHEMAS[ordinal as usize - 111],
        136..=160 => third::VALUE_SCHEMAS[ordinal as usize - 136],
        _ => panic!("appendix tunable ordinal is outside 86..=160"),
    }
}
