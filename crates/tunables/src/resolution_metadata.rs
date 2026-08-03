use crate::{ActivationSpec, DefaultSpec, SourceSpec};

macro_rules! resolver_id {
    ($id:literal) => {
        concat!("core://tunables/resolvers/", $id, "-v1")
    };
}

macro_rules! catalog_id {
    ($id:literal) => {
        concat!("core://tunables/catalogs/", $id, "-v1")
    };
}

macro_rules! literal_default {
    ($value:expr) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Literal,
            resolver: crate::DefaultResolver::Literal,
            requirement: crate::DefaultValueRequirement::Optional,
            value: Some($value),
        }
    };
}

macro_rules! derived_default {
    ($id:literal) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Derived,
            resolver: crate::DefaultResolver::Builtin {
                resolver_id: resolver_id!($id),
            },
            requirement: crate::DefaultValueRequirement::Optional,
            value: None,
        }
    };
}

macro_rules! derived_default_with_value {
    ($id:literal, $value:expr) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Derived,
            resolver: crate::DefaultResolver::Builtin {
                resolver_id: resolver_id!($id),
            },
            requirement: crate::DefaultValueRequirement::Optional,
            value: Some($value),
        }
    };
}

macro_rules! catalog_default {
    ($id:literal) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Derived,
            resolver: crate::DefaultResolver::GovernedCatalog {
                catalog_id: catalog_id!($id),
            },
            requirement: crate::DefaultValueRequirement::Optional,
            value: None,
        }
    };
}

macro_rules! operator_default {
    ($id:literal) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Dynamic,
            resolver: crate::DefaultResolver::Operator {
                input_id: concat!("core://tunables/operator-inputs/", $id, "-v1"),
            },
            requirement: crate::DefaultValueRequirement::Required,
            value: None,
        }
    };
}

macro_rules! model_default {
    ($field:literal) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Dynamic,
            resolver: crate::DefaultResolver::ModelMetadata { field: $field },
            requirement: crate::DefaultValueRequirement::Optional,
            value: None,
        }
    };
}

macro_rules! model_default_with_value {
    ($field:literal, $value:expr) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Dynamic,
            resolver: crate::DefaultResolver::ModelMetadata { field: $field },
            requirement: crate::DefaultValueRequirement::Optional,
            value: Some($value),
        }
    };
}

macro_rules! provider_default {
    ($capability:literal) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Dynamic,
            resolver: crate::DefaultResolver::ProviderCapability {
                capability: $capability,
            },
            requirement: crate::DefaultValueRequirement::Optional,
            value: None,
        }
    };
}

macro_rules! transport_default {
    ($field:literal) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Dynamic,
            resolver: crate::DefaultResolver::Transport { field: $field },
            requirement: crate::DefaultValueRequirement::Optional,
            value: None,
        }
    };
}

macro_rules! observation_default {
    ($field:literal) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Derived,
            resolver: crate::DefaultResolver::RuntimeObservation { field: $field },
            requirement: crate::DefaultValueRequirement::Optional,
            value: None,
        }
    };
}

macro_rules! dynamic_observation_default {
    ($field:literal) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Dynamic,
            resolver: crate::DefaultResolver::RuntimeObservation { field: $field },
            requirement: crate::DefaultValueRequirement::Optional,
            value: None,
        }
    };
}

macro_rules! dynamic_observation_default_with_value {
    ($field:literal, $value:expr) => {
        crate::DefaultSpec {
            kind: crate::DefaultKind::Dynamic,
            resolver: crate::DefaultResolver::RuntimeObservation { field: $field },
            requirement: crate::DefaultValueRequirement::Optional,
            value: Some($value),
        }
    };
}

macro_rules! boolean_value {
    ($value:expr) => {
        crate::TunableValue::Boolean { value: $value }
    };
}

macro_rules! integer_value {
    ($value:expr) => {
        crate::TunableValue::Integer { value: $value }
    };
}

macro_rules! decimal_value {
    ($coefficient:expr, $scale:expr) => {
        crate::TunableValue::Decimal {
            value: crate::DecimalValue {
                coefficient: $coefficient,
                scale: $scale,
            },
        }
    };
}

macro_rules! enum_value {
    ($value:literal) => {
        crate::TunableValue::Enum { value: $value }
    };
}

macro_rules! text_value {
    ($value:literal) => {
        crate::TunableValue::Text { value: $value }
    };
}

macro_rules! list_value {
    ($($value:expr),* $(,)?) => {
        crate::TunableValue::List {
            items: &[$($value),*],
        }
    };
}

macro_rules! map_value {
    ($($name:literal => $value:expr),* $(,)?) => {
        crate::TunableValue::Map {
            entries: &[$(
                crate::TunableValueField { name: $name, value: $value },
            )*],
        }
    };
}

macro_rules! object_value {
    ($($name:literal => $value:expr),+ $(,)?) => {
        crate::TunableValue::Object {
            fields: &[$(
                crate::TunableValueField { name: $name, value: $value },
            )+],
        }
    };
}

mod appendix;
mod current;
mod provenance;

pub(crate) const fn default_spec(ordinal: u16) -> DefaultSpec {
    if ordinal <= 85 {
        current::DEFAULTS[ordinal as usize - 1]
    } else {
        appendix::DEFAULTS[ordinal as usize - 86]
    }
}

pub(crate) const fn source_spec(ordinal: u16) -> SourceSpec {
    provenance::SOURCES[ordinal as usize - 1]
}

pub(crate) const fn activation_spec(ordinal: u16) -> ActivationSpec {
    provenance::ACTIVATIONS[ordinal as usize - 1]
}
