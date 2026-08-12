//! Decode the executable MIME-to-inspector table from the immutable run checkpoint.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use crate::image_input::{
    BinaryMediaInspectionPolicy, MultimodalDecodeEnvelope, UnknownMimePolicy,
};
use iteron_tunables::{ResolutionValue, RuntimeGetterId};
use std::collections::BTreeMap;

pub(crate) fn decode(
    view: &EffectiveTunablesView,
) -> Result<BinaryMediaInspectionPolicy, EffectiveBinaryMediaError> {
    view.with_getter(RuntimeGetterId::EffectiveBinaryMedia, || decode_inner(view))
}

fn decode_inner(
    view: &EffectiveTunablesView,
) -> Result<BinaryMediaInspectionPolicy, EffectiveBinaryMediaError> {
    let family = "binary_media_inspection_routing";
    let fields = view.object(family)?;
    let routes = match fields.get("mime_routes") {
        Some(ResolutionValue::Map { entries }) => entries
            .iter()
            .map(|(mime, value)| {
                let inspector = match value {
                    ResolutionValue::Enum { value } | ResolutionValue::Text { value } => value,
                    _ => return Err(EffectiveBinaryMediaError::WrongType("mime_routes")),
                };
                Ok((mime.clone(), inspector.clone()))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?,
        Some(_) => return Err(EffectiveBinaryMediaError::WrongType("mime_routes")),
        None => return Err(EffectiveBinaryMediaError::Missing("mime_routes")),
    };
    let unknown_mime = match enum_field(fields, "unknown_mime")? {
        "reject" => UnknownMimePolicy::Reject,
        "metadata_only" => UnknownMimePolicy::MetadataOnly,
        value => return Err(EffectiveBinaryMediaError::UnknownEnum(value.to_owned())),
    };
    BinaryMediaInspectionPolicy::new(
        routes,
        unknown_mime,
        usize_field(fields, "max_input_bytes")?,
    )
    .map_err(EffectiveBinaryMediaError::InvalidOwner)
}

pub(crate) fn decode_multimodal(
    view: &EffectiveTunablesView,
) -> Result<MultimodalDecodeEnvelope, EffectiveBinaryMediaError> {
    view.with_getter(RuntimeGetterId::EffectiveInputAdmission, || {
        decode_multimodal_inner(view)
    })
}

fn decode_multimodal_inner(
    view: &EffectiveTunablesView,
) -> Result<MultimodalDecodeEnvelope, EffectiveBinaryMediaError> {
    let fields = view.object("multimodal_input_admission_decode_envelope")?;
    MultimodalDecodeEnvelope::try_new(
        usize_field(fields, "max_images")?,
        usize_field(fields, "per_image_raw_bytes")?,
        usize_field(fields, "aggregate_raw_bytes")?,
        u32_field(fields, "max_dimension")?,
        u32_field(fields, "max_frames")?,
    )
    .map_err(EffectiveBinaryMediaError::InvalidOwner)
}

fn usize_field(
    fields: &BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<usize, EffectiveBinaryMediaError> {
    match fields.get(field) {
        Some(ResolutionValue::Integer { value }) => {
            usize::try_from(*value).map_err(|_| EffectiveBinaryMediaError::Range(field))
        }
        Some(_) => Err(EffectiveBinaryMediaError::WrongType(field)),
        None => Err(EffectiveBinaryMediaError::Missing(field)),
    }
}

fn u32_field(
    fields: &BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<u32, EffectiveBinaryMediaError> {
    match fields.get(field) {
        Some(ResolutionValue::Integer { value }) => {
            u32::try_from(*value).map_err(|_| EffectiveBinaryMediaError::Range(field))
        }
        Some(_) => Err(EffectiveBinaryMediaError::WrongType(field)),
        None => Err(EffectiveBinaryMediaError::Missing(field)),
    }
}

fn enum_field<'a>(
    fields: &'a BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<&'a str, EffectiveBinaryMediaError> {
    match fields.get(field) {
        Some(ResolutionValue::Enum { value }) => Ok(value),
        Some(_) => Err(EffectiveBinaryMediaError::WrongType(field)),
        None => Err(EffectiveBinaryMediaError::Missing(field)),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveBinaryMediaError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error("binary media policy is missing `{0}`")]
    Missing(&'static str),
    #[error("binary media policy field `{0}` has the wrong type")]
    WrongType(&'static str),
    #[error("binary media policy field `{0}` is outside the runtime range")]
    Range(&'static str),
    #[error("binary media policy contains unknown enum `{0}`")]
    UnknownEnum(String),
    #[error("invalid binary media inspection owner: {0}")]
    InvalidOwner(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multimodal_value(max_dimension: i64) -> ResolutionValue {
        ResolutionValue::Object {
            fields: [
                ("max_images".into(), ResolutionValue::Integer { value: 8 }),
                (
                    "per_image_raw_bytes".into(),
                    ResolutionValue::Integer { value: 6_291_456 },
                ),
                (
                    "aggregate_raw_bytes".into(),
                    ResolutionValue::Integer { value: 25_165_824 },
                ),
                (
                    "max_dimension".into(),
                    ResolutionValue::Integer {
                        value: max_dimension,
                    },
                ),
                ("max_frames".into(), ResolutionValue::Integer { value: 256 }),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[test]
    fn multimodal_checkpoint_decoder_preserves_narrowing_and_rejects_safety_drift() {
        let narrowed = EffectiveTunablesView::from_test_values(BTreeMap::from([(
            "multimodal_input_admission_decode_envelope".into(),
            multimodal_value(1),
        )]));
        assert_eq!(decode_multimodal(&narrowed).unwrap().max_dimension, 1);

        let widened = EffectiveTunablesView::from_test_values(BTreeMap::from([(
            "multimodal_input_admission_decode_envelope".into(),
            multimodal_value(8_193),
        )]));
        assert!(matches!(
            decode_multimodal(&widened),
            Err(EffectiveBinaryMediaError::InvalidOwner(_))
        ));
    }
}
