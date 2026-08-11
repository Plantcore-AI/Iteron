//! Decode the resident App Server's bounded queue owner from an immutable checkpoint.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use crate::app_server::{AppServerQueuePolicy, AuthoritativeOverflow, CosmeticOverflow};
use iteron_tunables::{ResolutionValue, RuntimeGetterId};
use std::collections::BTreeMap;

pub(crate) fn decode(
    view: &EffectiveTunablesView,
) -> Result<AppServerQueuePolicy, EffectiveAppServerError> {
    view.with_getter(RuntimeGetterId::EffectiveAppServer, || decode_inner(view))
}

fn decode_inner(
    view: &EffectiveTunablesView,
) -> Result<AppServerQueuePolicy, EffectiveAppServerError> {
    let fields = view.object("app_server_sq_eq_backpressure")?;
    AppServerQueuePolicy::new(
        usize_field(fields, "submission_entries")?,
        usize_field(fields, "submission_bytes")?,
        usize_field(fields, "event_entries")?,
        match enum_field(fields, "cosmetic_overflow")? {
            "drop" => CosmeticOverflow::Drop,
            "coalesce" => CosmeticOverflow::Coalesce,
            value => return Err(EffectiveAppServerError::UnknownEnum(value.to_owned())),
        },
        match enum_field(fields, "authoritative_overflow")? {
            "wait" => AuthoritativeOverflow::Wait,
            "reject" => AuthoritativeOverflow::Reject,
            value => return Err(EffectiveAppServerError::UnknownEnum(value.to_owned())),
        },
    )
    .map_err(EffectiveAppServerError::InvalidOwner)
}

fn usize_field(
    fields: &BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<usize, EffectiveAppServerError> {
    match fields.get(field) {
        Some(ResolutionValue::Integer { value }) => {
            usize::try_from(*value).map_err(|_| EffectiveAppServerError::Range(field))
        }
        Some(_) => Err(EffectiveAppServerError::WrongType(field)),
        None => Err(EffectiveAppServerError::Missing(field)),
    }
}

fn enum_field<'a>(
    fields: &'a BTreeMap<String, ResolutionValue>,
    field: &'static str,
) -> Result<&'a str, EffectiveAppServerError> {
    match fields.get(field) {
        Some(ResolutionValue::Enum { value }) => Ok(value),
        Some(_) => Err(EffectiveAppServerError::WrongType(field)),
        None => Err(EffectiveAppServerError::Missing(field)),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveAppServerError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error("app-server queue policy is missing `{0}`")]
    Missing(&'static str),
    #[error("app-server queue policy field `{0}` has the wrong type")]
    WrongType(&'static str),
    #[error("app-server queue policy field `{0}` is outside the runtime range")]
    Range(&'static str),
    #[error("app-server queue policy contains unknown enum `{0}`")]
    UnknownEnum(String),
    #[error("invalid app-server queue owner: {0}")]
    InvalidOwner(&'static str),
}
