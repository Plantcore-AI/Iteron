//! Explicit high-assurance profile. Host bootstrap alone enrolls human keys and creates the scope.
//! The default runtime holds no owner and makes no audit/verifier/authentication calls here.
mod journal;
mod owner;
mod profile;
mod types;
pub(crate) use journal::HighAssuranceJournal;
pub(crate) use owner::{HighAssuranceAdmission, HighAssuranceOwner};
pub(crate) use profile::load_operator_profile;
pub(crate) use types::{
    HighAssuranceCommandV1, HighAssurancePolicy, HighAssuranceProfileV1, HighAssuranceScope,
    HighAssuranceViewV1, SignedHumanApprovalV1,
};
#[cfg(test)]
mod tests;
