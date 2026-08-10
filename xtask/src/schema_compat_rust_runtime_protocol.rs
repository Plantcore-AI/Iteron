use super::{parse, require_function, require_method};
use anyhow::Result;
use std::path::Path;

pub(super) fn validate(root: &Path) -> Result<()> {
    let file = parse(root, "crates/protocol/src/wire.rs")?;
    validate_file(&file)
}

fn validate_file(file: &syn::File) -> Result<()> {
    require_function(
        file,
        "require_current",
        r#"fn require_current(actual: u32) -> Result<(), ProtocolVersionError> {
            if actual == PROTOCOL_VERSION {
                Ok(())
            } else {
                Err(ProtocolVersionError { expected: PROTOCOL_VERSION, actual, })
            }
        }"#,
    )?;
    require_method(
        file,
        "SqEnvelope",
        "current",
        r#"pub fn current(op: Op) -> Self {
            Self {
                protocol_version: PROTOCOL_VERSION,
                submission_id: SubmissionId::default(),
                op,
            }
        }"#,
    )?;
    require_method(
        file,
        "SqEnvelope",
        "into_current_identified",
        r#"pub fn into_current_identified(self) -> Result<(SubmissionId, Op), ProtocolVersionError> {
            require_current(self.protocol_version)?;
            Ok((self.submission_id, self.op))
        }"#,
    )?;
    require_method(
        file,
        "SqEnvelope",
        "into_current",
        r#"pub fn into_current(self) -> Result<Op, ProtocolVersionError> {
            require_current(self.protocol_version)?;
            Ok(self.op)
        }"#,
    )?;
    require_method(
        file,
        "EqEnvelope",
        "current",
        r#"pub fn current(event: Event) -> Self {
            Self { protocol_version: PROTOCOL_VERSION, event, }
        }"#,
    )?;
    require_method(
        file,
        "EqEnvelope",
        "into_current",
        r#"pub fn into_current(self) -> Result<Event, ProtocolVersionError> {
            require_current(self.protocol_version)?;
            Ok(self.event)
        }"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_stamp_and_admission_witness_rejects_bypasses() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let source = std::fs::read_to_string(root.join("crates/protocol/src/wire.rs")).unwrap();
        let file = syn::parse_file(&source).unwrap();
        validate_file(&file).unwrap();

        let bypass = source.replacen("if actual == PROTOCOL_VERSION", "if true", 1);
        assert!(validate_file(&syn::parse_file(&bypass).unwrap()).is_err());
        let wrong_stamp = source.replacen(
            "protocol_version: PROTOCOL_VERSION,",
            "protocol_version: 0,",
            1,
        );
        assert!(validate_file(&syn::parse_file(&wrong_stamp).unwrap()).is_err());
    }
}
