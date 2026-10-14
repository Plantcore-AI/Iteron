//! One-shot submission adapter constructs canonical public operations.

use crate::{app_server, image_input};

pub(crate) fn build_one_shot_submission(
    task: String,
    images: image_input::ImageAttachments,
) -> Result<iteron_protocol::Op, image_input::ImageInputError> {
    if images.is_empty() {
        // This exact legacy variant is a compatibility contract: adding an empty content-segment
        // wrapper would change every text-only SQ byte.
        Ok(iteron_protocol::Op::UserInput { text: task })
    } else {
        Ok(iteron_protocol::Op::UserInputV2 {
            segments: images.into_content_segments(task)?,
        })
    }
}

/// Admit the complete one-shot SQ before exposing attachment metadata on machine stdout.
///
/// Returning metadata only after the bounded submission queue accepts the operation prevents a
/// validation or backpressure refusal from leaving a plausible-looking partial machine stream.
pub(crate) fn submit_one_shot(
    client: &app_server::AppServerClient,
    task: String,
    images: image_input::ImageAttachments,
) -> anyhow::Result<Vec<(iteron_protocol::ImageMediaType, usize)>> {
    let attachment_metadata = images
        .as_slice()
        .iter()
        .map(|attachment| (attachment.media_type(), attachment.encoded().len()))
        .collect();
    let submission = build_one_shot_submission(task, images)?;
    client.submit(submission)?;
    Ok(attachment_metadata)
}
