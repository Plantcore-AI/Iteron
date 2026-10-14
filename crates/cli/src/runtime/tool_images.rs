//! Post-terminal private pixels and model projection. No model/input can mint the receipt.
use super::{Agent, tool_execution_journal::ToolTerminalReceipt};
#[cfg(test)]
use iteron_protocol::Block;
use iteron_tools::CapturedToolImage;

pub(super) struct PendingToolImageProjection {
    pub(super) receipt: ToolTerminalReceipt,
    pub(super) images: Vec<CapturedToolImage>,
}

impl Agent {
    #[cfg(test)]
    pub(super) fn project_captured_tool_images(
        &mut self,
        receipt: &ToolTerminalReceipt,
        images: &[CapturedToolImage],
    ) -> Vec<Block> {
        self.tool_image_projection(receipt.turn())
            .project_captured_tool_images(receipt, images)
    }
}
