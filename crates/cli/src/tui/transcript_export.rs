//! Bounded transcript rendering. Native destination authority belongs to the host export owner.
use crate::block;
pub(crate) use crate::client_effects::{CollisionPolicy, MAX_TRANSCRIPT_EXPORT_BYTES};
use std::collections::HashSet;
use std::sync::Arc;

pub(crate) fn body(
    blocks: &[Arc<block::Block>],
    selected_ids: Option<&[u64]>,
) -> Result<Vec<u8>, String> {
    let selected = selected_ids.map(|ids| ids.iter().copied().collect::<HashSet<_>>());
    let mut body = String::from("# Iteron transcript\n\n");
    for block in blocks {
        if selected
            .as_ref()
            .is_some_and(|selected| !selected.contains(&block.id))
        {
            continue;
        }
        let text = block.to_text();
        if body.len().saturating_add(text.len()).saturating_add(1)
            > iteron_tunables::param_integer(
                "cli.tui.transcript_export.max_transcript_export_bytes",
                MAX_TRANSCRIPT_EXPORT_BYTES,
            )
            .min(MAX_TRANSCRIPT_EXPORT_BYTES)
        {
            return Err("transcript export exceeds the 8 MiB limit".into());
        }
        body.push_str(&text);
        body.push('\n');
    }
    Ok(body.into_bytes())
}
