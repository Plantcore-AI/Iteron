//! Physical submission lifetime: retained private image references and exactly one deadline
//! lease survive every model/tool turn and release on return, staging failure or future drop.
use super::KernelError;
use super::execution_deadline::{DeadlineLease, ExecutionDeadlineOwner};
use super::private_attachments::InvocationImages;
use iteron_protocol::{ImageContent, RunId, TenantId, TurnId};
use std::path::Path;

pub(super) struct InvocationScope<'a> {
    pub(super) runs: &'a Path,
    pub(super) tenant: TenantId,
    pub(super) run: RunId,
    pub(super) turn: TurnId,
    pub(super) wall_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::{InvocationScope, SubmissionInvocation};
    use crate::runtime::execution_deadline::ExecutionDeadlineOwner;
    use iteron_protocol::{ImageContent, ImageMediaType, RunId, TenantId, TurnId};

    #[test]
    fn actual_private_image_store_refusal_releases_the_new_invocation_clock() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "iteron-invocation-stage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runs = root.join("not-a-directory");
        std::fs::write(&runs, b"physical store refusal").unwrap();
        let mut deadlines = ExecutionDeadlineOwner::default();
        let image = ImageContent::new(ImageMediaType::Png, "AAAA").unwrap();
        assert!(
            SubmissionInvocation::stage(
                InvocationScope {
                    runs: &runs,
                    tenant: TenantId::default(),
                    run: RunId("actual".into()),
                    turn: TurnId(1),
                    wall_secs: 30,
                },
                &mut deadlines,
                &[image]
            )
            .is_err()
        );
        assert_eq!(deadlines.current(), None);
        assert_eq!(std::fs::read(&runs).unwrap(), b"physical store refusal");
        std::fs::remove_dir_all(root).unwrap();
    }
}
pub(super) struct SubmissionInvocation {
    images: InvocationImages,
    deadline: Option<DeadlineLease>,
}
impl SubmissionInvocation {
    pub(super) fn stage(
        scope: InvocationScope<'_>,
        deadlines: &mut ExecutionDeadlineOwner,
        images: &[ImageContent],
    ) -> Result<Self, KernelError> {
        let deadline = deadlines.begin_invocation(scope.wall_secs)?;
        let images =
            InvocationImages::stage(scope.runs, scope.tenant, scope.run, scope.turn, images)
                .map_err(|_| {
                    KernelError::ContextResolution("private image attachment storage failed".into())
                })?;
        Ok(Self {
            images,
            deadline: Some(deadline),
        })
    }
    pub(super) fn images(&self) -> &[ImageContent] {
        self.images.images()
    }
    /// Stop hooks/post-answer maintenance follow the original contract and run after the owned
    /// invocation deadline is released. Inherited parent deadlines are unaffected.
    pub(super) fn release_deadline(&mut self) {
        self.deadline.take();
    }
}
