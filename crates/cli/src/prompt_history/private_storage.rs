use super::{MAX_ENTRIES, PersistedState, PrivateContentHandle, State, Store, bound_and_scrub};
use core_protocol::Seq;

impl Store {
    pub(super) fn store_text(
        &self,
        index: usize,
        text: &str,
    ) -> anyhow::Result<PrivateContentHandle> {
        Ok(self
            .private
            .put(Seq(u64::try_from(index)?), text.as_bytes())?)
    }

    pub(super) fn hydrate(&self, state: PersistedState) -> anyhow::Result<State> {
        if state.history.len() > MAX_ENTRIES {
            anyhow::bail!("prompt history exceeds its {MAX_ENTRIES}-entry bound");
        }
        self.reconcile(&state)?;
        let history = state
            .history
            .iter()
            .enumerate()
            .map(|(index, handle)| self.load_text(index, handle))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let draft = state
            .draft
            .as_ref()
            .map(|handle| self.load_text(MAX_ENTRIES, handle))
            .transpose()?;
        Ok(bound_and_scrub(State::new(history, draft)))
    }

    fn load_text(&self, index: usize, handle: &PrivateContentHandle) -> anyhow::Result<String> {
        let bytes = self.private.read_at(Seq(u64::try_from(index)?), handle)?;
        Ok(String::from_utf8(bytes)?)
    }

    pub(super) fn reconcile(&self, state: &PersistedState) -> anyhow::Result<()> {
        let mut desired = state
            .history
            .iter()
            .enumerate()
            .map(|(index, handle)| Ok((Seq(u64::try_from(index)?), handle.digest.clone())))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if let Some(draft) = &state.draft {
            desired.push((Seq(u64::try_from(MAX_ENTRIES)?), draft.digest.clone()));
        }
        self.private.retain(&desired)?;
        Ok(())
    }
}
