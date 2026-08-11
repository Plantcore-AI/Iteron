use super::{
    LineageState, MAX_ENTRIES, MAX_ENTRY_BYTES, PersistedEntry, PersistedState, PreparedState,
    SourceBinding, State, Store, bound_and_scrub,
};
use iteron_protocol::{RunId, Seq};
use iteron_record::{
    ContentStoreError, PrivateContentClass, PrivateContentDerivativeStore, PrivateContentNamespace,
    PrivateContentRetention, PrivateContentSource,
};
use std::collections::{BTreeMap, VecDeque};

impl Store {
    fn available_record_sources(
        &self,
        active_run: &RunId,
    ) -> anyhow::Result<BTreeMap<String, PrivateContentSource>> {
        match iteron_record::content_store::private_content_sources_for_run(
            &self.runs_dir,
            &self.tenant,
            active_run,
        ) {
            Ok(sources) => Ok(sources
                .into_iter()
                .map(|source| (source.digest.as_str().to_owned(), source))
                .collect()),
            Err(ContentStoreError::Revoked { .. } | ContentStoreError::Unresolved { .. }) => {
                Ok(BTreeMap::new())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn source_store(&self, owner: RunId) -> anyhow::Result<PrivateContentDerivativeStore> {
        Ok(PrivateContentDerivativeStore::open_registered(
            self.runs_dir.clone(),
            self.tenant.clone(),
            owner,
            PrivateContentNamespace::PromptHistory,
            PrivateContentClass::Transcript,
            PrivateContentRetention::ExplicitRevocation,
            MAX_ENTRY_BYTES,
        )?)
    }

    fn reusable_sources(&self) -> anyhow::Result<BTreeMap<String, VecDeque<SourceBinding>>> {
        let state = self
            .lineage
            .lock()
            .map_err(|_| anyhow::anyhow!("prompt history lineage state is poisoned"))?
            .clone();
        let mut reusable = BTreeMap::<String, VecDeque<SourceBinding>>::new();
        for (text, source) in state.history.into_iter().chain(state.draft) {
            reusable.entry(text).or_default().push_back(source);
        }
        Ok(reusable)
    }

    fn bind_source(
        &self,
        active_run: &RunId,
        index: usize,
        stored_text: &str,
        source_text: &str,
        record_sources: &BTreeMap<String, PrivateContentSource>,
        reusable: &mut BTreeMap<String, VecDeque<SourceBinding>>,
    ) -> anyhow::Result<SourceBinding> {
        let digest = iteron_record::content_store::private_content_digest(source_text.as_bytes());
        if let Some(existing) = reusable.get_mut(stored_text).and_then(VecDeque::pop_front) {
            if existing.synthetic_seq.is_some()
                && existing.source.owner == *active_run
                && let Some(source) = record_sources.get(existing.source.digest.as_str())
            {
                return Ok(SourceBinding {
                    source: source.clone(),
                    synthetic_seq: None,
                });
            }
            return Ok(existing);
        }
        if let Some(source) = record_sources.get(digest.as_str()) {
            return Ok(SourceBinding {
                source: source.clone(),
                synthetic_seq: None,
            });
        }

        // Drafts and keystroke snapshots can precede the journal append. Store the pre-sanitize,
        // scrubbed source as an active-run-scoped root, then bind the visible history entry to it.
        // A normal-exit flush prefers the now-durable RecordField source above and replaces this
        // temporary lineage after the append has landed.
        let source_store = self.source_store(active_run.clone())?;
        let slot = u64::try_from(index)?;
        if slot > u8::MAX.into() {
            anyhow::bail!("prompt history synthetic source slot exceeds its fixed bound");
        }
        let seq = Seq(self.source_seq_base | slot);
        let handle = source_store.put(seq, source_text.as_bytes())?;
        Ok(SourceBinding {
            source: PrivateContentSource {
                owner: active_run.clone(),
                digest: handle.digest,
            },
            synthetic_seq: Some(seq.0),
        })
    }

    fn stage_entry(
        &self,
        index: usize,
        text: &str,
        source: SourceBinding,
    ) -> anyhow::Result<PersistedEntry> {
        let seq = Seq(u64::try_from(index)?);
        let handle = self
            .private
            .put_derived(seq, text.as_bytes(), &[source.source.clone()])?;
        Ok(PersistedEntry { handle, source })
    }

    pub(super) fn stage_entries(
        &self,
        prepared: &PreparedState,
        active_run: &RunId,
    ) -> anyhow::Result<(Vec<PersistedEntry>, Option<PersistedEntry>)> {
        let record_sources = self.available_record_sources(active_run)?;
        let mut reusable = self.reusable_sources()?;
        let mut history = Vec::with_capacity(prepared.state.history.len());
        for (index, (text, source_text)) in prepared
            .state
            .history
            .iter()
            .zip(&prepared.history_sources)
            .enumerate()
        {
            let source = self.bind_source(
                active_run,
                index,
                text,
                source_text,
                &record_sources,
                &mut reusable,
            )?;
            history.push(self.stage_entry(index, text, source)?);
        }
        let draft = prepared
            .state
            .draft
            .as_deref()
            .zip(prepared.draft_source.as_deref())
            .map(|(text, source_text)| {
                let source = self.bind_source(
                    active_run,
                    MAX_ENTRIES,
                    text,
                    source_text,
                    &record_sources,
                    &mut reusable,
                )?;
                self.stage_entry(MAX_ENTRIES, text, source)
            })
            .transpose()?;
        Ok((history, draft))
    }

    pub(super) fn hydrate(
        &self,
        mut state: PersistedState,
        active_run: &RunId,
    ) -> anyhow::Result<State> {
        if state.history.len() > MAX_ENTRIES {
            anyhow::bail!("prompt history exceeds its {MAX_ENTRIES}-entry bound");
        }
        // Recover the crash boundary before any plaintext can be hydrated: the background writer
        // published a synthetic source, the Message became durable, then the process exited before
        // its final flush. `sources_at` proves the derivative's durable lineage and the RecordField
        // inventory proves the actual source exists. Release the now-redundant synthetic reference
        // first; if publication then crashes, the old manifest can repeat this idempotent rebound
        // from the still-live RecordField rather than serving through stale synthetic authority.
        let record_sources = self.available_record_sources(active_run)?;
        let mut rebound_owners = BTreeMap::<String, RunId>::new();
        for (index, entry) in state
            .history
            .iter_mut()
            .enumerate()
            .chain(state.draft.iter_mut().map(|entry| (MAX_ENTRIES, entry)))
        {
            if entry.source.synthetic_seq.is_none() || entry.source.source.owner != *active_run {
                continue;
            }
            let Some(source) = record_sources.get(entry.source.source.digest.as_str()) else {
                continue;
            };
            match self
                .private
                .sources_at(Seq(u64::try_from(index)?), &entry.handle)
            {
                Ok(durable) if durable == [source.clone()] => {}
                Ok(_) => anyhow::bail!(
                    "prompt history manifest lineage does not match the durable graph"
                ),
                Err(error)
                    if matches!(
                        error,
                        ContentStoreError::Revoked { .. } | ContentStoreError::Unresolved { .. }
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
            rebound_owners.insert(active_run.0.clone(), active_run.clone());
            entry.source.source = source.clone();
            entry.source.synthetic_seq = None;
        }
        if !rebound_owners.is_empty() {
            self.reconcile_synthetic_sources_with(&state, rebound_owners.into_values())?;
            self.publish(&state)?;
        }

        let mut history = Vec::with_capacity(state.history.len());
        let mut retained_bindings = Vec::with_capacity(state.history.len());
        let mut pruned = false;
        for (index, entry) in state.history.iter().enumerate() {
            match self.load_text(index, entry) {
                Ok(text) => {
                    retained_bindings.push((text.clone(), entry.source.clone()));
                    history.push(text);
                }
                Err(error) if content_is_unavailable(&error) => pruned = true,
                Err(error) => return Err(error),
            }
        }
        let (draft, retained_draft) = match state.draft.as_ref() {
            Some(entry) => match self.load_text(MAX_ENTRIES, entry) {
                Ok(text) => (Some(text.clone()), Some((text, entry.source.clone()))),
                Err(error) if content_is_unavailable(&error) => {
                    pruned = true;
                    (None, None)
                }
                Err(error) => return Err(error),
            },
            None => (None, None),
        };
        let hydrated = bound_and_scrub(State::new(history, draft));
        if pruned {
            *self
                .lineage
                .lock()
                .map_err(|_| anyhow::anyhow!("prompt history lineage state is poisoned"))? =
                LineageState {
                    history: retained_bindings,
                    draft: retained_draft,
                };
            // Compact only successfully gated entries into fresh sequence slots. A revoked entry
            // is never served, while independent entries retain their original source authority.
            self.save(hydrated.clone(), active_run)?;
            return Ok(hydrated);
        }
        self.reconcile(&state)?;
        self.remember(&hydrated, &state)?;
        Ok(hydrated)
    }

    fn load_text(&self, index: usize, entry: &PersistedEntry) -> anyhow::Result<String> {
        let seq = Seq(u64::try_from(index)?);
        let durable_sources = self.private.sources_at(seq, &entry.handle)?;
        if durable_sources != [entry.source.source.clone()] {
            anyhow::bail!("prompt history manifest lineage does not match the durable graph");
        }
        let bytes = self.private.read_at(seq, &entry.handle)?;
        Ok(String::from_utf8(bytes)?)
    }

    pub(super) fn reconcile(&self, state: &PersistedState) -> anyhow::Result<()> {
        let mut desired = state
            .history
            .iter()
            .enumerate()
            .map(|(index, entry)| Ok((Seq(u64::try_from(index)?), entry.handle.digest.clone())))
            .collect::<anyhow::Result<Vec<_>>>()?;
        if let Some(draft) = &state.draft {
            desired.push((
                Seq(u64::try_from(MAX_ENTRIES)?),
                draft.handle.digest.clone(),
            ));
        }
        self.private.retain(&desired)?;
        self.reconcile_synthetic_sources(state)?;
        Ok(())
    }

    fn reconcile_synthetic_sources(&self, state: &PersistedState) -> anyhow::Result<()> {
        self.reconcile_synthetic_sources_with(state, std::iter::empty())
    }

    fn reconcile_synthetic_sources_with(
        &self,
        state: &PersistedState,
        additional_owners: impl IntoIterator<Item = RunId>,
    ) -> anyhow::Result<()> {
        let previous = self
            .lineage
            .lock()
            .map_err(|_| anyhow::anyhow!("prompt history lineage state is poisoned"))?
            .clone();
        let mut desired =
            BTreeMap::<String, (RunId, Vec<(Seq, iteron_protocol::ErasureContentDigest)>)>::new();
        let mut owners = previous
            .history
            .into_iter()
            .chain(previous.draft)
            .filter_map(|(_, binding)| {
                binding
                    .synthetic_seq
                    .map(|_| (binding.source.owner.0.clone(), binding.source.owner))
            })
            .collect::<BTreeMap<_, _>>();
        owners.extend(
            additional_owners
                .into_iter()
                .map(|owner| (owner.0.clone(), owner)),
        );
        for entry in state.history.iter().chain(state.draft.iter()) {
            let Some(seq) = entry.source.synthetic_seq else {
                continue;
            };
            owners.insert(
                entry.source.source.owner.0.clone(),
                entry.source.source.owner.clone(),
            );
            desired
                .entry(entry.source.source.owner.0.clone())
                .or_insert_with(|| (entry.source.source.owner.clone(), Vec::new()))
                .1
                .push((Seq(seq), entry.source.source.digest.clone()));
        }
        for (owner_key, owner) in owners {
            self.source_store(owner)?.retain(
                desired
                    .get(&owner_key)
                    .map(|(_, references)| references.as_slice())
                    .unwrap_or_default(),
            )?;
        }
        Ok(())
    }

    pub(super) fn remember(&self, state: &State, persisted: &PersistedState) -> anyhow::Result<()> {
        let history = state
            .history
            .iter()
            .cloned()
            .zip(persisted.history.iter().map(|entry| entry.source.clone()))
            .collect();
        let draft = state
            .draft
            .clone()
            .zip(persisted.draft.as_ref().map(|entry| entry.source.clone()));
        *self
            .lineage
            .lock()
            .map_err(|_| anyhow::anyhow!("prompt history lineage state is poisoned"))? =
            LineageState { history, draft };
        Ok(())
    }
}

fn content_is_unavailable(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ContentStoreError>()
        .is_some_and(|source| {
            matches!(
                source,
                ContentStoreError::Revoked { .. } | ContentStoreError::Unresolved { .. }
            )
        })
}
