use super::*;
use crate::runtime::DurableAppendFault;
use crate::runtime::session_transcript::TranscriptAdmissionJournal;
use crate::runtime::turn_publication::TurnPublicationOwner;
use iteron_ctx::{ContextStrategy, MemoryRecallStrategy, PortStub};
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::Ledger;
use iteron_protocol::{Effort, Event, RunId, Seq, TenantId};
use iteron_record::Rollout;

struct Writer {
    root: PathBuf,
    rollout: Rollout,
    ledger: Ledger,
    failed: bool,
    publications: TurnPublicationOwner,
    diagnostics: DiagnosticEmitter,
    fault: Option<DurableAppendFault>,
}
impl Writer {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "iteron-context-materialization-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut rollout =
            Rollout::open(&root, &RunId("context".into()), TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: root.to_string_lossy().into(),
                    model: "fixture".into(),
                    effort: Effort::Low,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        let publications = TurnPublicationOwner::for_rollout(&rollout);
        Self {
            root,
            rollout,
            publications,
            ledger: Ledger::default(),
            failed: false,
            diagnostics: DiagnosticEmitter::default(),
            fault: None,
        }
    }
    fn journal(&mut self) -> ContextInjectionJournal<'_> {
        ContextInjectionJournal {
            transcript: TranscriptAdmissionJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.failed,
                diagnostics: &self.diagnostics,
                publications: &mut self.publications,
                fault: &mut self.fault,
            },
            policy: None,
        }
    }
    fn close(self) -> (PathBuf, PathBuf) {
        let path = self.rollout.path().to_path_buf();
        let root = self.root.clone();
        drop(self);
        (root, path)
    }
}

fn world<'a>(
    context: &'a ContextStrategy,
    memory: &'a MemoryRecallStrategy,
    port: &'a PortStub,
) -> ContextInjectionWorld<'a> {
    ContextInjectionWorld {
        memory_workspace: None,
        home: None,
        dependency_skill_dirs: &[],
        context,
        memory,
        port,
        benchmark_scope: None,
        materialization: ContextMaterializationPolicy::default(),
    }
}

#[test]
fn actual_legacy_upgrade_reopens_with_its_admitted_prefix_and_ignores_changed_proposals() {
    let mut writer = Writer::new();
    writer
        .journal()
        .injection(
            TurnId(0),
            "historical memory\n".into(),
            Trust::Workspace,
            None,
        )
        .unwrap();
    let recorded = RecordedContextHistory::read(writer.rollout.path()).unwrap();
    let instructions = ("original instructions\n".into(), Trust::Untrusted);
    let environment = ("original environment\n".into(), Trust::Workspace);
    let preparation = ContextInjectionPreparation::new(
        recorded,
        Some(&instructions),
        Some(&environment),
        false,
        Instant::now(),
    );
    assert!(!preparation.needs_live_policy(true));
    let context = ContextStrategy::default();
    let memory = MemoryRecallStrategy::default();
    let port = PortStub::new(Vec::new());
    let materialized = preparation
        .materialize(
            TurnId(1),
            "resume",
            world(&context, &memory, &port),
            &mut writer.journal(),
        )
        .unwrap();
    assert!(matches!(
        materialized.observation(TurnId(1), "resume"),
        ContextInjectionObservation::Recorded {
            trust: Trust::Untrusted,
            ..
        }
    ));
    let committed = materialized
        .commit(
            TurnId(1),
            &mut writer.journal(),
            &mut RequestContextEvidenceOwner::default(),
        )
        .unwrap();
    assert!(committed.text.contains("original instructions"));
    assert!(committed.text.contains("original environment"));
    assert!(committed.text.contains("historical memory"));
    assert_eq!(committed.trust, Some(Trust::Untrusted));
    let (root, path) = writer.close();
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::ContextInjection { .. }))
            .count(),
        2
    );
    let changed = ("changed live proposal\n".into(), Trust::Trusted);
    let preparation = ContextInjectionPreparation::new(
        RecordedContextHistory::read(&path).unwrap(),
        Some(&changed),
        Some(&changed),
        false,
        Instant::now(),
    );
    let mut reopened = Rollout::open(&root, &RunId("context".into()), TenantId::default()).unwrap();
    let mut publications = TurnPublicationOwner::for_rollout(&reopened);
    let mut ledger = Ledger::default();
    let mut failed = false;
    let mut fault = None;
    let diagnostics = DiagnosticEmitter::default();
    let mut journal = ContextInjectionJournal {
        transcript: TranscriptAdmissionJournal {
            rollout: &mut reopened,
            ledger: &mut ledger,
            record_failed: &mut failed,
            diagnostics: &diagnostics,
            publications: &mut publications,
            fault: &mut fault,
        },
        policy: None,
    };
    let replayed = preparation
        .materialize(
            TurnId(2),
            "different task",
            world(&context, &memory, &port),
            &mut journal,
        )
        .unwrap()
        .commit(
            TurnId(2),
            &mut journal,
            &mut RequestContextEvidenceOwner::default(),
        )
        .unwrap();
    assert_eq!(replayed.text, committed.text);
    assert_eq!(replayed.trust, committed.trust);
    drop(journal);
    drop(reopened);
    assert_eq!(iteron_record::replay(&path).unwrap().len(), events.len());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn real_poisoned_writer_cannot_release_an_installable_live_prefix() {
    let mut writer = Writer::new();
    // Refuse the actual owning journal, then carry that same poisoned writer into the new context
    // barrier. Reopening must contain neither the refused observation nor a ContextInjection.
    writer.fault = Some(DurableAppendFault::Notice);
    assert!(
        writer
            .journal()
            .transcript
            .notice(TurnId(0), "refused observation".into())
            .is_err()
    );
    assert!(writer.failed);
    let instruction = ("not yet admitted prefix\n".into(), Trust::Workspace);
    let preparation = ContextInjectionPreparation::new(
        RecordedContextHistory::read(writer.rollout.path()).unwrap(),
        Some(&instruction),
        None,
        false,
        Instant::now(),
    );
    let context = ContextStrategy::default();
    let memory = MemoryRecallStrategy::default();
    let port = PortStub::new(Vec::new());
    let pending = preparation
        .materialize(
            TurnId(0),
            "task",
            world(&context, &memory, &port),
            &mut writer.journal(),
        )
        .unwrap();
    assert!(
        pending
            .commit(
                TurnId(0),
                &mut writer.journal(),
                &mut RequestContextEvidenceOwner::default()
            )
            .is_err()
    );
    assert!(writer.failed);
    let (root, path) = writer.close();
    let events = iteron_record::replay(&path).unwrap();
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        EventKind::ContextInjection { .. } | EventKind::Notice { .. }
    )));
    std::fs::remove_dir_all(root).unwrap();
}
