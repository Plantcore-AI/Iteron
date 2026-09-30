use super::{CohortReplay, installation_from_rows};
use iteron_protocol::agent_cohort::{AgentCohortInstallationV1, AgentCohortOriginV1};
use iteron_protocol::{Event, EventKind, RunId, Seq, TenantId, TurnId};
use iteron_record::ScopedEvent;
fn marker(run: &str, origin: &str) -> ScopedEvent {
    ScopedEvent {
        tenant: TenantId("tenant".into()),
        run_id: RunId(run.into()),
        event: Event {
            seq: Seq(1),
            turn: TurnId(0),
            kind: EventKind::AgentCohortInstalledV1 {
                installation: AgentCohortInstallationV1 {
                    origin: AgentCohortOriginV1 {
                        version: 1,
                        tenant: TenantId("tenant".into()),
                        run_id: RunId(origin.into()),
                        config_sha256: format!("sha256:{}", "a".repeat(64)),
                    },
                    installed_run: RunId(run.into()),
                },
            },
        },
    }
}
#[test]
fn installation_is_authenticated_by_physical_scope_not_labels_or_latest_disk_path() {
    let tenant = TenantId("tenant".into());
    let rows = vec![
        marker("owning-run", "owning-run"),
        marker("fork-run", "owning-run"),
    ];
    let recovered = installation_from_rows(&rows, &tenant).unwrap().unwrap();
    assert_eq!(recovered.origin.run_id, RunId("owning-run".into()));
    assert_eq!(recovered.installed_run, RunId("fork-run".into()));
    let mut wrong = rows.clone();
    wrong[1].tenant = TenantId("foreign".into());
    assert!(installation_from_rows(&wrong, &tenant).is_err());
    let mut wrong = rows.clone();
    wrong[1].run_id = RunId("another-run".into());
    assert!(installation_from_rows(&wrong, &tenant).is_err());
    assert!(
        installation_from_rows(
            &[rows[0].clone(), marker("fork-run", "different-origin")],
            &tenant
        )
        .is_err()
    );
}
#[test]
fn replayed_fork_keeps_the_exact_original_admitted_prefix_after_more_local_history() {
    let tenant = TenantId("tenant".into());
    let run = RunId("fork-run".into());
    let mut rows = vec![
        marker("owning-run", "owning-run"),
        marker("fork-run", "owning-run"),
    ];
    let replay = CohortReplay {
        installation: None,
        forked: true,
        rows: rows.clone(),
    };
    let admitted = replay.main_admission(&tenant, &run, None).unwrap();
    rows.push(ScopedEvent {
        tenant: tenant.clone(),
        run_id: run.clone(),
        event: Event {
            seq: Seq(2),
            turn: TurnId(1),
            kind: EventKind::Message {
                message: iteron_protocol::Message::user_text("later text"),
            },
        },
    });
    let resumed = CohortReplay {
        installation: None,
        forked: true,
        rows: rows.clone(),
    };
    assert_eq!(
        resumed
            .main_admission(&tenant, &run, Some(&admitted))
            .unwrap(),
        admitted
    );
    // Prefix content mutation is not reconciled by changing its stored admission hash.
    rows[1].event.turn = TurnId(2);
    let tampered = CohortReplay {
        installation: None,
        forked: true,
        rows,
    };
    assert!(
        tampered
            .main_admission(&tenant, &run, Some(&admitted))
            .is_err()
    );
}
#[test]
fn portable_locator_and_scope_commitments_cannot_supply_arbitrary_paths() {
    for name in [
        "../run",
        "/run",
        "run\\next",
        "NUL",
        "COM1.log",
        "run.",
        "run ",
    ] {
        let mut row = marker(name, "owning-run");
        if let EventKind::AgentCohortInstalledV1 { installation } = &mut row.event.kind {
            assert!(installation.validate().is_err(), "{name}");
        }
    }
    let row = marker("fork-run", "owning-run");
    let EventKind::AgentCohortInstalledV1 { installation } = row.event.kind else {
        unreachable!()
    };
    assert!(
        installation
            .origin
            .directory_component()
            .starts_with("agents-controller-")
    );
    assert!(!installation.origin.directory_component().contains('/'));
}
