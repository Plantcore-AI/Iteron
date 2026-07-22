//! D9-04 oracle — `EventKind::Notice` is a durable secret surface.
//!
//! A notice's free-form text is scrubbed at the single record-redaction chokepoint
//! (`redact_event`). A URL basic-auth credential (`scheme://user:password@host`) — which provider
//! error and diagnostic notices routinely echo — must not survive that boundary. On the INTEG base
//! the password fuses with the host into one `@`/`.`-bearing word that matches no known secret
//! shape and no lone-token split, so it reaches the durable record verbatim; the fix masks the
//! userinfo password before the token scanner runs.

use core_protocol::{Event, EventKind, Seq, TurnId};
use core_record::redact::redact_event;

fn notice(text: String) -> Event {
    Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::Notice { text },
    }
}

#[test]
fn notice_url_basic_auth_password_is_scrubbed_from_the_record() {
    let password = "S3cretProviderPassw0rdABCDEFGH123456";
    let event = notice(format!(
        "provider request failed: https://svc:{password}@api.example.com/v1/messages returned 401"
    ));

    let redacted = redact_event(&event);
    let encoded = serde_json::to_string(&redacted).expect("serialize redacted notice");

    assert!(
        !encoded.contains(password),
        "URL basic-auth password leaked into the durable notice record: {encoded}"
    );
    assert!(
        encoded.contains("[REDACTED"),
        "the basic-auth credential must be masked in the record: {encoded}"
    );

    // The message text, host, and path are ordinary provenance and must be preserved.
    match &redacted.kind {
        EventKind::Notice { text } => {
            assert!(
                text.contains("api.example.com/v1/messages"),
                "host and path must be preserved: {text}"
            );
            assert!(
                text.contains("provider request failed") && text.contains("returned 401"),
                "surrounding notice text must survive redaction: {text}"
            );
        }
        other => panic!("redaction changed the event kind: {other:?}"),
    }

    // A second record-boundary redaction must leave the generated marker byte-stable (idempotent),
    // so repeated scrubbing on resume/fork never mangles an already-masked credential.
    let twice = serde_json::to_string(&redact_event(&redacted)).expect("serialize second pass");
    assert_eq!(
        twice, encoded,
        "second record-boundary redaction changed the generated redaction marker"
    );
}

#[test]
fn notice_without_a_password_keeps_the_url_intact() {
    // A userinfo without a password, and an ordinary host:port URL, are not credentials and must
    // pass through unchanged — the fix must not over-redact legitimate routing provenance.
    let event = notice(
        "connecting to https://api.example.com:8443/v1 (proxy git@host:repo) ok".to_string(),
    );
    let redacted = redact_event(&event);
    match &redacted.kind {
        EventKind::Notice { text } => {
            assert_eq!(
                text, "connecting to https://api.example.com:8443/v1 (proxy git@host:repo) ok",
                "a passwordless URL must be left byte-for-byte intact: {text}"
            );
        }
        other => panic!("redaction changed the event kind: {other:?}"),
    }
}
