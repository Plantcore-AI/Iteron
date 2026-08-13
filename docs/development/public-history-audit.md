# Public history audit

This record describes the launch audit of the Git history GitHub exposes for
Iteron. It contains no credential values or secret-shaped fixture bytes.

## Reproducible scope

The audit used an isolated `--mirror` clone of `Plantcore-AI/Iteron`, then fetched
both `refs/pull/*/head` and `refs/pull/*/merge`. The resulting graph contained:

- 10 branch heads;
- 4 annotated version tags;
- 116 pull-request heads;
- 5 pull-request merge refs;
- 506 reachable commits across 135 refs.

Local worktrees, `dgxfleet`, `dgxrotom`, and other non-GitHub remotes were excluded
because they are not part of the repository visibility change.

Gitleaks 8.30.1 was downloaded from its upstream GitHub release. The selected
Darwin arm64 archive had SHA-256
`b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5`; the
upstream checksum file had SHA-256
`061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae`.
Both the GitHub asset digest and the entry in that checksum file were verified
before the scanner ran.

The bounded scan command was equivalent to:

```sh
gitleaks git --redact=100 --timeout 900 \
  --log-opts='--all --full-history' \
  --report-format json --report-path gitleaks-all-refs.json .
```

The final acceptance run additionally supplied the checked-in
`.gitleaksignore`. Reports stay redacted and outside the repository.

## Finding disposition

The initial scan reported 31 fingerprints:

| Rule | Count | Disposition |
| --- | ---: | --- |
| `generic-api-key` | 25 | synthetic inputs in redaction, environment scrubbing, and adversarial request-refusal tests |
| `gcp-api-key` | 2 | synthetic credential-shaped correlation IDs used to prove masking |
| `jwt` | 2 | synthetic credential-shaped correlation IDs used to prove masking |
| `slack-legacy-bot-token` | 2 | synthetic credential-shaped correlation IDs used to prove masking |

Every hit maps to a named test covering redaction, credential-shaped input,
environment scrubbing, or adversarial metadata refusal. None is a live
credential. No credential rotation or history rewrite is required.

The allowlist records each exact commit, file, rule, and line fingerprint.
There are no path-wide, rule-wide, regex, entropy, or stop-word exceptions, so a
new credential-shaped value still fails the scan.

## Internal-material disposition

| Surface named by the launch review | Disposition |
| --- | --- |
| `.local-analysis/` | absent from every audited GitHub ref; remains local-only |
| `Plan.md`, `AOL.md`, `Errors.md`, `Principal.md` | absent from every audited GitHub ref; remain machine governance state outside this repository |
| absolute developer paths | no real developer path or username was present; `/Users/` occurrences are synthetic path-handling fixtures |
| internal hosts | no audited ref contains the known internal runner or fleet host names |
| `core-internal` | one historical source reference names the private downstream edition but exposes no URL, host, credential, or source; retained as a public upstream/downstream compatibility fact |
| customer or partner material | no named customer/partner data or proprietary snapshot was found in paths or the reviewed reachable content |

Files were not relocated during this audit because the previously identified
local governance and analysis paths are already absent from the entire GitHub
ref graph. The synthetic security fixtures remain public test inputs, protected
by exact fingerprint exceptions and their redaction/refusal tests.

## Release decision

The exact final public candidate is recorded on launch-gate issue #221 after its
merge commit is known. The release owner must repeat the redacted all-ref scan
after any subsequent ref or candidate change and before changing repository
visibility.
