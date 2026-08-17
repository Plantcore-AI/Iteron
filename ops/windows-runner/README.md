# Windows self-hosted runner: operator runbook

Provisioning kit for the loaned Aliyun ECS Windows Server box that serves as this org's native
Windows CI machine (issue #227). Target: `114.55.106.139`, 4 vCPU / 8 GiB / 100 GiB, admin user
`Administrator`. Approved purpose: native Windows CI, installer verification, GUI debugging.
Approved budget ceiling: **160 machine-hours per month**.

---

## 0. Read this first: the machine cannot be automated from outside yet

**Nothing in this kit can be run remotely today.** The first step is a human at a graphical
console. This is the current, measured state of the box:

| Path | Port | State |
| --- | --- | --- |
| OpenSSH | 22 | Reachable, but **no usable auth**. `sshd` advertises `publickey,keyboard-interactive` and then issues **zero password prompts**, returning an immediate `USERAUTH_FAILURE`. That is the signature of password authentication being disabled server-side. Only a pre-installed public key would work, and none is installed. |
| RDP | 3389 | Reachable, and it is a real Windows host (a raw X.224 connection request is answered with a connection confirm advertising NLA / CredSSP). Authentication with the credentials we were given fails at the NLA layer with **`STATUS_LOGON_FAILURE 0xc000006d`**, which means exactly one thing: **the username or password is wrong.** Not a policy block, not a password-change prompt. |
| WinRM | 5985 / 5986 | **Blocked** by the cloud security group. Not available, do not plan around it. |
| SMB | 445 | **Blocked** by the cloud security group. |

So the first human step is simply: **obtain a correct `Administrator` password**, from whoever
provisioned the instance or by resetting it in the cloud console (an instance password reset
requires a restart to take effect). Then RDP in normally.

Two diagnostic traps cost real time here; do not repeat them:

- **`xfreerdp /auth-only` is not a credential test.** It prints
  `[ERROR] ... Authentication only, exit status 0` even when authentication *failed*. Grepping for
  `exit status 0` reports success on bad credentials. The only trustworthy signal is the NTSTATUS
  on the `nla_decode_ts_request` line (`STATUS_LOGON_FAILURE` = bad credentials,
  `STATUS_PASSWORD_MUST_CHANGE` = policy).
- **A local TUN/HTTP proxy makes every port look open.** `nc -z` against this host reported
  22, 135, 445, 3389, 5985, 5986 and even 80 as open, because the proxy accepts the CONNECT and
  answers optimistically. Only a real protocol handshake tells the truth: an SSH banner, an X.224
  connection confirm, a genuine HTTP status. Measured reality here is that **only 22 and 3389 are
  actually open**; WinRM and SMB are blocked at the cloud security group.

Once you have a session, pick **one** of the two ways forward. Document both, do both if you can.

### (a) Install an SSH public key, so the rest is scriptable

This is the preferred outcome: it makes every later step remotable and repeatable.

```powershell
# In the GUI session, as Administrator.
# Paste the operator's PUBLIC key (never a private key, never a password) into the
# admin-wide authorized_keys file that Windows OpenSSH uses for members of Administrators:
$key = 'ssh-ed25519 AAAA... operator@laptop'
$f   = 'C:\ProgramData\ssh\administrators_authorized_keys'
Set-Content -LiteralPath $f -Value $key -Encoding ascii

# sshd SILENTLY refuses this file unless its ACL is exactly Administrators + SYSTEM.
# Inherited user ACEs are the single most common reason "the key does nothing".
icacls $f /inheritance:r /grant Administrators:F /grant SYSTEM:F

# Make sure sshd is actually running and will come back after reboot:
Get-Service sshd | Set-Service -StartupType Automatic
Restart-Service sshd
```

Verify from your laptop: `ssh -i <key> Administrator@114.55.106.139 "whoami"`.

If key auth still fails, check `C:\ProgramData\ssh\sshd_config` for
`PubkeyAuthentication yes` and for the `Match Group administrators` block at the bottom pointing at
`administrators_authorized_keys`, and read `Get-WinEvent -LogName OpenSSH/Operational`.

### (b) Run the scripts directly in the GUI session

If key installation is not possible in the time you have, copy this directory onto the machine
through the RDP clipboard or an RDP drive redirection mount, open an **elevated** PowerShell, and
run the sequence in section 2. Everything in this kit is designed to work with no inbound network
access to the machine at all: it only makes outbound HTTPS calls.

---

## 1. Checksum pinning (do this before anything downloads)

Every download in `bootstrap.ps1` is HTTPS **and** verified against a pinned SHA-256. The pin table
in that script **ships empty on purpose**: no hash in this repo was invented, and an empty pin
aborts the run before a single byte is executed. You must fill the pins once, deliberately.

```powershell
Copy-Item .\checksums.example.json .\checksums.json
# then fill each value with a real 64-hex-char SHA-256
```

Where the real hashes come from:

| Artifact | Authoritative source |
| --- | --- |
| `rustup-init.exe` | `https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe.sha256` |
| `node-v<ver>-x64.msi` | `https://nodejs.org/dist/v<ver>/SHASUMS256.txt` (signed as `SHASUMS256.txt.sig`) |
| `Git-<ver>-64-bit.exe` | `gh release view v<ver>.windows.1 --repo git-for-windows/git --json body --jq .body` |
| `wix314.exe` | `gh release view <tag> --repo wixtoolset/wix3 --json body --jq .body` |
| `python-<ver>-amd64.exe` | python.org publishes an MD5, a GPG signature (`<file>.asc`) and a sigstore bundle, **not** a SHA-256. Verify the signature, then pin the SHA-256 of the file you verified. |
| `nsis-<ver>-setup.exe` | SourceForge file listing for `NSIS 3/<ver>` shows the SHA-256 |
| `vs_BuildTools.exe` | **No published per-build hash.** See below. |
| `MicrosoftEdgeWebview2Setup.exe` | **No published per-build hash.** See below. |

**The two Microsoft bootstrappers are honest exceptions.** Microsoft rotates
`aka.ms/vs/17/release/vs_BuildTools.exe` and the WebView2 Evergreen bootstrapper silently behind a
redirect and publishes no per-build digest. For those two, a pin is a **change detector, not a
supply-chain proof**: it records the exact bytes you fetched over HTTPS from the Microsoft host, so
that a later silent change stops the script instead of slipping through. When that mismatch fires,
the correct response is to re-verify and re-pin deliberately, never to paste the new hash in
without looking.

`refresh-checksums.ps1` automates the arithmetic and cross-checks against the vendor-published
hashes where they exist. It refuses to touch the two trust-on-first-use artifacts unless you pass
`-IUnderstandTrustOnFirstUse`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\refresh-checksums.ps1 `
    -IUnderstandTrustOnFirstUse -OutFile .\checksums.json
```

Version numbers are parameters, and the pin key is the artifact **file name**, so bumping a version
automatically invalidates its pin. That is intended: a version bump and a hash refresh are one
change, reviewed together.

---

## 2. The command sequence

All three scripts are idempotent, fail-closed (`$ErrorActionPreference = 'Stop'`,
`Set-StrictMode`), PowerShell 5.1 compatible, and safe to re-run. Run them from an **elevated**
PowerShell.

### 2.1 `bootstrap.ps1`: toolchain

```powershell
cd C:\ops\windows-runner
powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 -ChecksumFile .\checksums.json
```

Installs, checking first and skipping what is already present:

- **Visual Studio Build Tools** into `C:\BuildTools`, unattended
  (`--quiet --wait --norestart`), with `Microsoft.VisualStudio.Workload.VCTools`,
  `Microsoft.VisualStudio.Component.VC.Tools.x86.x64` and the Windows SDK component
  (default `Microsoft.VisualStudio.Component.Windows11SDK.22621`; pass
  `-WindowsSdkComponent Microsoft.VisualStudio.Component.Windows11SDK.26100` for the 24H2 SDK).
  This is what supplies `link.exe` for `x86_64-pc-windows-msvc`.
- **Rust pinned to 1.90.0**, matching `RUSTUP_TOOLCHAIN` in `.github/workflows/*.yml`, with target
  `x86_64-pc-windows-msvc` and components `clippy` and `rustfmt`. Not `stable`: pass
  `-RustToolchain <ver>` when CI's pin moves.
- **Git for Windows**, **Node.js 22**, **CPython 3.12** (`-PythonVersion`, minimum 3.11),
  **WebView2 Runtime**, **NSIS**, **WiX Toolset v3.14**.
- Long path support, and (opt-in, `-AddDefenderExclusions`) Defender exclusions for the build
  trees.

Then it re-invokes every tool, prints its version, and **fails if any is missing**.

Two deliberate decisions worth knowing:

- **Rust is installed machine-wide** under `C:\rust` with `CARGO_HOME` / `RUSTUP_HOME` /
  `RUSTUP_TOOLCHAIN` set as machine environment variables, and the tree is ACL'd so
  `NT AUTHORITY\NETWORK SERVICE` can write it. The runner service does not run as the interactive
  Administrator, so a per-user `~\.cargo` would be invisible to CI.
- **No 7-Zip.** Windows Server ships `tar.exe` and PowerShell `Expand-Archive`, which cover every
  archive this fleet touches. One fewer unpinnable third-party download. The verification phase
  asserts both are present.
- **`C:\Program Files\Git\bin` is added to the machine PATH** on purpose. Several CI and release
  steps run with `shell: bash`, which on a self-hosted Windows runner means Git for Windows' bash
  resolved from PATH. Git's "CmdTools" PATH option alone puts only `git.exe` there, so without this
  every such step dies before running a single command, and the failure reads like a broken script
  rather than a missing shell. `verify.ps1` checks `bash --version` explicitly and treats a miss as
  a hard failure.
- **Python is installed so that both `python` and `python3` resolve**, including inside a
  `shell: bash` step. The whole release pipeline is Python: `.github/workflows/release.yml` invokes
  `release-tools/*.py` (`package.py`, `manifest.py`, `sbom.py`, `checksums.py`,
  `verify_release.py`, `fetch_tool.py`) through a matrix interpreter value that is `python3` on the
  POSIX legs, and those tools import `tomllib`, which requires **3.11 or newer**.
  The python.org installer ships `python.exe` plus the `py` launcher and creates **no**
  `python3.exe`, so `bootstrap.ps1` copies `python.exe` to `python3.exe` in the same install
  directory. A copy resolves its prefix from its own directory, so it behaves identically, and
  unlike a `python3.cmd` shim it is found by Git bash, which only probes `python3` and
  `python3.exe` on PATH.

  **For whoever writes the release matrix entry: this machine answers to `python3`.** Keeping the
  Windows leg's interpreter value as `python3`, identical to the other legs, is correct and is what
  this kit guarantees. `python` and `py -3` also work, so a matrix that uses `python` is not
  broken, only inconsistent with the other legs.

If an installer returns 3010 the script says a reboot is required. Reboot, re-run the script once
(it will change nothing and confirm everything), then continue.

Useful flags: `-SkipVisualStudio`, `-SkipRust`, `-SkipGit`, `-SkipNode`, `-SkipPython`,
`-SkipWebView2`, `-SkipNsis`, `-SkipWix`.

### 2.2 `install-runner.ps1`: runner service

One machine serves two repositories, so runners live in separate directories with distinct labels:

| Repository | Directory | Label |
| --- | --- | --- |
| `Plantcore-AI/Iteron` | `C:\actions-runner\iteron` | `iteron-win` |
| `Plantcore-AI/plantcore-desktop` | `C:\actions-runner\desktop` | `desktop-win` |

Resolve the runner version and its hash first (both are required parameters; neither is defaulted,
because guessing one desynchronises it from the other):

```powershell
# On any machine with gh:
gh api repos/actions/runner/releases/latest --jq .tag_name
gh release view <tag> --repo actions/runner --json body --jq .body   # contains the win-x64 SHA-256
```

Then, on the Windows box:

```powershell
# Short-lived registration token (about one hour). NEVER commit or persist this.
$tok = ConvertTo-SecureString `
    (gh api --method POST repos/Plantcore-AI/Iteron/actions/runners/registration-token --jq .token) `
    -AsPlainText -Force

powershell -NoProfile -ExecutionPolicy Bypass -File .\install-runner.ps1 `
    -Repo Plantcore-AI/Iteron `
    -RunnerVersion 2.328.0 `
    -RunnerSha256 <64-hex-from-the-release-body> `
    -Token $tok
```

If `gh` is not installed on the Windows box, generate the token on your laptop and paste it in
without echoing it:

```powershell
$tok = Read-Host -AsSecureString "registration token"
```

For the desktop repo, same command with `-Repo Plantcore-AI/plantcore-desktop`; the instance
directory and the `desktop-win` label are derived automatically.

What it does:

- Downloads `actions-runner-win-x64-<ver>.zip`, **verifies the SHA-256**, extracts to the instance
  directory.
- Registers with `--unattended --replace`, so a re-run replaces the same-named runner instead of
  creating a duplicate.
- Installs it as a **Windows service** (`--runasservice --windowslogonaccount "NT AUTHORITY\NETWORK
  SERVICE"`), then sets:
  - `sc.exe config <svc> start= delayed-auto` -- Automatic (Delayed Start), so the network stack is
    up before the listener tries to connect. This is what makes it survive reboot unattended.
  - `sc.exe failure <svc> reset= 86400 actions= restart/60000/restart/60000/restart/60000` plus
    `sc.exe failureflag <svc> 1` -- restart three times a minute apart, applied to clean exits as
    well as crashes. This is what turns a network loss into a reconnect instead of a runner that
    silently goes offline.

**Token handling.** The token is a parameter only: never hardcoded, never logged (the script prints
a redacted command line), never written to disk, and the decrypted copy is zeroed from memory as
soon as `config.cmd` returns. The one honest caveat: `config.cmd` accepts the token only as a
command-line argument, so for the few seconds it runs the token is visible to any process on the
host that can read another process's command line. That is inherent to the vendor tool; the
mitigations are that the token is short-lived and grants only "register a runner", and that nobody
else should have a session on this machine.

### 2.3 `verify.ps1`: prove it can do the job

```powershell
git clone https://github.com/Plantcore-AI/Iteron C:\src\Iteron
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1 `
    -CheckoutPath C:\src\Iteron -Clean -RunConPtyTest -ReportPath C:\actions-runner\verify-report.json
```

It prints every tool version, the runner services and their start type, free disk, and then runs a
real `cargo check --workspace --locked --target x86_64-pc-windows-msvc` and reports elapsed
wall-clock. `-Clean` deletes only `<checkout>\target` first, so the number is a cold compile.
A run that finishes in under 60 seconds is flagged as a warm-cache replay rather than a compile.

---

## 3. The final enablement step

**The runner does nothing until you flip the repository variable.** After it shows Online at
`https://github.com/Plantcore-AI/Iteron/settings/actions/runners`:

```bash
gh variable set WINDOWS_RUNNER_LABELS --repo Plantcore-AI/Iteron \
  --body '["self-hosted","Windows","X64","iteron-win"]'
```

The value is a **JSON array of labels**, not a bare label. That is the shape this repository
already uses for its self-hosted runners: `release.yml` carries entries such as
`'["self-hosted","Linux","ARM64","dgx-release-x86"]'` and resolves them with
`runs-on: ${{ fromJSON(matrix.runner) }}`. A bare string would not parse.

While `WINDOWS_RUNNER_LABELS` is unset, nothing points at this machine. That default is deliberate,
not an oversight. A job pointed at a self-hosted label that no machine answers **queues forever**
instead of failing, and this org has already taken that outage on Iteron-internal, where a workflow
sat queued permanently because no runner carried the label. So the two lanes degrade differently,
and both degrade safely:

- `windows.yml` (CI) carries `if: vars.WINDOWS_RUNNER_LABELS != ''`, so with the variable unset the
  job is **skipped** — honestly skipped, never a green result it did not earn. No hosted minutes.
- `release.yml` (release build) falls back to the hosted `windows-2025` runner, because a release
  must not stall: `publish` has `needs: build`, so a queued Windows build would block the whole tag.

Unsetting the variable is therefore the entire rollback:

```bash
gh variable delete WINDOWS_RUNNER_LABELS --repo Plantcore-AI/Iteron
```

The desktop repository is a **separate** setting with its own variable and its own runner label
(`desktop-win`); setting one does not affect the other.

Set it only after the runner is Online, and check that the label in the variable matches the label
the runner actually carries.

---

## 4. Verifying acceptance (issue #227)

1. **Duration consistent with real compilation.** Open a trivial PR and look at the Windows job.
   `verify.ps1 -Clean` gives you the local baseline for comparison; a cold `cargo check` on 4 vCPU
   is minutes, not seconds. A Windows job that "passes" in seconds is a job that did not compile.
   The `windows.yml` lane also runs the ConPTY test precisely so that a warm `target/` cannot fake
   a pass.
2. **Survives a reboot and reconnects unattended.** From an elevated session:
   ```powershell
   Restart-Computer -Force
   # after it comes back, without logging in interactively:
   Get-Service actions.runner.* | Select-Object Name, Status, StartType
   (Get-CimInstance Win32_Service -Filter "Name LIKE 'actions.runner%'").StartMode   # Auto
   ```
   Then confirm the runner shows Online in the repository's runner list again. Also test the
   network-loss half: stop the service, confirm GitHub shows it offline, start it, confirm it
   returns; and confirm the recovery config with `sc.exe qfailure <service name>`.
3. **Hosted Windows minutes drop to zero for ordinary PRs.** Check billing after a few PRs:
   `Settings -> Billing -> Actions`, Windows line. A run executing on the self-hosted machine shows
   the runner name and its labels in the job's "Runner" section and is billed nothing. If Windows
   minutes are still accruing, some job is still resolving to `windows-2025`; grep the workflows
   for `runs-on:` entries that do not consult `vars.WINDOWS_RUNNER_LABELS`.

---

## 5. Cost control

The machine is approved for **160 machine-hours per month**. Two facts drive the discipline here:

- GitHub does **not** bill for self-hosted runner minutes. Moving jobs here makes GitHub's Windows
  line go to zero.
- Aliyun **does** bill the ECS instance by the hour, whether or not it is running a job. A runner
  idling at the login screen costs exactly the same as one compiling.

So: **stop the instance when it is idle.** 160 hours is roughly 5.3 hours a day, or about seven
full working days a month. Practical policy:

- Stop the instance from the Aliyun console (or CLI) at the end of a Windows working session. The
  runner service is Automatic (Delayed Start), so it reconnects on its own the next time the
  instance boots. No re-registration is needed and no token is required to bring it back.
- Do not leave it running overnight to "catch" PR traffic. Windows lanes in this repo are advisory
  and non-gating; a PR that misses a Windows run is not blocked.
- Track hours monthly against the 160 cap before adding another repository to the machine. Two
  runner instances on one box share the same instance-hours, which is the point of putting both on
  one machine.

If the cap becomes binding, the correct escalation is to reduce which jobs target Windows, not to
quietly exceed the approved budget.

---

## 6. Security posture

**No long-lived credential belongs on this machine.**

- Company policy explicitly forbids putting the main-account cloud AccessKey into any ECS image,
  code repository, or CI variable. Do not put one on this box, in this kit, or in any workflow
  that runs on it. Nothing in this directory reads, writes, or accepts a cloud AccessKey, and
  nothing in it should ever be changed to do so.
- The only credential this kit touches is the runner **registration token**, which lives about an
  hour, is a parameter only, is never logged or persisted, and is zeroed from memory after use.
  The long-lived runner credential that `config.cmd` writes into the instance directory
  (`.credentials`, `.credentials_rsaparams`) is GitHub's own runner identity: it is scoped to
  "this runner may take jobs from this repository", and it must never be copied off the machine.
- **Self-hosted runners must not run untrusted fork pull requests.** A self-hosted runner is not a
  fresh VM: the workspace, the Cargo registry cache and `target/` persist between jobs, so a
  malicious PR could plant something that a later, trusted job executes. What the repositories
  should configure:
  - `Settings -> Actions -> General -> Fork pull request workflows from outside collaborators`:
    require approval for **all** outside collaborators. This is the control that keeps a fork PR
    from reaching this machine at all until a maintainer approves it.
  - Keep the runner **repository-scoped**, not organization-scoped, so a new repository cannot
    schedule work on it by accident.
  - Do not add repository secrets that Windows jobs consume unless they are genuinely needed on
    Windows. Anything a job can read, a compromised job can exfiltrate.
  - Prefer keeping the Windows lanes advisory (as `ci.yml` and `windows.yml` already are), so a
    compromised or broken machine cannot gate merges.
- The runner service runs as `NT AUTHORITY\NETWORK SERVICE`, not as `Administrator`, and no service
  password is stored anywhere. Change that only with a reason.
- `install-runner.ps1` and `bootstrap.ps1` never delete anything outside their own directories, and
  `verify.ps1 -Clean` deletes only `<checkout>\target`. This is a shared engineering machine, not a
  disposable image.

---

## 7. Files in this directory

| File | Purpose |
| --- | --- |
| `bootstrap.ps1` | Idempotent toolchain provisioning: MSVC, Rust 1.90.0, Git (and its bash), Node 22, CPython 3.12 (`python` and `python3`), WebView2, NSIS, WiX. Verifies every tool afterwards. |
| `install-runner.ps1` | Downloads, registers and services a runner instance per repository, with delayed auto-start and restart-on-failure. |
| `verify.ps1` | Post-provision self-check: tool inventory plus a real timed `cargo check` for `x86_64-pc-windows-msvc`. |
| `refresh-checksums.ps1` | Computes and, where the vendor publishes one, cross-checks the SHA-256 pins. |
| `checksums.example.json` | Template pin file. Copy to `checksums.json` and fill it in. |

None of these files contains a secret, a token, a password, or a cloud AccessKey, and none should
ever be changed so that it does.

---

## 8. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `bootstrap.ps1` aborts with "SHA-256 pin is EMPTY" | Working as designed. Fill `checksums.json` (section 1). |
| `CHECKSUM MISMATCH` | The vendor rotated the artifact, or something is wrong. The rejected file is kept as `<name>.rejected`. Re-verify against the vendor's published hash before re-pinning. |
| `config.cmd` fails with an auth error | The registration token expired (they live about an hour). Mint a new one and re-run. |
| Runner shows Offline after reboot | Check `Get-Service actions.runner.*` and `sc.exe qc <svc>` for `DELAYED_AUTO_START`. Re-run `install-runner.ps1`; it re-asserts the service policy without re-registering. |
| Windows jobs queue forever | `WINDOWS_RUNNER_LABELS` names a label no online runner carries. Unset the variable (CI skips, release falls back to hosted), then fix the label. |
| Windows job dies immediately on "Run ..." with `bash: command not found` | `C:\Program Files\Git\bin` is not on the machine PATH, so `shell: bash` steps have no shell. Re-run `bootstrap.ps1`, then `verify.ps1` (it checks `bash --version`). |
| Release job fails with `python3: command not found` or `ModuleNotFoundError: tomllib` | Python missing, older than 3.11, or the `python3.exe` copy absent. Re-run `bootstrap.ps1`; `verify.ps1` reports both `python` and `python3`. |
| `cargo` fails with permission errors under the service account | `C:\rust` ACLs. Re-run `bootstrap.ps1`, which grants Modify to `NT AUTHORITY\NETWORK SERVICE`. |
| Link errors about `link.exe` not found | VS Build Tools missing or the SDK component id was wrong for the installed VS version. Check `vswhere -products * -latest -property installationPath`. |
