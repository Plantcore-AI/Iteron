# Windows self-hosted runner: operator runbook

Provisioning kit for the loaned Aliyun ECS Windows Server box that serves as this org's native
Windows CI machine (issue #227). Target: `114.55.106.139`, 4 vCPU / 8 GiB / 100 GiB, admin user
`Administrator`. Approved purpose: native Windows CI, installer verification, GUI debugging.
Approved budget ceiling: **160 machine-hours per month**.

---

## 0. Access: SSH with an already-provisioned key

The box is reachable and scriptable. An operator public key is already installed in
`C:\ProgramData\ssh\administrators_authorized_keys`, so everything in this kit runs remotely:

```console
$ ssh windows whoami
izrt4daujljimgz\administrator
```

Measured state of the host, so nobody plans around a path that does not exist:

| Path | Port | State |
| --- | --- | --- |
| OpenSSH | 22 | **The way in.** Public-key auth only. `sshd` advertises `publickey,keyboard-interactive`, but the keyboard-interactive branch returns an immediate `USERAUTH_FAILURE` with **zero prompts** — password authentication is disabled server-side. A key is not optional. |
| RDP | 3389 | Open, for GUI debugging. Needs a valid `Administrator` password, which is a separate credential from the SSH key. |
| WinRM | 5985 / 5986 | **Blocked** by the cloud security group. Not available, do not plan around it. |
| SMB | 445 | **Blocked** by the cloud security group. |

Host facts: Windows Server 2022 Datacenter (build 20348), 4 vCPU / 7.7 GiB, ~182 GiB free on `C:`,
`sshd` Running and Automatic, default SSH shell is `cmd.exe`, and **only Windows PowerShell 5.1 is
present — there is no `pwsh`.** That last one is load-bearing: workflow steps must say
`shell: powershell`, never `shell: pwsh`, or they fail with a command-not-found on this machine.

Three traps that cost real time here. Do not repeat them:

- **Check configured identities before concluding a host is unreachable.** This host was written
  off as inaccessible for an entire work session because a freshly generated key was the only one
  tested — and that key was, of course, not installed. The key already named by the machine's SSH
  configuration was authorized. Do not enumerate or offer unrelated private keys to a host.
- **A local TUN/HTTP proxy makes every port look open.** `nc -z` against this host reported
  22, 135, 445, 3389, 5985, 5986 and even 80 as open, because the proxy accepts the CONNECT and
  answers optimistically. Only a real protocol handshake tells the truth: an SSH banner, an X.224
  connection confirm, a genuine HTTP status.
- **`xfreerdp /auth-only` is not a credential test.** It prints
  `[ERROR] ... Authentication only, exit status 0` even when authentication *failed*. The only
  trustworthy signal is the NTSTATUS on the `nla_decode_ts_request` line
  (`STATUS_LOGON_FAILURE 0xc000006d` = bad credentials).

### If key auth ever stops working

`sshd` **silently** refuses `administrators_authorized_keys` unless its ACL is exactly
Administrators + SYSTEM; inherited user ACEs are the usual cause of "the key does nothing":

```powershell
$f = 'C:\ProgramData\ssh\administrators_authorized_keys'
icacls $f /inheritance:r /grant Administrators:F /grant SYSTEM:F
Get-Service sshd | Set-Service -StartupType Automatic
Restart-Service sshd
```

Then check `C:\ProgramData\ssh\sshd_config` for `PubkeyAuthentication yes` and the
`Match Group administrators` block at the bottom, and read
`Get-WinEvent -LogName OpenSSH/Operational`.

### Sending this kit to the machine

```console
$ ssh windows 'if not exist C:\ops mkdir C:\ops'
$ scp -r ops/windows-runner windows:C:/ops/
```

Everything here only makes outbound HTTPS calls, so it also works from a GUI session with no
inbound access at all.

---

## 0b. Network reality: this box is in China, and it decides every download URL

Measured from the machine itself. This is not a footnote — it is the difference between a
provisioning run that finishes in minutes and one that never finishes at all.

| Source | Measured | Verdict |
| --- | ---: | --- |
| `static.rust-lang.org` | 46 KB/s | unusable |
| `github.com` release assets | 36 KB/s, often times out | unusable |
| `nodejs.org` | connection times out | **unreachable** |
| `www.python.org` | 1 KB/s | **unreachable in practice** |
| `aka.ms` (VS bootstrapper) | 9.2 MB/s | fine as-is |
| `registry.npmmirror.com` | 12–14 MB/s | **use this** |
| `mirrors.tuna.tsinghua.edu.cn` | 6.3 MB/s | **use this** |

Working mirror URLs, each one verified by downloading from this host:

```
Git      https://registry.npmmirror.com/-/binary/git-for-windows/v2.51.0.windows.1/Git-2.51.0-64-bit.exe
Node     https://registry.npmmirror.com/-/binary/node/v22.18.0/node-v22.18.0-x64.msi
Python   https://registry.npmmirror.com/-/binary/python/3.12.7/python-3.12.7-amd64.exe
rustup   https://mirrors.tuna.tsinghua.edu.cn/rustup/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe
VS       https://aka.ms/vs/17/release/vs_BuildTools.exe          (already fast, keep)
```

Note the rustup path has `rustup` twice; `mirrors.tuna.tsinghua.edu.cn/rustup/dist/...` is a 404,
and `rsproxy.cn/dist/...` is also a 404. Both were tried.

For comparison: Git for Windows is 61.7 MB. From the mirror it took **4.6 seconds**. From
github.com at 36 KB/s it would take roughly **45 minutes**, assuming it did not time out first.

### The Actions runner package must be side-loaded

`github.com/actions/runner/releases/download/...` **times out** from this host, so the runner
cannot download itself. Fetch it on a machine with working international egress and copy it over:

```console
$ curl -sSLO https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-win-x64-2.336.0.zip
$ shasum -a 256 actions-runner-win-x64-2.336.0.zip
  d59123a43003e357b0805b5d0f611d0bd2f65ab67d51bd070dd4e7a0f685c162
$ scp actions-runner-win-x64-2.336.0.zip windows:C:/bootstrap-cache/
```

The upload took 15 s for 103 MB, so the constraint is purely the international egress, not the
link to the box. Pass the file to `install-runner.ps1` rather than letting it fetch.

### But the runner itself will work: the control plane is reachable

This was the open question, and it is answered. Every endpoint an Actions runner needs responds
fast from this host:

| Endpoint | Result |
| --- | --- |
| `api.github.com` | **HTTP 200 in 0.4 s** — registration and job acquisition |
| `pipelines.actions.githubusercontent.com` | reachable |
| `vstoken.actions.githubusercontent.com` | reachable |
| `results-receiver.actions.githubusercontent.com` | reachable |
| `codeload.github.com` | **HTTP 200 in 0.8 s** — this is what `actions/checkout` uses |

`raw.githubusercontent.com` and plain `github.com` time out, so avoid workflow steps that curl
either one. Anything that fetches a release asset by URL — the kind of step that installs a pinned
tool — will be slow or hang on this runner and needs a mirror or a side-loaded copy.

### Still unverified

`crates.io` throughput from this host has **not** been measured. If it is as slow as the other
international sources, a cold `cargo check --workspace` will be dominated by crate downloads rather
than compilation, and the machine will need a sparse-registry mirror in a machine-wide
`config.toml` under `CARGO_HOME`. Measure before concluding the runner is slow at building.

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

On this China-hosted runner, keep the verified offline cache and route the remaining Rust
toolchain/crate traffic through the measured regional endpoints. The bootstrap persists Rustup at
machine scope and writes Cargo's documented source replacement to
`C:\rust\cargo\config.toml`, so both `NETWORK SERVICE` runner services inherit them:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 `
    -ChecksumFile .\checksums.json `
    -DownloadCache C:\bootstrap-cache `
    -RustupDistServer https://rsproxy.cn `
    -RustupUpdateRoot https://rsproxy.cn/rustup `
    -CargoRegistryIndex sparse+https://rsproxy.cn/index/
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

Rust re-runs are offline-idempotent once that exact toolchain, both components and the target are
installed. The script inventories only local rustup metadata before any install/update command; a
healthy installation skips the Rust dist server completely, so retirement of an old manifest by a
regional mirror cannot break an otherwise healthy runner. If the toolchain, a component or the
target is actually missing, the script fetches only the missing surface and still exits non-zero if
the mirror cannot supply it or the post-install inventory remains incomplete.

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

| Repository | Instance / workspace | Label | Repository variable |
| --- | --- | --- | --- |
| `Plantcore-AI/Iteron` | `C:\actions-runner\iteron` / `C:\actions-runner\iteron\_work` | `iteron-win` | `WINDOWS_RUNNER_LABELS` (JSON array) |
| `Plantcore-AI/plantcore-desktop` | `C:\actions-runner\desktop` / `C:\actions-runner\desktop\_work` | `desktop-win` | `WINDOWS_RUNNER` (single label) |

These are two repository-scoped registrations and therefore two Windows services. Their runner
workspaces cannot overlap: `install-runner.ps1` accepts only a relative one-segment `-WorkFolder`
and resolves it below the selected instance directory. The workflows also keep Rust target output
in repository-specific directories, so simultaneous Iteron and Desktop jobs cannot contend for the
same Cargo target lock.

Resolve the runner version and its hash first (both are required parameters; neither is defaulted,
because guessing one desynchronises it from the other):

```powershell
# On any machine with gh:
gh api repos/actions/runner/releases/latest --jq .tag_name
gh release view <tag> --repo actions/runner --json body --jq .body   # contains the win-x64 SHA-256
```

Then, in an **elevated Windows PowerShell session** on the Windows box, invoke the script directly
twice. Each repository needs its own short-lived registration token. Both values remain only in
the current PowerShell process, are passed as `SecureString`, and are disposed after registration:

```powershell
# Fill these from the release query above. Do not guess either value.
$runnerVersion = '<version-without-v>'
$runnerSha256 = '<64-hex-from-the-release-body>'

# Iteron service: C:\actions-runner\iteron, label iteron-win.
$iteronToken = ConvertTo-SecureString `
    (gh api --method POST repos/Plantcore-AI/Iteron/actions/runners/registration-token --jq .token) `
    -AsPlainText -Force
try {
    & .\install-runner.ps1 `
        -Repo Plantcore-AI/Iteron `
        -Instance iteron `
        -Labels iteron-win `
        -RunnerVersion $runnerVersion `
        -RunnerSha256 $runnerSha256 `
        -Token $iteronToken
} finally {
    $iteronToken.Dispose()
    Remove-Variable iteronToken -ErrorAction SilentlyContinue
}

# Desktop service: C:\actions-runner\desktop, label desktop-win.
$desktopToken = ConvertTo-SecureString `
    (gh api --method POST repos/Plantcore-AI/plantcore-desktop/actions/runners/registration-token --jq .token) `
    -AsPlainText -Force
try {
    & .\install-runner.ps1 `
        -Repo Plantcore-AI/plantcore-desktop `
        -Instance desktop `
        -Labels desktop-win `
        -RunnerVersion $runnerVersion `
        -RunnerSha256 $runnerSha256 `
        -Token $desktopToken
} finally {
    $desktopToken.Dispose()
    Remove-Variable desktopToken -ErrorAction SilentlyContinue
}

Get-Service actions.runner.* | Select-Object Name, Status, StartType
```

If `gh` is not installed on the Windows box, generate the token on your laptop and paste it in
without echoing it:

```powershell
$iteronToken = Read-Host -AsSecureString "Iteron registration token"
```

Repeat the prompt immediately before the Desktop invocation. Do not save either token in a file,
shell profile, command history, CI variable, or report. If `-Instance` and `-Labels` are omitted,
the same `iteron`/`iteron-win` and `desktop`/`desktop-win` values are derived from the repo name.

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

The desktop repository is a **separate** setting with its own variable and its own runner label;
setting one does not affect the other. After its runner is Online:

```bash
gh variable set WINDOWS_RUNNER --repo Plantcore-AI/plantcore-desktop --body desktop-win
```

While `WINDOWS_RUNNER` is unset, Desktop keeps using `windows-latest`. Its rollback is likewise
only the variable deletion:

```bash
gh variable delete WINDOWS_RUNNER --repo Plantcore-AI/plantcore-desktop
```

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
  fresh VM: the repository-specific workspace, Cargo registry cache and isolated CI target
  directory persist between jobs, so a
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
| `register-runner.ps1` | SSH-safe non-interactive bridge: clears the short-lived registration token from process environment, then calls `install-runner.ps1`. |
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
