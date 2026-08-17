<#
.SYNOPSIS
    Provisions a bare Windows Server machine with everything needed to build and test this Rust
    workspace for `x86_64-pc-windows-msvc`, plus the Tauri desktop app (issue #227).

.DESCRIPTION
    Idempotent and re-runnable. Every step first checks whether the tool is already present and
    only installs when it is not, so a second run is close to a no-op and a partially failed run
    can simply be re-run.

    Fail-closed by construction:
      * `$ErrorActionPreference = 'Stop'` and `Set-StrictMode -Version Latest`.
      * Every download is HTTPS and is verified against a pinned SHA-256. There are NO default
        hashes in this file: the pin table below ships EMPTY on purpose. An unset, malformed or
        mismatching hash aborts the script. See `README.md` -> "Checksum pinning".
      * The final phase re-invokes every tool and prints its version; a missing tool is an error.

    What it installs:
      * Visual Studio Build Tools (C++ workload + Windows SDK) -- the MSVC linker.
      * Rust pinned to the toolchain this repo pins in CI (default 1.90.0), machine-wide, with the
        `x86_64-pc-windows-msvc` target and the `clippy` / `rustfmt` components.
      * Git for Windows (also supplies `bash.exe`, which the CI jobs run with `shell: bash`).
      * Node.js 22 (the desktop repo's CI pins node 22).
      * CPython 3.11+ -- the whole release pipeline (`release-tools/*.py`, driven by
        `.github/workflows/release.yml`) is Python, and those tools import `tomllib`. Installed so
        that BOTH `python` and `python3` resolve on PATH, in cmd, PowerShell and Git bash.
      * WebView2 Runtime, NSIS and WiX 3 -- required to build/package the Tauri desktop app.

    Deliberately NOT installed: 7-Zip. Windows Server ships `tar.exe` (bsdtar) and PowerShell
    `Expand-Archive`, which cover every archive this fleet touches; skipping it removes one more
    unpinnable third-party download. The verification phase asserts both are present.

.PARAMETER ChecksumFile
    Optional JSON file mapping artifact file name -> SHA-256, merged over the in-script pin table.
    Lets an operator pin hashes without editing this file. See `checksums.example.json`.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 -ChecksumFile .\checksums.json

.NOTES
    PowerShell 5.1 compatible (Windows Server ships 5.1). Must run elevated.
    No secret, token or cloud AccessKey is read, written or accepted by this script.
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ChecksumFile,

    # Downloads are cached here so a re-run does not re-fetch. Safe to delete.
    [Parameter()]
    [string]$DownloadCache = 'C:\bootstrap-cache',

    # Keep in step with `RUSTUP_TOOLCHAIN` in .github/workflows/{ci,windows,release}.yml.
    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$RustToolchain = '1.90.0',

    [Parameter()]
    [string]$RustTarget = 'x86_64-pc-windows-msvc',

    # Rust is installed MACHINE-wide, not into a user profile: the Actions runner service runs as
    # NT AUTHORITY\NETWORK SERVICE by default and would never see `%USERPROFILE%\.cargo`.
    [Parameter()]
    [string]$RustRoot = 'C:\rust',

    # Optional regional mirrors. Persist these machine-wide so both runner services inherit them.
    # Leave empty to use the upstream defaults.
    [Parameter()]
    [string]$RustupDistServer,

    [Parameter()]
    [string]$RustupUpdateRoot,

    [Parameter()]
    [string]$CargoRegistryIndex,

    [Parameter()]
    [string]$VsInstallPath = 'C:\BuildTools',

    # Windows SDK component id. `...Windows11SDK.22621` is valid on every VS 17.x; `.26100` is the
    # Windows Server 2025 / 24H2 SDK on VS 17.10+. Change together with its pinned hash-free
    # installer (the SDK is a component of the same vs_BuildTools.exe download).
    [Parameter()]
    [string]$WindowsSdkComponent = 'Microsoft.VisualStudio.Component.Windows11SDK.22621',

    # Version knobs. Changing any of these changes the artifact FILE NAME, which is the key into
    # the pin table -- so a version bump fails closed until its hash is pinned too. That is the
    # point.
    [Parameter()]
    [string]$GitVersion = '2.51.0',

    [Parameter()]
    [string]$GitWindowsRevision = '1',

    [Parameter()]
    [string]$NodeVersion = '22.18.0',

    # CPython. The release pipeline (`release-tools/*.py`, driven by .github/workflows/release.yml)
    # is Python, and those tools use `tomllib`, which is 3.11+. Do not drop below 3.11.
    [Parameter()]
    [ValidatePattern('^3\.(1[1-9]|[2-9]\d)\.\d+$')]
    [string]$PythonVersion = '3.12.7',

    [Parameter()]
    [string]$NsisVersion = '3.10',

    [Parameter()]
    [string]$WixReleaseTag = 'wix3141rtm',

    [switch]$SkipVisualStudio,
    [switch]$SkipRust,
    [switch]$SkipGit,
    [switch]$SkipNode,
    [switch]$SkipPython,
    [switch]$SkipWebView2,
    [switch]$SkipNsis,
    [switch]$SkipWix,

    # Opt-in: excluding the Cargo/target trees from Defender roughly halves cold Rust build time on
    # this hardware, but it is a real reduction in on-host scanning. Off by default; the operator
    # decides. Only ever excludes build/cache paths, never a whole drive.
    [switch]$AddDefenderExclusions
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

# TLS 1.2+ is required by every vendor host below and is not the .NET default under PS 5.1.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ---------------------------------------------------------------------------------------------
# OPERATOR-MAINTAINED CHECKSUM PIN TABLE
# ---------------------------------------------------------------------------------------------
# Keys are the exact downloaded FILE NAME. Values are lowercase SHA-256 hex, 64 chars.
#
# THESE SHIP EMPTY ON PURPOSE. No hash in this repo was invented. An empty, malformed or
# mismatching value aborts the run before anything is executed. Fill them in once, commit them
# through review, and refresh them deliberately whenever a vendor rotates an artifact -- a
# rotation shows up here as a loud checksum failure, which is exactly the signal you want.
#
# Where the vendor publishes a hash you can verify independently, USE IT:
#   rustup-init.exe   https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe.sha256
#   node-*.msi        https://nodejs.org/dist/v<NodeVersion>/SHASUMS256.txt   (signed: SHASUMS256.txt.sig)
#   Git-*-64-bit.exe  the release body of https://github.com/git-for-windows/git/releases/tag/v<ver>
#   wix314.exe        the release body of https://github.com/wixtoolset/wix3/releases/tag/<tag>
#   python-*-amd64.exe  python.org publishes an MD5 and a GPG signature (`<file>.asc`) plus a
#                       sigstore bundle, not a SHA-256. Verify the signature FIRST, then pin the
#                       SHA-256 of the file you verified.
#
# Two artifacts have NO vendor-published per-build hash, because Microsoft rotates them silently
# behind an aka.ms/go.microsoft.com redirect:
#   vs_BuildTools.exe, MicrosoftEdgeWebview2Setup.exe
# For those the pin is a CHANGE DETECTOR, not a supply-chain proof: download once over HTTPS from
# the Microsoft host, record the hash, and treat a later mismatch as "Microsoft shipped a new
# bootstrapper -- re-verify and re-pin", never as "just overwrite it". README documents this.
# ---------------------------------------------------------------------------------------------
$script:PinnedSha256 = @{
    'vs_BuildTools.exe'              = ''   # FILL ME (Microsoft bootstrapper; rotates, see above)
    'rustup-init.exe'                = ''   # FILL ME (rustup-init.exe.sha256 next to the artifact)
    "Git-$GitVersion-64-bit.exe"     = ''   # FILL ME (git-for-windows release body)
    "node-v$NodeVersion-x64.msi"     = ''   # FILL ME (nodejs.org SHASUMS256.txt)
    "python-$PythonVersion-amd64.exe" = ''  # FILL ME (python.org: verify the .asc, then pin sha256)
    "nsis-$NsisVersion-setup.exe"    = ''   # FILL ME (sourceforge file listing shows SHA-256)
    'wix314.exe'                     = ''   # FILL ME (wixtoolset/wix3 release body)
    'MicrosoftEdgeWebview2Setup.exe' = ''   # FILL ME (Microsoft bootstrapper; rotates, see above)
}

$script:ChecksumOverrides = @{}
$script:RebootRequired = $false
$script:Summary = New-Object System.Collections.ArrayList

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    ok: $Message" -ForegroundColor Green
}

function Write-Note {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    note: $Message" -ForegroundColor Yellow
}

function Add-Summary {
    param([Parameter(Mandatory)][string]$Component, [Parameter(Mandatory)][string]$State)
    [void]$script:Summary.Add([pscustomobject]@{ Component = $Component; State = $State })
}

function Import-ChecksumFile {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "ChecksumFile '$Path' does not exist."
    }
    $raw = Get-Content -LiteralPath $Path -Raw
    $json = $raw | ConvertFrom-Json
    foreach ($prop in $json.PSObject.Properties) {
        if ($prop.Name -like '_*') { continue }   # `_comment` style keys are ignored
        $script:ChecksumOverrides[$prop.Name] = [string]$prop.Value
    }
    Write-Ok "loaded $($script:ChecksumOverrides.Count) checksum pin(s) from $Path"
}

function Get-PinnedSha256 {
    param([Parameter(Mandatory)][string]$FileName)

    $value = $null
    if ($script:ChecksumOverrides.ContainsKey($FileName)) {
        $value = $script:ChecksumOverrides[$FileName]
    } elseif ($script:PinnedSha256.ContainsKey($FileName)) {
        $value = $script:PinnedSha256[$FileName]
    } else {
        throw @"
No SHA-256 pin exists for '$FileName'.
This usually means a version parameter was changed without pinning the new artifact.
Add the hash to `$script:PinnedSha256 in bootstrap.ps1, or pass -ChecksumFile with a JSON entry:
  { "$FileName": "<64 hex chars>" }
Refresh helper (trust-on-first-use, read its warning first): .\refresh-checksums.ps1
"@
    }

    if ([string]::IsNullOrWhiteSpace($value)) {
        throw @"
SHA-256 pin for '$FileName' is EMPTY. Refusing to download an unverified artifact.
Fill it in bootstrap.ps1's pin table or pass -ChecksumFile. See README.md -> "Checksum pinning".
"@
    }
    if ($value -notmatch '^[0-9a-fA-F]{64}$') {
        throw "SHA-256 pin for '$FileName' is not 64 hex characters: '$value'."
    }
    return $value.ToLowerInvariant()
}

function Invoke-PinnedDownload {
    <#
      Downloads $Url to the cache and returns the local path, after verifying its SHA-256 against
      the pin table. A cached file that already matches is reused (idempotence). A file that does
      NOT match is left on disk as `<name>.rejected` for forensics and the run aborts.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$FileName
    )

    if ($Url -notmatch '^https://') { throw "Refusing non-HTTPS download URL: $Url" }
    $expected = Get-PinnedSha256 -FileName $FileName

    if (-not (Test-Path -LiteralPath $DownloadCache)) {
        [void](New-Item -ItemType Directory -Path $DownloadCache -Force)
    }
    $target = Join-Path $DownloadCache $FileName

    if (Test-Path -LiteralPath $target) {
        $have = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($have -eq $expected) {
            Write-Ok "cached and checksum-verified: $FileName"
            return $target
        }
        Write-Note "cached $FileName has an unexpected hash; re-downloading"
        Remove-Item -LiteralPath $target -Force
    }

    $partial = "$target.part"
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    Write-Host "    downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $partial -UseBasicParsing -MaximumRedirection 10

    $actual = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        $rejected = "$target.rejected"
        if (Test-Path -LiteralPath $rejected) { Remove-Item -LiteralPath $rejected -Force }
        Move-Item -LiteralPath $partial -Destination $rejected
        throw @"
CHECKSUM MISMATCH for $FileName
  url      : $Url
  expected : $expected
  actual   : $actual
  kept at  : $rejected
Do NOT 'fix' this by copying the actual hash into the pin table without understanding why the
artifact changed. If the vendor legitimately rotated the file, re-verify it against the vendor's
own published hash (or, for the Microsoft bootstrappers, against a fresh download on a second
network path) and then re-pin deliberately.
"@
    }
    Move-Item -LiteralPath $partial -Destination $target
    Write-Ok "downloaded and checksum-verified: $FileName"
    return $target
}

function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int[]]$SuccessExitCodes = @(0),
        [Parameter(Mandatory)][string]$What
    )
    Write-Host "    running: $FilePath $($Arguments -join ' ')"
    $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
    $code = $proc.ExitCode
    if ($code -eq 3010) {
        # 3010 == ERROR_SUCCESS_REBOOT_REQUIRED. Success, but the machine wants a restart.
        $script:RebootRequired = $true
    }
    if ($SuccessExitCodes -notcontains $code) {
        throw "$What failed with exit code $code."
    }
    Write-Ok "$What (exit $code)"
}

function Set-MachineEnvVar {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    $current = [Environment]::GetEnvironmentVariable($Name, 'Machine')
    if ($current -ne $Value) {
        [Environment]::SetEnvironmentVariable($Name, $Value, 'Machine')
        Write-Ok "machine env $Name = $Value"
    }
    Set-Item -Path "Env:$Name" -Value $Value
}

function Add-MachinePathEntry {
    param([Parameter(Mandatory)][string]$Entry)
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($machinePath -split ';' | Where-Object { $_ -ne '' })
    if ($parts -notcontains $Entry) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $Entry) -join ';'), 'Machine')
        Write-Ok "machine PATH += $Entry"
    }
    $sessionParts = @($env:Path -split ';' | Where-Object { $_ -ne '' })
    if ($sessionParts -notcontains $Entry) { $env:Path = "$env:Path;$Entry" }
}

function Test-CommandVersion {
    <# Returns the trimmed first line of `<cmd> <args>` output, or $null if the command is absent. #>
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Arguments = @('--version')
    )
    $resolved = Get-Command $Command -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $resolved) { return $null }
    $previousErrorAction = $ErrorActionPreference
    try {
        # Several healthy version commands (notably rustup 1.29) write informational lines to
        # stderr. Under this script's fail-closed Stop preference, PS 5.1 promotes those native
        # lines to a terminating NativeCommandError even when the process exits zero.
        $ErrorActionPreference = 'Continue'
        $out = & $resolved.Source @Arguments 2>&1
    } catch {
        return $null
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($null -eq $out) { return $null }
    $line = @($out | ForEach-Object { "$_" } | Where-Object { $_.Trim() -ne '' }) | Select-Object -First 1
    if ($null -eq $line) { return $null }
    return $line.Trim()
}

function Get-VsWherePath {
    $candidate = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $candidate) { return $candidate }
    return $null
}

function Get-VcToolsInstallPath {
    $vswhere = Get-VsWherePath
    if ($null -eq $vswhere) { return $null }
    $out = & $vswhere -products '*' -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null
    $path = @($out | Where-Object { $_ -and $_.Trim() -ne '' }) | Select-Object -First 1
    if ($null -eq $path) { return $null }
    return $path.Trim()
}

function Find-MsvcLinker {
    param([Parameter(Mandatory)][string]$InstallPath)
    $root = Join-Path $InstallPath 'VC\Tools\MSVC'
    if (-not (Test-Path -LiteralPath $root)) { return $null }
    $link = Get-ChildItem -Path $root -Filter 'link.exe' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like '*\bin\Hostx64\x64\*' } |
        Select-Object -First 1
    if ($null -eq $link) { return $null }
    return $link.FullName
}

# ---------------------------------------------------------------------------------------------
# Install steps
# ---------------------------------------------------------------------------------------------

function Install-VisualStudioBuildTools {
    Write-Step 'Visual Studio Build Tools (C++ workload + Windows SDK)'
    $existing = Get-VcToolsInstallPath
    if ($null -ne $existing) {
        Write-Ok "already installed at $existing"
        Add-Summary -Component 'VS Build Tools' -State 'present'
        return
    }

    $installer = Invoke-PinnedDownload `
        -Url 'https://aka.ms/vs/17/release/vs_BuildTools.exe' `
        -FileName 'vs_BuildTools.exe'

    # `--quiet --wait --norestart` is the documented unattended form. The channel/installer cache
    # is left in place (`--nocache` is deliberately NOT passed) so a later `modify` does not have
    # to re-download the whole layer.
    $installArgs = @(
        '--quiet', '--wait', '--norestart',
        '--installPath', $VsInstallPath,
        '--add', 'Microsoft.VisualStudio.Workload.VCTools',
        '--add', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
        '--add', $WindowsSdkComponent,
        '--includeRecommended'
    )
    # 3010 = reboot required, 1641 = reboot initiated -- both are successful installs.
    Invoke-Native -FilePath $installer -Arguments $installArgs -SuccessExitCodes @(0, 3010, 1641) `
        -What 'vs_BuildTools.exe install'

    $now = Get-VcToolsInstallPath
    if ($null -eq $now) {
        throw 'VS Build Tools reported success but vswhere still cannot find the VC++ tools component.'
    }
    Write-Ok "installed at $now"
    Add-Summary -Component 'VS Build Tools' -State 'installed'
}

function Install-Rust {
    Write-Step "Rust $RustToolchain (machine-wide, target $RustTarget)"

    if (-not [string]::IsNullOrWhiteSpace($RustupDistServer)) {
        if ($RustupDistServer -notmatch '^https://') {
            throw 'RustupDistServer must be an HTTPS URL.'
        }
        Set-MachineEnvVar -Name 'RUSTUP_DIST_SERVER' -Value $RustupDistServer.TrimEnd('/')
    }
    if (-not [string]::IsNullOrWhiteSpace($RustupUpdateRoot)) {
        if ($RustupUpdateRoot -notmatch '^https://') {
            throw 'RustupUpdateRoot must be an HTTPS URL.'
        }
        Set-MachineEnvVar -Name 'RUSTUP_UPDATE_ROOT' -Value $RustupUpdateRoot.TrimEnd('/')
    }
    if (-not [string]::IsNullOrWhiteSpace($CargoRegistryIndex)) {
        if ($CargoRegistryIndex -notmatch '^(sparse\+)?https://') {
            throw 'CargoRegistryIndex must be an HTTPS or sparse+HTTPS URL.'
        }
        Set-MachineEnvVar -Name 'CARGO_REGISTRIES_CRATES_IO_INDEX' -Value $CargoRegistryIndex
    }

    # Machine-wide CARGO_HOME/RUSTUP_HOME: the runner service account is NOT the interactive
    # Administrator, so a per-user ~/.cargo would be invisible to CI.
    $cargoHome = Join-Path $RustRoot 'cargo'
    $rustupHome = Join-Path $RustRoot 'rustup'
    foreach ($dir in @($RustRoot, $cargoHome, $rustupHome)) {
        if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    }
    if (-not [string]::IsNullOrWhiteSpace($CargoRegistryIndex)) {
        # CARGO_REGISTRIES_CRATES_IO_INDEX alone does not replace Cargo's built-in crates.io
        # source. Write the documented source replacement into the machine-wide CARGO_HOME so
        # NETWORK SERVICE fetches both the sparse index and crate payloads through the mirror.
        $cargoConfig = @"
[source.crates-io]
replace-with = "iteron-mirror"

[source.iteron-mirror]
registry = "$CargoRegistryIndex"

[net]
git-fetch-with-cli = true
"@
        $cargoConfigPath = Join-Path $cargoHome 'config.toml'
        Set-Content -LiteralPath $cargoConfigPath -Value $cargoConfig -Encoding ascii
        Write-Ok "Cargo crates.io source replacement = $CargoRegistryIndex"
    }
    Set-MachineEnvVar -Name 'CARGO_HOME' -Value $cargoHome
    Set-MachineEnvVar -Name 'RUSTUP_HOME' -Value $rustupHome
    # Pin the toolchain for every process on the box, exactly like the workflows' env do.
    Set-MachineEnvVar -Name 'RUSTUP_TOOLCHAIN' -Value $RustToolchain
    Add-MachinePathEntry -Entry (Join-Path $cargoHome 'bin')

    $rustup = Get-Command 'rustup' -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $rustup) {
        $init = Invoke-PinnedDownload `
            -Url 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' `
            -FileName 'rustup-init.exe'
        $installArgs = @(
            '-y',
            '--no-modify-path',            # PATH is managed above, machine-wide
            '--profile', 'minimal',
            '--default-host', 'x86_64-pc-windows-msvc',
            '--default-toolchain', $RustToolchain,
            '--component', 'clippy',
            '--component', 'rustfmt',
            '--target', $RustTarget
        )
        Invoke-Native -FilePath $init -Arguments $installArgs -What "rustup-init (pin $RustToolchain)"
        Add-Summary -Component 'Rust' -State 'installed'
    } else {
        Write-Ok "rustup already present at $($rustup.Source)"
        Add-Summary -Component 'Rust' -State 'present'
    }

    # Idempotent either way: installing an already-installed toolchain/target/component is a no-op.
    Invoke-Native -FilePath 'rustup' -Arguments @(
        'toolchain', 'install', $RustToolchain, '--profile', 'minimal',
        '--component', 'clippy', '--component', 'rustfmt', '--target', $RustTarget
    ) -What "rustup toolchain install $RustToolchain"
    Invoke-Native -FilePath 'rustup' -Arguments @('default', $RustToolchain) `
        -What "rustup default $RustToolchain"
    Invoke-Native -FilePath 'rustup' -Arguments @(
        'target', 'add', $RustTarget, '--toolchain', $RustToolchain
    ) -What "rustup target add $RustTarget"

    # The runner service account must be able to write the registry cache and build dirs.
    Grant-ServiceAccountWrite -Path $RustRoot
}

function Grant-ServiceAccountWrite {
    <#
      Grants Modify to the default Actions-runner service account (NETWORK SERVICE) and to
      BUILTIN\Users. Without this, `cargo` cannot write $CARGO_HOME/registry when the runner runs
      as a service and every build fails with a permission error that looks like a network fault.
    #>
    param([Parameter(Mandatory)][string]$Path)
    foreach ($principal in @('NT AUTHORITY\NETWORK SERVICE', 'BUILTIN\Users')) {
        & icacls.exe $Path '/grant' "${principal}:(OI)(CI)M" '/T' '/C' '/Q' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Note "icacls could not grant Modify on $Path to $principal (exit $LASTEXITCODE)"
        }
    }
    Write-Ok "ACLs on $Path allow the runner service account to write"
}

function Install-GitForWindows {
    Write-Step "Git for Windows $GitVersion"
    $tag = "v$GitVersion.windows.$GitWindowsRevision"
    $file = "Git-$GitVersion-64-bit.exe"
    $gitBin = Join-Path $env:ProgramFiles 'Git\bin'
    $gitCmd = Join-Path $env:ProgramFiles 'Git\cmd'

    $gitExe = Join-Path $gitCmd 'git.exe'
    $have = if (Test-Path -LiteralPath $gitExe) {
        Test-CommandVersion -Command $gitExe
    } else {
        Test-CommandVersion -Command 'git'
    }
    if ($null -ne $have) {
        Write-Ok "already installed: $have"
        Add-Summary -Component 'Git' -State 'present'
    } else {
        $installer = Invoke-PinnedDownload `
            -Url "https://github.com/git-for-windows/git/releases/download/$tag/$file" `
            -FileName $file
        # Inno Setup unattended switches. CRLFCommitAsIs keeps checkouts byte-identical to the
        # POSIX runners -- this repo compares golden fixtures byte-for-byte.
        $installArgs = @(
            '/VERYSILENT', '/NORESTART', '/NOCANCEL', '/SP-', '/SUPPRESSMSGBOXES',
            '/o:PathOption=CmdTools',
            '/o:CRLFOption=CRLFCommitAsIs',
            '/o:BashTerminalOption=ConHost'
        )
        Invoke-Native -FilePath $installer -Arguments $installArgs -SuccessExitCodes @(0, 3010) `
            -What "Git for Windows $GitVersion install"
        Add-Summary -Component 'Git' -State 'installed'
    }

    # CI jobs in this repo run `shell: bash` on Windows, which resolves `bash` from PATH. The
    # Inno "CmdTools" option only puts Git\cmd on PATH (git.exe, no bash.exe), so add Git\bin
    # explicitly -- otherwise every Windows job dies at the first step with "bash not found".
    foreach ($dir in @($gitCmd, $gitBin)) {
        if (Test-Path -LiteralPath $dir) { Add-MachinePathEntry -Entry $dir }
    }

    # Long paths: Rust target dirs plus this workspace's nested fixture paths overrun MAX_PATH.
    & git config --system core.longpaths true
    if ($LASTEXITCODE -ne 0) { Write-Note 'could not set system git core.longpaths' }
}

function Install-NodeJs {
    Write-Step "Node.js $NodeVersion"
    $nodeDir = Join-Path $env:ProgramFiles 'nodejs'
    $nodeExe = Join-Path $nodeDir 'node.exe'
    $have = if (Test-Path -LiteralPath $nodeExe) {
        Test-CommandVersion -Command $nodeExe
    } else {
        Test-CommandVersion -Command 'node'
    }
    if ($null -ne $have -and $have -like 'v22.*') {
        Write-Ok "already installed: $have"
        Add-MachinePathEntry -Entry $nodeDir
        Add-Summary -Component 'Node.js' -State 'present'
        return
    }
    if ($null -ne $have) { Write-Note "replacing unexpected node version: $have" }

    $file = "node-v$NodeVersion-x64.msi"
    $msi = Invoke-PinnedDownload -Url "https://nodejs.org/dist/v$NodeVersion/$file" -FileName $file
    Invoke-Native -FilePath 'msiexec.exe' -Arguments @(
        '/i', "`"$msi`"", '/qn', '/norestart', 'ADDLOCAL=ALL'
    ) -SuccessExitCodes @(0, 3010) -What "Node.js $NodeVersion install"
    Add-MachinePathEntry -Entry $nodeDir
    Add-Summary -Component 'Node.js' -State 'installed'
}

function Install-Python {
    Write-Step "CPython $PythonVersion (release-tools/*.py)"

    $pythonDirName = 'Python' + (($PythonVersion -split '\.')[0] + ($PythonVersion -split '\.')[1])
    $installDir = Join-Path $env:ProgramFiles $pythonDirName
    $candidate = Join-Path $installDir 'python.exe'
    $pythonCommand = if (Test-Path -LiteralPath $candidate) { $candidate } else { 'python' }
    $existing = Test-CommandVersion -Command $pythonCommand
    $needInstall = $true
    if ($null -ne $existing -and $existing -match '^Python 3\.(\d+)\.') {
        $minor = [int]$Matches[1]
        $found = Get-Command $pythonCommand -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $found -and $found.Source -like '*\WindowsApps\*') {
            # Microsoft Store alias stub, not a real interpreter. Never treat it as installed.
            Write-Note 'the python on PATH is the Store alias stub; installing a real CPython'
            $minor = 0
        }
        if ($minor -ge 11) {
            Write-Ok "already installed: $existing"
            Add-Summary -Component 'Python' -State 'present'
            $needInstall = $false
            $resolved = Get-Command $pythonCommand -CommandType Application | Select-Object -First 1
            $installDir = Split-Path -Parent $resolved.Source
        } else {
            Write-Note "found $existing, which is older than 3.11 (release-tools need tomllib); installing $PythonVersion alongside"
        }
    }

    if ($needInstall) {
        $file = "python-$PythonVersion-amd64.exe"
        $setup = Invoke-PinnedDownload -Url "https://www.python.org/ftp/python/$PythonVersion/$file" -FileName $file
        # All-users install so the runner service account can use it. The py launcher is included
        # because some tooling shells out to `py -3`.
        $installArgs = @(
            '/quiet',
            'InstallAllUsers=1',
            'PrependPath=1',
            'Include_launcher=1',
            'InstallLauncherAllUsers=1',
            'Include_test=0',
            'Include_doc=0',
            "`"TargetDir=$installDir`""
        )
        Invoke-Native -FilePath $setup -Arguments $installArgs -SuccessExitCodes @(0, 3010) `
            -What "CPython $PythonVersion install"
        Add-Summary -Component 'Python' -State 'installed'
    }

    # `python3` on Windows. The python.org installer ships `python.exe` and the `py` launcher but
    # NO `python3.exe`, while `release.yml` invokes the interpreter through a matrix value that is
    # `python3` on the POSIX legs. A copy of python.exe named python3.exe in the SAME directory
    # resolves correctly (CPython derives its prefix from the executable's directory) and is found
    # by cmd, PowerShell AND Git bash -- a `python3.cmd` shim would not be, because MSYS bash only
    # probes `python3` and `python3.exe` on PATH. This is what makes `python3` usable in a
    # `shell: bash` step.
    $py = Join-Path $installDir 'python.exe'
    $py3 = Join-Path $installDir 'python3.exe'
    if (-not (Test-Path -LiteralPath $py)) {
        throw "python.exe not found in $installDir after install."
    }
    Add-MachinePathEntry -Entry $installDir
    Add-MachinePathEntry -Entry (Join-Path $installDir 'Scripts')
    $needCopy = $true
    if (Test-Path -LiteralPath $py3) {
        $a = (Get-FileHash -LiteralPath $py -Algorithm SHA256).Hash
        $b = (Get-FileHash -LiteralPath $py3 -Algorithm SHA256).Hash
        $needCopy = ($a -ne $b)
    }
    if ($needCopy) {
        Copy-Item -LiteralPath $py -Destination $py3 -Force
        Write-Ok "created $py3 so the name python3 resolves"
    } else {
        Write-Ok "$py3 already matches python.exe"
    }
}

function Test-WebView2Installed {
    # Evergreen Runtime registers this fixed client GUID under EdgeUpdate.
    $guid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $keys = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guid",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid"
    )
    foreach ($key in $keys) {
        if (Test-Path -LiteralPath $key) {
            $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
            if ($null -ne $props -and $props.PSObject.Properties.Name -contains 'pv' -and $props.pv) {
                return [string]$props.pv
            }
        }
    }
    return $null
}

function Install-WebView2 {
    Write-Step 'WebView2 Runtime (Tauri webview host)'
    $have = Test-WebView2Installed
    if ($null -ne $have) {
        Write-Ok "already installed: version $have"
        Add-Summary -Component 'WebView2' -State 'present'
        return
    }
    # Evergreen bootstrapper. Server SKUs do NOT ship WebView2 preinstalled, unlike Windows 11.
    $setup = Invoke-PinnedDownload `
        -Url 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' `
        -FileName 'MicrosoftEdgeWebview2Setup.exe'
    Invoke-Native -FilePath $setup -Arguments @('/silent', '/install') -SuccessExitCodes @(0, 3010) `
        -What 'WebView2 Runtime install'
    if ($null -eq (Test-WebView2Installed)) {
        throw 'WebView2 bootstrapper returned success but no runtime version is registered.'
    }
    Add-Summary -Component 'WebView2' -State 'installed'
}

function Get-NsisPath {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'NSIS\makensis.exe'),
        (Join-Path $env:ProgramFiles 'NSIS\makensis.exe')
    )
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
    return $null
}

function Install-Nsis {
    Write-Step "NSIS $NsisVersion (Tauri .exe installer target)"
    $have = Get-NsisPath
    if ($null -ne $have) {
        Write-Ok "already installed at $have"
        Add-Summary -Component 'NSIS' -State 'present'
        return
    }
    $file = "nsis-$NsisVersion-setup.exe"
    $url = "https://downloads.sourceforge.net/project/nsis/NSIS%203/$NsisVersion/$file"
    $setup = Invoke-PinnedDownload -Url $url -FileName $file
    Invoke-Native -FilePath $setup -Arguments @('/S') -What "NSIS $NsisVersion install"
    $now = Get-NsisPath
    if ($null -eq $now) { throw 'NSIS installer returned success but makensis.exe was not found.' }
    Add-MachinePathEntry -Entry (Split-Path -Parent $now)
    Add-Summary -Component 'NSIS' -State 'installed'
    Write-Note 'cargo-tauri also fetches its own NSIS/WiX copies into %LOCALAPPDATA%\tauri; this system install is the offline fallback.'
}

function Get-WixBinPath {
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'WiX Toolset v3.14\bin'),
        (Join-Path $env:ProgramFiles 'WiX Toolset v3.14\bin')
    )
    foreach ($r in $roots) {
        if (Test-Path -LiteralPath (Join-Path $r 'candle.exe')) { return $r }
    }
    return $null
}

function Install-Wix {
    Write-Step 'WiX Toolset v3.14 (Tauri .msi installer target)'
    $have = Get-WixBinPath
    if ($null -ne $have) {
        Write-Ok "already installed at $have"
        Add-Summary -Component 'WiX' -State 'present'
        return
    }

    # WiX 3.x needs .NET Framework 3.5. On Server SKUs that feature often needs install media or
    # Windows Update; a failure here is a warning, not fatal, because the WiX bundle will say so
    # itself and Tauri's own vendored WiX may still work.
    try {
        if (Get-Command 'Get-WindowsFeature' -ErrorAction SilentlyContinue) {
            $feature = Get-WindowsFeature -Name 'NET-Framework-Core' -ErrorAction Stop
            if ($null -ne $feature -and -not $feature.Installed) {
                Write-Note 'installing Windows feature NET-Framework-Core (WiX 3 dependency)'
                $result = Install-WindowsFeature -Name 'NET-Framework-Core' -ErrorAction Stop
                if ($result.RestartNeeded -ne 'No') { $script:RebootRequired = $true }
            }
        }
    } catch {
        Write-Note ".NET Framework 3.5 could not be enabled automatically: $($_.Exception.Message)"
        Write-Note 'If wix314.exe fails below, enable it from install media: Install-WindowsFeature NET-Framework-Core -Source <sxs>'
    }

    $setup = Invoke-PinnedDownload `
        -Url "https://github.com/wixtoolset/wix3/releases/download/$WixReleaseTag/wix314.exe" `
        -FileName 'wix314.exe'
    Invoke-Native -FilePath $setup -Arguments @('/install', '/quiet', '/norestart') `
        -SuccessExitCodes @(0, 3010) -What 'WiX Toolset v3.14 install'

    $now = Get-WixBinPath
    if ($null -eq $now) { throw 'WiX installer returned success but candle.exe was not found.' }
    Add-MachinePathEntry -Entry $now
    Add-Summary -Component 'WiX' -State 'installed'
}

function Enable-LongPaths {
    Write-Step 'Windows long path support'
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
    $current = (Get-ItemProperty -LiteralPath $key -Name 'LongPathsEnabled' -ErrorAction SilentlyContinue)
    if ($null -ne $current -and $current.LongPathsEnabled -eq 1) {
        Write-Ok 'already enabled'
        return
    }
    Set-ItemProperty -LiteralPath $key -Name 'LongPathsEnabled' -Value 1 -Type DWord
    Write-Ok 'enabled (takes effect for newly started processes)'
}

function Add-BuildDefenderExclusions {
    Write-Step 'Windows Defender exclusions for build trees (opt-in)'
    if (-not (Get-Command 'Add-MpPreference' -ErrorAction SilentlyContinue)) {
        Write-Note 'Defender cmdlets unavailable; skipping'
        return
    }
    $paths = @($RustRoot, 'C:\actions-runner', $DownloadCache)
    foreach ($p in $paths) {
        try {
            Add-MpPreference -ExclusionPath $p -ErrorAction Stop   # idempotent: repeats are no-ops
            Write-Ok "excluded $p"
        } catch {
            Write-Note "could not exclude ${p}: $($_.Exception.Message)"
        }
    }
    foreach ($proc in @('rustc.exe', 'cargo.exe', 'link.exe')) {
        try {
            Add-MpPreference -ExclusionProcess $proc -ErrorAction Stop
            Write-Ok "excluded process $proc"
        } catch {
            Write-Note "could not exclude process ${proc}: $($_.Exception.Message)"
        }
    }
}

function Assert-Provisioned {
    <# Invokes every tool and prints its version. Any missing tool fails the script. #>
    Write-Step 'Verification: invoking every tool'
    $failures = New-Object System.Collections.ArrayList

    function Report {
        param([string]$Label, [string]$Value, [bool]$Required = $true)
        if ([string]::IsNullOrWhiteSpace($Value)) {
            Write-Host ("    {0,-22} MISSING" -f $Label) -ForegroundColor Red
            if ($Required) { [void]$failures.Add($Label) }
        } else {
            Write-Host ("    {0,-22} {1}" -f $Label, $Value)
        }
    }

    if (-not $SkipVisualStudio) {
        $vs = Get-VcToolsInstallPath
        Report -Label 'VS Build Tools' -Value $vs
        if ($null -ne $vs) {
            $link = Find-MsvcLinker -InstallPath $vs
            Report -Label 'MSVC link.exe' -Value $link
        }
    }
    if (-not $SkipRust) {
        Report -Label 'rustup' -Value (Test-CommandVersion -Command 'rustup')
        $rustc = Test-CommandVersion -Command 'rustc'
        Report -Label 'rustc' -Value $rustc
        if ($null -ne $rustc -and $rustc -notlike "*$RustToolchain*") {
            Write-Note "rustc is not the pinned $RustToolchain -- CI pins RUSTUP_TOOLCHAIN=$RustToolchain"
            [void]$failures.Add("rustc != $RustToolchain")
        }
        Report -Label 'cargo' -Value (Test-CommandVersion -Command 'cargo')
        Report -Label 'clippy' -Value (Test-CommandVersion -Command 'cargo' -Arguments @('clippy', '--version'))
        Report -Label 'rustfmt' -Value (Test-CommandVersion -Command 'cargo' -Arguments @('fmt', '--version'))
        $targets = & rustup target list --installed --toolchain $RustToolchain 2>$null
        if (@($targets) -notcontains $RustTarget) {
            Write-Host "    target $RustTarget MISSING" -ForegroundColor Red
            [void]$failures.Add("rust target $RustTarget")
        } else {
            Write-Host "    rust target           $RustTarget installed"
        }
    }
    if (-not $SkipGit) {
        Report -Label 'git' -Value (Test-CommandVersion -Command 'git')
        # `shell: bash` on Windows CI depends on this one.
        Report -Label 'bash (git)' -Value (Test-CommandVersion -Command 'bash')
    }
    if (-not $SkipNode) {
        Report -Label 'node' -Value (Test-CommandVersion -Command 'node')
        Report -Label 'npm' -Value (Test-CommandVersion -Command 'npm.cmd')
    }
    if (-not $SkipPython) {
        # Both names matter: release.yml reaches the interpreter through a matrix value that is
        # `python3` on the POSIX legs, and `shell: bash` steps resolve it through PATH.
        Report -Label 'python' -Value (Test-CommandVersion -Command 'python')
        Report -Label 'python3' -Value (Test-CommandVersion -Command 'python3')
        Report -Label 'pip' -Value (Test-CommandVersion -Command 'pip') -Required $false
    }
    if (-not $SkipWebView2) {
        Report -Label 'WebView2 runtime' -Value (Test-WebView2Installed)
    }
    if (-not $SkipNsis) {
        $nsis = Get-NsisPath
        Report -Label 'makensis' -Value $nsis
    }
    if (-not $SkipWix) {
        $wix = Get-WixBinPath
        Report -Label 'WiX candle/light' -Value $wix
    }
    # Archive tools, in place of 7-Zip.
    Report -Label 'tar.exe' -Value (Test-CommandVersion -Command 'tar')
    $expand = Get-Command 'Expand-Archive' -ErrorAction SilentlyContinue
    Report -Label 'Expand-Archive' -Value $(if ($null -ne $expand) { 'available' } else { '' })

    if ($failures.Count -gt 0) {
        throw "Provisioning verification failed for: $($failures -join ', ')"
    }
    Write-Ok 'every required tool is present'
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

$started = Get-Date
Write-Host "Iteron Windows runner bootstrap -- $($started.ToString('u'))" -ForegroundColor White
Write-Host "host: $env:COMPUTERNAME  PowerShell: $($PSVersionTable.PSVersion)"

Import-ChecksumFile -Path $ChecksumFile

if (-not $SkipVisualStudio) { Install-VisualStudioBuildTools } else { Write-Note 'skipping VS Build Tools' }
if (-not $SkipGit)         { Install-GitForWindows }          else { Write-Note 'skipping Git' }
if (-not $SkipRust)        { Install-Rust }                   else { Write-Note 'skipping Rust' }
if (-not $SkipNode)        { Install-NodeJs }                 else { Write-Note 'skipping Node.js' }
if (-not $SkipPython)      { Install-Python }                 else { Write-Note 'skipping Python' }
if (-not $SkipWebView2)    { Install-WebView2 }               else { Write-Note 'skipping WebView2' }
if (-not $SkipNsis)        { Install-Nsis }                   else { Write-Note 'skipping NSIS' }
if (-not $SkipWix)         { Install-Wix }                    else { Write-Note 'skipping WiX' }

Enable-LongPaths
if ($AddDefenderExclusions) { Add-BuildDefenderExclusions }

Assert-Provisioned

Write-Step 'Summary'
$script:Summary | Format-Table -AutoSize | Out-String | Write-Host
$elapsed = (Get-Date) - $started
Write-Host ("bootstrap completed in {0:hh\:mm\:ss}" -f $elapsed) -ForegroundColor Green
if ($script:RebootRequired) {
    Write-Host 'A REBOOT IS REQUIRED before the toolchain is fully usable (an installer returned 3010).' -ForegroundColor Yellow
    Write-Host 'Reboot, then re-run this script once: it will confirm every tool and change nothing.' -ForegroundColor Yellow
}
Write-Host 'Next: install-runner.ps1 (see README.md).' -ForegroundColor White
