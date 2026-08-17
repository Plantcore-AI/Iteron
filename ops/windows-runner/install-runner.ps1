<#
.SYNOPSIS
    Installs and registers a GitHub Actions self-hosted runner as a Windows service that survives
    reboot and network loss unattended (issue #227).

.DESCRIPTION
    Idempotent. Safe to re-run: an already-correctly-configured instance is left alone and only its
    service settings are re-asserted. `--replace` means a re-registration never creates a duplicate
    runner on the GitHub side.

    One machine serves TWO repositories, so runners live in separate directories under a common
    root and get distinct labels:

      C:\actions-runner\iteron    label `iteron-win`   for Plantcore-AI/Iteron
      C:\actions-runner\desktop   label `desktop-win`  for Plantcore-AI/plantcore-desktop

    TOKEN HANDLING. The registration token is SHORT-LIVED (about one hour) and is a parameter only.
    It is never hardcoded, never logged, never written to disk by this script, and the decrypted
    copy is zeroed from memory as soon as `config.cmd` returns. Obtain it with:

      gh api --method POST repos/Plantcore-AI/Iteron/actions/runners/registration-token --jq .token

    Honest caveat: `config.cmd` accepts the token only as a command-line argument, so for the few
    seconds it runs, the token is visible to any process on this host that can read another
    process's command line. That is inherent to the vendor tool. The mitigations are that the token
    is short-lived, that it grants only "register a runner", and that nobody else should have a
    session on this machine.

.PARAMETER Token
    Registration token as a SecureString. Omit it and PowerShell prompts without echoing. To pass
    it non-interactively:
      $t = ConvertTo-SecureString (gh api --method POST repos/OWNER/REPO/actions/runners/registration-token --jq .token) -AsPlainText -Force

.PARAMETER RunnerSha256
    SHA-256 of the runner zip. REQUIRED and never defaulted: no hash is invented in this repo.
    Get it from the release body:
      gh release view v<version> --repo actions/runner --json body --jq .body

.EXAMPLE
    & .\install-runner.ps1 `
        -Repo Plantcore-AI/Iteron -RunnerVersion 2.328.0 -RunnerSha256 <hex> -Token (Read-Host -AsSecureString)

.NOTES
    PowerShell 5.1 compatible. Must run elevated. Run bootstrap.ps1 first.
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$')]
    [string]$Repo,

    [Parameter(Mandatory)]
    [securestring]$Token,

    # No default: the correct version is whatever actions/runner has released, and guessing it
    # would desynchronise from the hash below. Resolve it with:
    #   gh api repos/actions/runner/releases/latest --jq .tag_name
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$RunnerVersion,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$RunnerSha256,

    [Parameter()]
    [string]$RunnerRoot = 'C:\actions-runner',

    # Subdirectory under $RunnerRoot. Defaults from the repo name (Iteron -> iteron,
    # plantcore-desktop -> desktop).
    [Parameter()]
    [ValidatePattern('^(?!\.{1,2}$)[A-Za-z0-9._-]+$')]
    [string]$Instance,

    # Runner name as it appears in the repository's runner list. Must be unique per repo.
    [Parameter()]
    [string]$RunnerName,

    # Comma-separated custom labels. Defaults per repo. Iteron selects a JSON label array through
    # WINDOWS_RUNNER_LABELS; Desktop selects its single custom label through WINDOWS_RUNNER.
    [Parameter()]
    [string]$Labels,

    # Keep each runner's workspace below its own instance directory. Restricting this to one
    # relative directory name prevents the two services from accidentally sharing a work tree.
    [Parameter()]
    [ValidatePattern('^(?!\.{1,2}$)[A-Za-z0-9._-]+$')]
    [string]$WorkFolder = '_work',

    # Built-in service account, no password, no long-lived credential on the box. Change only if
    # you know the build needs an interactive profile.
    [Parameter()]
    [string]$ServiceAccount = 'NT AUTHORITY\NETWORK SERVICE',

    # Re-extract the runner and re-register even when the existing configuration already matches.
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

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

# ---------------------------------------------------------------------------------------------
# Defaults derived from the repository
# ---------------------------------------------------------------------------------------------
$owner, $repoName = $Repo -split '/', 2

if ([string]::IsNullOrWhiteSpace($Instance)) {
    switch -Regex ($repoName) {
        '^(?i)iteron$'            { $Instance = 'iteron'; break }
        '^(?i)plantcore-desktop$' { $Instance = 'desktop'; break }
        default                   { $Instance = $repoName.ToLowerInvariant() }
    }
}
if ([string]::IsNullOrWhiteSpace($Labels)) {
    switch ($Instance) {
        'iteron'  { $Labels = 'iteron-win'; break }
        'desktop' { $Labels = 'desktop-win'; break }
        default   { throw "No default label for instance '$Instance'. Pass -Labels explicitly." }
    }
}
if ([string]::IsNullOrWhiteSpace($RunnerName)) {
    $RunnerName = "$($env:COMPUTERNAME.ToLowerInvariant())-$Instance"
}

# The two known repositories intentionally have fixed instance directories and workflow labels.
# Fail before download if an override would make the runbook and repository variables lie.
$normalisedLabels = @($Labels -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($repoName -match '^(?i)iteron$') {
    if ($Instance -ne 'iteron') { throw "Plantcore-AI/Iteron must use -Instance iteron." }
    if ($normalisedLabels -notcontains 'iteron-win') {
        throw "Plantcore-AI/Iteron must carry the iteron-win label selected by WINDOWS_RUNNER_LABELS."
    }
} elseif ($repoName -match '^(?i)plantcore-desktop$') {
    if ($Instance -ne 'desktop') { throw "Plantcore-AI/plantcore-desktop must use -Instance desktop." }
    if ($normalisedLabels -notcontains 'desktop-win') {
        throw "Plantcore-AI/plantcore-desktop must carry the desktop-win label selected by WINDOWS_RUNNER."
    }
}

$instanceDir = Join-Path $RunnerRoot $Instance
$zipName = "actions-runner-win-x64-$RunnerVersion.zip"
$zipUrl = "https://github.com/actions/runner/releases/download/v$RunnerVersion/$zipName"
$markerPath = Join-Path $instanceDir '.provisioned-runner-version'

Write-Host "GitHub Actions runner install -- $(Get-Date -Format u)" -ForegroundColor White
Write-Host "  repo      : $Repo"
Write-Host "  directory : $instanceDir"
Write-Host "  workspace : $(Join-Path $instanceDir $WorkFolder)"
Write-Host "  name      : $RunnerName"
Write-Host "  labels    : $Labels"
Write-Host "  version   : $RunnerVersion"
Write-Host "  account   : $ServiceAccount"

# ---------------------------------------------------------------------------------------------
# 1. Download + extract (checksum-verified)
# ---------------------------------------------------------------------------------------------
function Install-RunnerPackage {
    Write-Step "runner package $RunnerVersion"

    $alreadyThere = (Test-Path -LiteralPath (Join-Path $instanceDir 'config.cmd')) -and
                    (Test-Path -LiteralPath $markerPath) -and
                    ((Get-Content -LiteralPath $markerPath -Raw).Trim() -eq $RunnerVersion)
    if ($alreadyThere -and -not $Force) {
        Write-Ok "runner $RunnerVersion already extracted in $instanceDir"
        return
    }

    if (-not (Test-Path -LiteralPath $instanceDir)) {
        [void](New-Item -ItemType Directory -Path $instanceDir -Force)
    }
    $zipPath = Join-Path $RunnerRoot $zipName

    $needDownload = $true
    if (Test-Path -LiteralPath $zipPath) {
        $have = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($have -eq $RunnerSha256.ToLowerInvariant()) {
            Write-Ok "cached and checksum-verified: $zipName"
            $needDownload = $false
        } else {
            Write-Note 'cached runner zip has an unexpected hash; re-downloading'
            Remove-Item -LiteralPath $zipPath -Force
        }
    }

    if ($needDownload) {
        Write-Host "    downloading $zipUrl"
        Invoke-WebRequest -Uri $zipUrl -OutFile "$zipPath.part" -UseBasicParsing -MaximumRedirection 10
        $actual = (Get-FileHash -LiteralPath "$zipPath.part" -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $RunnerSha256.ToLowerInvariant()) {
            Move-Item -LiteralPath "$zipPath.part" -Destination "$zipPath.rejected" -Force
            throw @"
CHECKSUM MISMATCH for $zipName
  url      : $zipUrl
  expected : $($RunnerSha256.ToLowerInvariant())
  actual   : $actual
  kept at  : $zipPath.rejected
Re-check the hash published in the actions/runner release body before touching anything else.
"@
        }
        Move-Item -LiteralPath "$zipPath.part" -Destination $zipPath -Force
        Write-Ok "downloaded and checksum-verified: $zipName"
    }

    # Expand-Archive is PS 5.1 built-in; -Force overwrites an older extraction in place, which is
    # what an in-place runner upgrade wants. `_work`, `.runner` and `.credentials` are not inside
    # the zip, so a re-extract never destroys an existing registration or a build workspace.
    Write-Host "    extracting into $instanceDir"
    Expand-Archive -LiteralPath $zipPath -DestinationPath $instanceDir -Force
    Set-Content -LiteralPath $markerPath -Value $RunnerVersion -Encoding ascii
    Write-Ok "extracted runner $RunnerVersion"
}

# ---------------------------------------------------------------------------------------------
# 2. Register (or confirm an existing registration)
# ---------------------------------------------------------------------------------------------
function Get-ExistingConfig {
    $dotRunner = Join-Path $instanceDir '.runner'
    if (-not (Test-Path -LiteralPath $dotRunner)) { return $null }
    try {
        return (Get-Content -LiteralPath $dotRunner -Raw | ConvertFrom-Json)
    } catch {
        Write-Note '.runner exists but is not readable JSON; treating the instance as unconfigured'
        return $null
    }
}

function Get-RunnerServiceName {
    $dotService = Join-Path $instanceDir '.service'
    if (Test-Path -LiteralPath $dotService) {
        $name = (Get-Content -LiteralPath $dotService -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($name)) { return $name }
    }
    # Fallback to the documented naming scheme: actions.runner.<owner>-<repo>.<runnerName>
    $guess = "actions.runner.$owner-$repoName.$RunnerName"
    $svc = Get-Service -Name $guess -ErrorAction SilentlyContinue
    if ($null -ne $svc) { return $svc.Name }
    return $null
}

function Remove-ExistingConfiguration {
    Write-Note 'removing the existing local configuration before re-registering'
    $svcName = Get-RunnerServiceName
    if ($null -ne $svcName) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -ne 'Stopped') {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
        }
        $svcCmd = Join-Path $instanceDir 'svc.cmd'
        if (Test-Path -LiteralPath $svcCmd) {
            Push-Location $instanceDir
            try { & $svcCmd uninstall | Out-Host } finally { Pop-Location }
        }
    }
    foreach ($f in @('.runner', '.credentials', '.credentials_rsaparams', '.service')) {
        $p = Join-Path $instanceDir $f
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
    }
}

function Register-Runner {
    Write-Step "registering '$RunnerName' against $Repo"

    $existing = Get-ExistingConfig
    if ($null -ne $existing -and -not $Force) {
        $sameUrl = $existing.gitHubUrl -eq "https://github.com/$Repo"
        $sameName = $existing.agentName -eq $RunnerName
        if ($sameUrl -and $sameName) {
            Write-Ok "already registered as '$($existing.agentName)' for $($existing.gitHubUrl)"
            Write-Note 'labels are server-side state; change them in the repository runner settings or re-run with -Force'
            return $false
        }
        Write-Note "existing registration ($($existing.gitHubUrl), $($existing.agentName)) does not match; re-registering"
        Remove-ExistingConfiguration
    } elseif ($null -ne $existing) {
        Remove-ExistingConfiguration
    }

    $configCmd = Join-Path $instanceDir 'config.cmd'
    if (-not (Test-Path -LiteralPath $configCmd)) { throw "config.cmd not found in $instanceDir" }

    # Decrypt the token as late as possible and zero it immediately afterwards.
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

        # `--replace` makes re-running idempotent on the server side: a runner with the same name
        # is replaced, not duplicated. `--runasservice` installs the Windows service so the runner
        # comes back on its own after a reboot.
        $configArgs = @(
            '--unattended',
            '--replace',
            '--url', "https://github.com/$Repo",
            '--token', $plain,
            '--name', $RunnerName,
            '--labels', $Labels,
            '--work', $WorkFolder,
            '--runasservice',
            '--windowslogonaccount', $ServiceAccount
        )

        # Deliberately NOT echoing $configArgs: it carries the token.
        Write-Host "    running: config.cmd --unattended --replace --url https://github.com/$Repo --token <redacted> --name $RunnerName --labels $Labels --work $WorkFolder --runasservice --windowslogonaccount `"$ServiceAccount`""
        Push-Location $instanceDir
        try {
            & $configCmd @configArgs | Out-Host
            $code = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($code -ne 0) {
            throw "config.cmd failed with exit code $code (token redacted from this message; it may simply have expired -- registration tokens live about one hour)."
        }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        if (Test-Path 'variable:plain') { Remove-Variable -Name plain -Force -ErrorAction SilentlyContinue }
    }
    Write-Ok 'registered'
    return $true
}

# ---------------------------------------------------------------------------------------------
# 3. Service hardening: delayed auto-start + restart-on-failure
# ---------------------------------------------------------------------------------------------
function Set-RunnerServicePolicy {
    Write-Step 'service policy (survive reboot and network loss)'
    $svcName = Get-RunnerServiceName
    if ($null -eq $svcName) {
        throw "Could not determine the runner service name (no .service file in $instanceDir)."
    }
    Write-Host "    service: $svcName"

    # Automatic (Delayed Start): the runner needs the network stack up before it can connect, and
    # a plain Automatic start races it on this cloud image.
    & sc.exe config $svcName start= delayed-auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config $svcName start= delayed-auto failed ($LASTEXITCODE)" }
    Write-Ok 'start type = Automatic (Delayed Start)'

    # Restart three times, one minute apart, resetting the failure count daily. This is what turns
    # a transient network loss into a reconnect instead of a silently offline runner.
    & sc.exe failure $svcName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe failure $svcName failed ($LASTEXITCODE)" }
    Write-Ok 'recovery = restart/60s x3, reset after 86400s'

    # Apply recovery to clean (non-crash) exits too; the listener exiting 1 is not a "crash".
    & sc.exe failureflag $svcName 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Note "sc.exe failureflag returned $LASTEXITCODE" }

    $svc = Get-Service -Name $svcName
    if ($svc.Status -ne 'Running') {
        Start-Service -Name $svcName
        $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(120))
    }
    $svc.Refresh()
    Write-Ok "service status = $($svc.Status)"
    return $svcName
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------
Install-RunnerPackage
[void](Register-Runner)
$serviceName = Set-RunnerServicePolicy

Write-Step 'result'
Get-Service -Name $serviceName |
    Select-Object -Property Name, Status, StartType |
    Format-List | Out-String | Write-Host

Write-Host 'Confirm it shows Online at:' -ForegroundColor White
Write-Host "  https://github.com/$Repo/settings/actions/runners"
if ($Instance -eq 'iteron') {
    $runnerLabels = @('self-hosted', 'Windows', 'X64') + $normalisedLabels
    $runnerLabelsJson = ConvertTo-Json -InputObject $runnerLabels -Compress
    Write-Host ''
    Write-Host 'Then, and only then, point the workflows at it:' -ForegroundColor White
    Write-Host "  gh variable set WINDOWS_RUNNER_LABELS --repo $Repo --body '$runnerLabelsJson'"
    Write-Host 'While WINDOWS_RUNNER_LABELS is unset, Windows CI stays dormant and Windows release'
    Write-Host 'falls back to a hosted image. A self-hosted label with no online runner queues forever.'
} elseif ($Instance -eq 'desktop') {
    $primaryLabel = $normalisedLabels[0]
    Write-Host ''
    Write-Host 'Then, and only then, point the Desktop workflow at it:' -ForegroundColor White
    Write-Host "  gh variable set WINDOWS_RUNNER --repo $Repo --body $primaryLabel"
    Write-Host 'While WINDOWS_RUNNER is unset, Desktop safely uses the hosted windows-latest image.'
}
