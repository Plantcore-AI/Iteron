<#
.SYNOPSIS
    Post-provision self-check: proves this machine can actually build the workspace for
    `x86_64-pc-windows-msvc`, and reports how long that took (issue #227).

.DESCRIPTION
    Two phases.

    1. INVENTORY -- invokes every tool bootstrap.ps1 installs and prints its version, plus the
       state of any installed Actions runner service and the free space on the build volume.

    2. REAL WORK -- runs `cargo check --workspace --locked --target x86_64-pc-windows-msvc` in a
       checkout you point it at, and reports elapsed wall-clock. Issue #227's acceptance criterion
       is that a Windows run's duration is consistent with real compilation rather than a few
       seconds, so the number matters as much as the exit code. Pass -Clean for a true cold build
       (it deletes only `<checkout>\target`, nothing else, and never anything outside the
       checkout).

    Read-only with respect to the machine: it installs nothing and changes no configuration.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1 -CheckoutPath C:\src\Iteron -Clean

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1 -CheckoutPath C:\src\Iteron `
        -RunConPtyTest -ReportPath C:\actions-runner\verify-report.json

.NOTES
    PowerShell 5.1 compatible. Does not need elevation (except that -Clean must be able to delete
    `target`). Contains no secret of any kind.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    # A checkout of Plantcore-AI/Iteron. `git clone https://github.com/Plantcore-AI/Iteron C:\src\Iteron`
    [Parameter(Mandatory)]
    [string]$CheckoutPath,

    [Parameter()]
    [string]$Target = 'x86_64-pc-windows-msvc',

    # Must match `RUSTUP_TOOLCHAIN` in .github/workflows/*.yml.
    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Toolchain = '1.90.0',

    # Delete <checkout>\target first, so the timing below reflects a cold compile.
    [switch]$Clean,

    # Also run the Windows-only ConPTY test the CI lanes run. Slower, but it proves the machine
    # links and executes a Windows binary rather than only type-checking.
    [switch]$RunConPtyTest,

    # Below this, the run is suspiciously fast for a cold Windows compile and is reported as such.
    [Parameter()]
    [int]$MinimumCompileSeconds = 60,

    [Parameter()]
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}
function Write-Note {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    note: $Message" -ForegroundColor Yellow
}

function Test-CommandVersion {
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Arguments = @('--version')
    )
    $resolved = Get-Command $Command -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $resolved) { return $null }
    try { $out = & $resolved.Source @Arguments 2>&1 } catch { return $null }
    if ($null -eq $out) { return $null }
    $line = @($out | ForEach-Object { "$_" } | Where-Object { $_.Trim() -ne '' }) | Select-Object -First 1
    if ($null -eq $line) { return $null }
    return $line.Trim()
}

function Get-VcToolsInstallPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { return $null }
    $out = & $vswhere -products '*' -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null
    $path = @($out | Where-Object { $_ -and $_.Trim() -ne '' }) | Select-Object -First 1
    if ($null -eq $path) { return $null }
    return $path.Trim()
}

function Get-WebView2Version {
    $guid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    foreach ($key in @(
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guid",
            "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid")) {
        if (Test-Path -LiteralPath $key) {
            $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
            if ($null -ne $props -and $props.PSObject.Properties.Name -contains 'pv') {
                return [string]$props.pv
            }
        }
    }
    return $null
}

$results = [ordered]@{}
$problems = New-Object System.Collections.ArrayList

function Record {
    param(
        [Parameter(Mandatory)][string]$Label,
        [string]$Value,
        [bool]$Required = $true
    )
    $results[$Label] = $Value
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Write-Host ("    {0,-24} MISSING" -f $Label) -ForegroundColor Red
        if ($Required) { [void]$problems.Add($Label) }
    } else {
        Write-Host ("    {0,-24} {1}" -f $Label, $Value)
    }
}

# ---------------------------------------------------------------------------------------------
# Phase 1: inventory
# ---------------------------------------------------------------------------------------------
$started = Get-Date
Write-Host "Iteron Windows runner verification -- $($started.ToString('u'))" -ForegroundColor White
Write-Host "host: $env:COMPUTERNAME  PowerShell: $($PSVersionTable.PSVersion)"

Write-Step 'toolchain inventory'
Record -Label 'OS' -Value (Get-CimInstance Win32_OperatingSystem).Caption
Record -Label 'CPU count' -Value "$env:NUMBER_OF_PROCESSORS"
$mem = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
Record -Label 'RAM (GiB)' -Value "$mem"

$vs = Get-VcToolsInstallPath
Record -Label 'VS Build Tools' -Value $vs
if ($null -ne $vs) {
    $link = Get-ChildItem -Path (Join-Path $vs 'VC\Tools\MSVC') -Filter 'link.exe' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like '*\bin\Hostx64\x64\*' } | Select-Object -First 1
    Record -Label 'MSVC link.exe' -Value $(if ($null -ne $link) { $link.FullName } else { '' })
}
Record -Label 'rustup' -Value (Test-CommandVersion -Command 'rustup')
$rustc = Test-CommandVersion -Command 'rustc'
Record -Label 'rustc' -Value $rustc
if ($null -ne $rustc -and $rustc -notlike "*$Toolchain*") {
    Write-Note "rustc is not the pinned $Toolchain; CI pins RUSTUP_TOOLCHAIN=$Toolchain"
    [void]$problems.Add("rustc != $Toolchain")
}
Record -Label 'cargo' -Value (Test-CommandVersion -Command 'cargo')
Record -Label 'clippy' -Value (Test-CommandVersion -Command 'cargo' -Arguments @('clippy', '--version'))
Record -Label 'rustfmt' -Value (Test-CommandVersion -Command 'cargo' -Arguments @('fmt', '--version'))
$installedTargets = @(& rustup target list --installed --toolchain $Toolchain 2>$null)
Record -Label "rust target $Target" -Value $(if ($installedTargets -contains $Target) { 'installed' } else { '' })
Record -Label 'git' -Value (Test-CommandVersion -Command 'git')
# REQUIRED, and a non-obvious way for a whole release leg to fail: several CI and release steps run
# with `shell: bash`, which on a self-hosted Windows runner is Git for Windows' bash resolved from
# PATH. If this line says MISSING, every such step dies before running a command.
$bash = Test-CommandVersion -Command 'bash'
Record -Label 'bash (git)' -Value $bash
if ([string]::IsNullOrWhiteSpace($bash)) {
    Write-Note 'add "C:\Program Files\Git\bin" to the machine PATH (bootstrap.ps1 does this) or every `shell: bash` step fails'
}
Record -Label 'node' -Value (Test-CommandVersion -Command 'node')
Record -Label 'npm' -Value (Test-CommandVersion -Command 'npm.cmd')
# release-tools/*.py drives the whole release pipeline and needs 3.11+ (tomllib). Both names are
# checked: release.yml reaches the interpreter through a matrix value that is `python3` elsewhere.
$python = Test-CommandVersion -Command 'python'
Record -Label 'python' -Value $python
Record -Label 'python3' -Value (Test-CommandVersion -Command 'python3')
if ($null -ne $python -and $python -match '^Python 3\.(\d+)\.' -and [int]$Matches[1] -lt 11) {
    Write-Note "python is $python; release-tools/*.py import tomllib and need 3.11 or newer"
    [void]$problems.Add('python older than 3.11')
}
Record -Label 'WebView2 runtime' -Value (Get-WebView2Version) -Required $false
$nsis = @(
    (Join-Path ${env:ProgramFiles(x86)} 'NSIS\makensis.exe'),
    (Join-Path $env:ProgramFiles 'NSIS\makensis.exe')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
Record -Label 'makensis' -Value $nsis -Required $false
$wix = @(
    (Join-Path ${env:ProgramFiles(x86)} 'WiX Toolset v3.14\bin\candle.exe'),
    (Join-Path $env:ProgramFiles 'WiX Toolset v3.14\bin\candle.exe')
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
Record -Label 'WiX candle.exe' -Value $wix -Required $false
Record -Label 'tar.exe' -Value (Test-CommandVersion -Command 'tar')
Record -Label 'CARGO_HOME' -Value $env:CARGO_HOME -Required $false
Record -Label 'RUSTUP_HOME' -Value $env:RUSTUP_HOME -Required $false

Write-Step 'runner services'
$services = @(Get-Service -Name 'actions.runner.*' -ErrorAction SilentlyContinue)
if ($services.Count -eq 0) {
    Write-Note 'no actions.runner.* service installed yet (run install-runner.ps1)'
    $results['runner services'] = 'none'
} else {
    foreach ($s in $services) {
        $startMode = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$($s.Name)'").StartMode
        Write-Host ("    {0,-24} {1} ({2})" -f $s.Name, $s.Status, $startMode)
        if ($s.Status -ne 'Running') { [void]$problems.Add("service $($s.Name) is $($s.Status)") }
    }
    $results['runner services'] = ($services | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join '; '
}

Write-Step 'disk'
$drive = (Resolve-Path -LiteralPath $CheckoutPath -ErrorAction SilentlyContinue)
if ($null -eq $drive) { throw "CheckoutPath '$CheckoutPath' does not exist. Clone the repo there first." }
$root = [System.IO.Path]::GetPathRoot($drive.Path)
$free = [math]::Round((Get-PSDrive -Name $root.TrimEnd(':\')).Free / 1GB, 1)
Record -Label 'free space (GiB)' -Value "$free"
if ($free -lt 20) { Write-Note 'under 20 GiB free; a cold Rust target/ tree alone can exceed that' }

if (-not (Test-Path -LiteralPath (Join-Path $CheckoutPath 'Cargo.toml'))) {
    throw "No Cargo.toml in '$CheckoutPath'; this must be a checkout of the workspace."
}

# ---------------------------------------------------------------------------------------------
# Phase 2: real compilation
# ---------------------------------------------------------------------------------------------
if ($Clean) {
    $targetDir = Join-Path $CheckoutPath 'target'
    if (Test-Path -LiteralPath $targetDir) {
        Write-Step "removing $targetDir for a cold build"
        Remove-Item -LiteralPath $targetDir -Recurse -Force
    }
}

Write-Step "cargo check --workspace --locked --target $Target"
Write-Host "    cwd: $CheckoutPath"
Push-Location $CheckoutPath
$checkSeconds = 0
$checkExit = -1
try {
    $env:RUSTUP_TOOLCHAIN = $Toolchain
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & cargo check --workspace --locked --target $Target
    $checkExit = $LASTEXITCODE
    $sw.Stop()
    $checkSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
} finally {
    Pop-Location
}
$results['cargo check exit'] = "$checkExit"
$results['cargo check seconds'] = "$checkSeconds"
Write-Host ''
Write-Host ("    cargo check exit {0} in {1}s" -f $checkExit, $checkSeconds) `
    -ForegroundColor $(if ($checkExit -eq 0) { 'Green' } else { 'Red' })
if ($checkExit -ne 0) { [void]$problems.Add('cargo check failed') }
elseif ($checkSeconds -lt $MinimumCompileSeconds) {
    Write-Note "finished in under ${MinimumCompileSeconds}s -- that is a warm-cache replay, not a cold compile."
    Write-Note 'Re-run with -Clean if you need the cold number for the #227 acceptance evidence.'
}

if ($RunConPtyTest) {
    Write-Step "cargo test -p iteron-cli --test windows_conpty --target $Target"
    Push-Location $CheckoutPath
    try {
        $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
        & cargo test --locked -p iteron-cli --test windows_conpty --target $Target
        $testExit = $LASTEXITCODE
        $sw2.Stop()
    } finally {
        Pop-Location
    }
    $results['conpty test exit'] = "$testExit"
    $results['conpty test seconds'] = "$([math]::Round($sw2.Elapsed.TotalSeconds, 1))"
    if ($testExit -ne 0) { [void]$problems.Add('windows_conpty test failed') }
}

# ---------------------------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------------------------
Write-Step 'verdict'
$total = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
$results['total seconds'] = "$total"
$results['verdict'] = $(if ($problems.Count -eq 0) { 'PASS' } else { 'FAIL' })

if ($ReportPath) {
    ([pscustomobject]$results) | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath $ReportPath -Encoding utf8
    Write-Host "    report written to $ReportPath"
}

if ($problems.Count -gt 0) {
    Write-Host "FAIL: $($problems -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "PASS -- cargo check succeeded in ${checkSeconds}s, total ${total}s" -ForegroundColor Green
Write-Host 'That duration is the evidence issue #227 asks for: a Windows run consistent with real'
Write-Host 'compilation rather than a few seconds of no-op.'
exit 0
