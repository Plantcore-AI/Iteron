#Requires -Version 5.1
param(
    [string]$ReleaseDirectory = '',
    [string]$ReleaseVersion = '0.0.29'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$installer = Join-Path $repo 'install.ps1'
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw ($parseErrors | Out-String) }
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('iteron-installer-test.' + [System.IO.Path]::GetRandomFileName())
$null = New-Item -ItemType Directory $work
$script:Fixture = ''
$script:UseRealPayload = $false
$script:FailMove = $false
$script:FailVersionPath = ''
$script:JourneyCount = 0
$destination = Join-Path $work 'install with spaces'

function Write-Sums([string]$Directory) {
    $lines = @(Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -ne 'SHA256SUMS' } | ForEach-Object {
        (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant() + '  ' + $_.Name
    })
    [System.IO.File]::WriteAllLines((Join-Path $Directory 'SHA256SUMS'), $lines)
}

function New-Fixture([string]$Version, [string]$Directory, [string]$Mutation = '') {
    $null = New-Item -ItemType Directory $Directory
    $root = "iteron-v$Version-x86_64-pc-windows-msvc"
    $archive = Join-Path $Directory "$root.zip"
    $zip = [System.IO.Compression.ZipFile]::Open($archive, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $members = @{}
        foreach ($name in @('LICENSE', 'README.md', 'THIRD_PARTY_LICENSES.html', 'THIRD_PARTY_NOTICES.txt',
            'SBOM.spdx.json', 'BUILD-INFO.json', 'STANDALONE-PERSISTENCE.md', 'machine-contract.json')) {
            $members[$name] = 'fixture'
        }
        foreach ($name in @(
            'README.md',
            'app-server-v5.schema.json',
            'check-app-server-v5.py',
            'check-workspace-hook.py',
            'check_machine_contract.py',
            'examples/app-server-v5-bootstrap-reply.json',
            'examples/app-server-v5-bootstrap.json',
            'examples/app-server-v5-command-reply.json',
            'examples/app-server-v5-command.json',
            'examples/app-server-v5-invalid-bootstrap.json',
            'examples/app-server-v5-invalid-session.json',
            'examples/app-server-v5-listening.json',
            'examples/app-server-v5-pause-command-reply.json',
            'examples/app-server-v5-pause-command.json',
            'examples/app-server-v5-resume-command-reply.json',
            'examples/app-server-v5-resume-command.json',
            'examples/app-server-v5-resume-terminal-command-reply.json',
            'examples/app-server-v5-resume-terminal-command.json',
            'examples/machine-contract-v1.json',
            'examples/workspace-hook-allow.json',
            'examples/workspace-hook-deny.json',
            'iteron-output-v7.schema.json',
            'machine-contract.schema.json',
            'test-vectors/portable-canonical-json-v1.json',
            'workspace-hook-v1.schema.json',
            'workspace-tools-v1.json'
        )) { $members['contracts/plantcore/' + $name] = 'contract fixture' }
        $members['iteron.exe'] = "iteron $Version"
        $members['iteron-workspace-hook.exe'] = "iteron $Version"
        if ($Version -ne '0.0.29' -and $Mutation -ne 'missing-server') { $members['iteron-app-server.exe'] = "iteron-app-server $Version" }
        foreach ($name in $members.Keys) {
            $path = "$root/$name"
            if ($Mutation -eq 'traversal' -and $name -eq 'README.md') { $path = "$root/../escape" }
            if ($Mutation -eq 'duplicate' -and $name -eq 'README.md') { $path = "$root/LICENSE" }
            $entry = $zip.CreateEntry($path)
            if ($Mutation -eq 'symlink' -and $name -eq 'README.md') { $entry.ExternalAttributes = -1577058304 }
            $writer = New-Object System.IO.StreamWriter($entry.Open())
            try { $writer.Write($members[$name]) } finally { $writer.Dispose() }
        }
    } finally { $zip.Dispose() }
    [System.IO.File]::WriteAllText((Join-Path $Directory 'manual-release-manifest.json'), '{"type":"iteron_manual_release_manifest"}')
    Write-Sums $Directory
}

$overrides = @'
$script:RealVersion = ${function:Get-IteronReportedVersion}
$script:RealSet = ${function:Set-IteronFile}
function Test-IteronPlatform {}
function Invoke-IteronDownload {
    param([string]$Uri, [string]$OutFile, [long]$MaximumBytes, [string]$Description)
    if ($Uri -notlike 'https://github.com/Plantcore-AI/Iteron/releases/download/*') { throw 'unexpected download URL' }
    $source = Join-Path $script:Fixture ($Uri.Split('/')[-1])
    if ((Get-Item -LiteralPath $source).Length -gt $MaximumBytes) { throw 'size ceiling exceeded' }
    Copy-Item -LiteralPath $source -Destination $OutFile
}
function Get-IteronReportedVersion {
    param([string]$Path)
    if ($Path -eq $script:FailVersionPath) { throw 'injected final version failure' }
    if ($script:UseRealPayload) { return (& $script:RealVersion -Path $Path) }
    return [System.IO.File]::ReadAllText($Path).Trim()
}
function Set-IteronFile {
    param([string]$Source, [string]$Target)
    if ($script:FailMove -and (Split-Path $Target -Leaf) -eq 'iteron.exe') {
        $script:FailMove = $false
        throw 'injected main replacement failure after support replacement'
    }
    & $script:RealSet -Source $Source -Target $Target
}
Invoke-IteronInstall
'@
$text = [System.IO.File]::ReadAllText($installer).Replace("`nInvoke-IteronInstall`n", "`n$overrides`n")
if ($text -notmatch 'injected main replacement') { throw 'installer injection point missing' }
$command = [scriptblock]::Create($text)

function Run-Installer([string]$Fixture, [string]$Version = '0.0.30', [bool]$Success = $true, [bool]$Rollback = $false) {
    $script:Fixture = $Fixture
    $failed = $false
    try { & $command -Version "v$Version" -BinDir $destination -SkipPathUpdate -Rollback:$Rollback | Out-Null }
    catch { $failed = $true; if ($Success) { throw } }
    if ($failed -eq $Success) { throw 'installer unexpectedly accepted a failure fixture' }
    $script:JourneyCount++
}

function Snapshot {
    $values = @()
    foreach ($name in @('iteron.exe', 'iteron-workspace-hook.exe', 'iteron-app-server.exe')) {
        $path = Join-Path $destination $name
        if (Test-Path -LiteralPath $path) { $values += (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
        else { $values += 'absent' }
    }
    return ($values -join ',')
}
function Assert-Snapshot([string]$Expected) {
    if ((Snapshot) -cne $Expected) { throw 'executable set changed unexpectedly' }
}
try {
    $old = Join-Path $work 'old'
    $new = Join-Path $work 'new'
    New-Fixture '0.0.29' $old
    New-Fixture '0.0.30' $new
    Run-Installer $old '0.0.29'
    $before = Snapshot
    Run-Installer $new
    $after = Snapshot
    Run-Installer $new '0.0.30' $true $true
    Assert-Snapshot $before
    Run-Installer $new '0.0.30' $true $true
    Assert-Snapshot $after
    $script:FailMove = $true
    Run-Installer $old '0.0.29' $false
    Assert-Snapshot $after
    $script:FailVersionPath = Join-Path $destination 'iteron.exe'
    Run-Installer $old '0.0.29' $false
    $script:FailVersionPath = ''
    Assert-Snapshot $after
    $script:FailVersionPath = Join-Path $destination 'iteron-app-server.exe'
    Run-Installer $new '0.0.30' $false
    $script:FailVersionPath = ''
    Assert-Snapshot $after
    foreach ($mutation in @('traversal', 'duplicate', 'symlink', 'missing-server')) {
        $bad = Join-Path $work $mutation
        New-Fixture '0.0.30' $bad $mutation
        Run-Installer $bad '0.0.30' $false
        Assert-Snapshot $after
    }
    $archive = Get-ChildItem -LiteralPath $new -Filter '*.zip' | Select-Object -First 1
    [System.IO.File]::AppendAllText($archive.FullName, 'corruption')
    Run-Installer $new '0.0.30' $false
    Assert-Snapshot $after
    if ($ReleaseDirectory -ne '') {
        $script:UseRealPayload = $true
        Run-Installer $ReleaseDirectory $ReleaseVersion
    }
    Write-Output "$script:JourneyCount PowerShell installer journeys passed; syntax parsed"
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
