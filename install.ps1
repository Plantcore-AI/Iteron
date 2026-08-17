#Requires -Version 5.1

<#
.SYNOPSIS
    Install Iteron from an immutable GitHub release on Windows x86-64.

.DESCRIPTION
    install.ps1 is the Windows counterpart of the POSIX install.sh. It resolves
    the x86_64-pc-windows-msvc release archive, verifies its exact lowercase
    SHA-256 row from the release SHA256SUMS manifest, proves every ZIP member is
    an expected regular file or plain directory that cannot escape the
    destination, and only then extracts and installs iteron.exe.

    The installer never requires administrator rights, never elevates, never
    installs a module, and never edits a PowerShell profile. Everything it
    changes lives under the chosen destination directory plus, unless
    -SkipPathUpdate is passed, the current user's PATH environment variable.

.PARAMETER Version
    An exact release tag such as v0.0.5, or "latest". Release packaging binds
    this default to an immutable tag; a copy taken straight from the repository
    still carries the unrendered marker and resolves "latest".

.PARAMETER BinDir
    Directory that receives iteron.exe. Defaults to $env:ITERON_INSTALL_DIR, then
    the deprecated $env:ITERON_CODE_INSTALL_DIR, then %LOCALAPPDATA%\Iteron\bin.

.PARAMETER SkipPathUpdate
    Install the executable without adding its directory to the user PATH.

.EXAMPLE
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri 'https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.ps1' | Invoke-Expression

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Version v0.0.5 -BinDir C:\tools\bin -SkipPathUpdate

.NOTES
    Windows PowerShell 5.1 and PowerShell 7 or newer are both supported. The
    -ExecutionPolicy Bypass argument applies to that one process only; no
    machine-wide or user-wide execution policy has to be weakened.
#>

[CmdletBinding()]
param(
    [string]$Version = '@ITERON_VERSION@',

    [string]$BinDir = '',

    [switch]$SkipPathUpdate
)

# Invoke-Expression evaluates text in its caller's scope. Keep strict mode,
# preferences, helper functions, and temporary state inside a child scope so
# the one-click form leaves the interactive PowerShell session intact.
& {
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# These mirror install.sh: the same release root, the same size protocol, and
# the one Windows target release-tools/common.py publishes.
$IteronReleaseRoot = 'https://github.com/Plantcore-AI/Iteron/releases'
$IteronTarget = 'x86_64-pc-windows-msvc'
$IteronBinaryName = 'iteron.exe'
$IteronMaxManifestBytes = 1048576
$IteronMaxArchiveBytes = 268435456
$IteronMaxUnpackedBytes = 134217728
$IteronArchiveMemberCount = 8
$IteronTagPattern = '^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$'
$IteronArchiveNamePattern =
    '^iteron-(v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-x86_64-pc-windows-msvc\.zip$'
$IteronArchiveMemberNames = @(
    'iteron.exe',
    'LICENSE',
    'README.md',
    'THIRD_PARTY_LICENSES.html',
    'THIRD_PARTY_NOTICES.txt',
    'SBOM.spdx.json',
    'BUILD-INFO.json'
)

# Fail the whole installation with one consistent, prefixed message.
function Write-IteronFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    throw "iteron: error: $Message"
}

# Refuse anything that cannot run the published x86-64 Windows executable.
function Test-IteronPlatform {
    $windowsFlag = Get-Variable -Name 'IsWindows' -ErrorAction SilentlyContinue
    if ($null -ne $windowsFlag -and -not $windowsFlag.Value) {
        Write-IteronFailure 'install.ps1 installs the Windows release and only runs on Windows. Use install.sh on macOS and Linux.'
    }

    $architecture = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = $env:PROCESSOR_ARCHITECTURE
    }
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        Write-IteronFailure 'the processor architecture is not reported by this environment'
    }

    $architecture = $architecture.Trim().ToUpperInvariant()
    if ($architecture -ne 'AMD64') {
        Write-IteronFailure "unsupported Windows architecture: $architecture. The release matrix publishes only $IteronTarget, so there is no ARM64 or 32-bit Windows archive to install."
    }
}

# Require TLS 1.2 or newer on Windows PowerShell, whose default is older.
function Enable-IteronTransportSecurity {
    try {
        $required = [Net.SecurityProtocolType]::Tls12
        if ([enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
            $required = $required -bor [Net.SecurityProtocolType]::Tls13
        }
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor $required
    } catch {
        Write-IteronFailure "could not require TLS 1.2 or newer: $($_.Exception.Message)"
    }
}

# Create a private working directory under the per-user temporary directory.
function Get-IteronWorkDirectory {
    $candidate = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('iteron.' + [System.IO.Path]::GetRandomFileName())
    $null = New-Item -ItemType Directory -Path $candidate
    return (Get-Item -LiteralPath $candidate).FullName
}

# Reject a redirect that leaves HTTPS. Older stacks allow that downgrade.
function Assert-IteronSecureResponse {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Response
    )

    if ($null -eq $Response) {
        return
    }

    $finalUri = $null
    try {
        $base = $Response.BaseResponse
        if ($null -ne $base) {
            $responseUri = $base.PSObject.Properties['ResponseUri']
            if ($null -ne $responseUri) {
                $finalUri = $responseUri.Value
            }
            if ($null -eq $finalUri) {
                $requestMessage = $base.PSObject.Properties['RequestMessage']
                if ($null -ne $requestMessage -and $null -ne $requestMessage.Value) {
                    $finalUri = $requestMessage.Value.RequestUri
                }
            }
        }
    } catch {
        $finalUri = $null
    }

    if ($null -ne $finalUri -and $finalUri.Scheme -ne 'https') {
        Write-IteronFailure "the download was redirected off HTTPS to $finalUri"
    }
}

# Best-effort advertised size, so an oversized body is refused before transfer.
function Get-IteronContentLength {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $ProgressPreference = 'SilentlyContinue'
    try {
        $response = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 60 -ErrorAction Stop
        $header = $response.Headers['Content-Length']
        if ($null -eq $header) {
            return $null
        }
        [long]$parsed = 0
        if ([long]::TryParse([string](@($header)[0]), [ref]$parsed)) {
            return $parsed
        }
        return $null
    } catch {
        return $null
    }
}

# Download one HTTPS asset with retries, a timeout, and a hard size ceiling.
function Invoke-IteronDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$OutFile,

        [Parameter(Mandatory = $true)]
        [long]$MaximumBytes,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if ($Uri -notmatch '^https://') {
        Write-IteronFailure "refusing a download URL that is not HTTPS: $Uri"
    }

    $advertised = Get-IteronContentLength -Uri $Uri
    if ($null -ne $advertised -and $advertised -gt $MaximumBytes) {
        Write-IteronFailure "$Description advertises $advertised bytes, above its $MaximumBytes byte ceiling"
    }

    $ProgressPreference = 'SilentlyContinue'
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $response = Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -MaximumRedirection 5 -TimeoutSec 300 -PassThru -ErrorAction Stop
            Assert-IteronSecureResponse -Response $response
            break
        } catch {
            if ($attempt -ge 3) {
                Write-IteronFailure "could not download $Description from ${Uri}: $($_.Exception.Message)"
            }
            Start-Sleep -Seconds $attempt
        }
    }

    if (-not (Test-Path -LiteralPath $OutFile -PathType Leaf)) {
        Write-IteronFailure "$Description was not written to disk"
    }
    $length = (Get-Item -LiteralPath $OutFile).Length
    if ($length -le 0 -or $length -gt $MaximumBytes) {
        Write-IteronFailure "$Description is empty or exceeds its $MaximumBytes byte ceiling"
    }
}

# Return the single SHA256SUMS row whose asset name matches, exactly as
# install.sh does: one lowercase digest, one name, no ambiguity.
function Select-IteronManifestEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$NamePattern
    )

    $matched = New-Object System.Collections.ArrayList
    foreach ($line in [System.IO.File]::ReadAllLines($ManifestPath)) {
        $row = [regex]::Match($line, '^(?<digest>[0-9a-f]{64})\s+\*?(?<name>\S+)\s*$')
        if (-not $row.Success) {
            continue
        }
        $name = $row.Groups['name'].Value
        if (-not [regex]::IsMatch($name, $NamePattern)) {
            continue
        }
        $null = $matched.Add([pscustomobject]@{
            Digest = $row.Groups['digest'].Value
            Name   = $name
        })
    }

    if ($matched.Count -ne 1) {
        Write-IteronFailure 'SHA256SUMS must contain exactly one digest for the Windows archive'
    }
    return $matched[0]
}

# Fail closed on any checksum mismatch, before the archive is ever opened.
function Assert-IteronChecksum {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedDigest
    )

    if ($ExpectedDigest -notmatch '^[0-9a-f]{64}$') {
        Write-IteronFailure 'archive digest is malformed'
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedDigest) {
        Write-IteronFailure "archive checksum verification failed: expected $ExpectedDigest, computed $actual"
    }
}

# Prove the archive is safe, then extract it. Pass one enumerates every member
# and rejects absolute, drive-qualified, traversing, unexpected, duplicated,
# oversized, symlinked, and non-regular entries. Pass two extracts only the
# validated members, each to the destination path that pass one proved.
function Expand-IteronArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArchivePath,

        [Parameter(Mandatory = $true)]
        [string]$RootName,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    try {
        Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction Stop
    } catch {
        # PowerShell 7 already carries these types; only Windows PowerShell 5.1
        # needs the assembly loaded, and loading it twice is harmless.
        Write-Verbose 'System.IO.Compression.FileSystem is already available'
    }

    $expectedDirectory = "$RootName/"
    $expectedFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($member in $IteronArchiveMemberNames) {
        $null = $expectedFiles.Add("$RootName/$member")
    }

    $destinationRoot = [System.IO.Path]::GetFullPath($DestinationPath)
    if (-not $destinationRoot.EndsWith([string][System.IO.Path]::DirectorySeparatorChar)) {
        $destinationRoot += [System.IO.Path]::DirectorySeparatorChar
    }

    $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        if ($archive.Entries.Count -ne $IteronArchiveMemberCount) {
            Write-IteronFailure 'release archive has an unexpected member count'
        }

        $plan = New-Object System.Collections.ArrayList
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $directorySeen = $false
        [long]$unpackedBytes = 0

        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            if ([string]::IsNullOrEmpty($name)) {
                Write-IteronFailure 'release archive contains an unnamed entry'
            }
            if ($name.Contains('\')) {
                Write-IteronFailure "release archive entry uses a backslash path: $name"
            }
            if ($name.Contains(':')) {
                Write-IteronFailure "release archive entry is drive qualified: $name"
            }
            if ($name.StartsWith('/') -or [System.IO.Path]::IsPathRooted($name)) {
                Write-IteronFailure "release archive entry is an absolute path: $name"
            }
            foreach ($segment in $name.TrimEnd('/').Split('/')) {
                if ($segment -eq '' -or $segment -eq '.' -or $segment -eq '..') {
                    Write-IteronFailure "release archive entry escapes its root: $name"
                }
            }
            if (-not $seen.Add($name)) {
                Write-IteronFailure "release archive contains a duplicate entry: $name"
            }

            $isDirectory = $false
            if ($name -ceq $expectedDirectory) {
                $isDirectory = $true
                $directorySeen = $true
            } elseif (-not $expectedFiles.Contains($name)) {
                Write-IteronFailure "release archive contains an unexpected path: $name"
            }

            # A ZIP directory entry is exactly the one with an empty Name.
            if ($isDirectory -ne [string]::IsNullOrEmpty($entry.Name)) {
                Write-IteronFailure "release archive entry type does not match its path: $name"
            }

            # Deterministic packaging stamps UNIX mode bits in the high word.
            # Anything that is not a plain file or plain directory, symbolic
            # links included, is refused here rather than written to disk.
            $attributes = [int]$entry.ExternalAttributes
            $fileType = ($attributes -shr 16) -band 0xF000
            if ($fileType -ne 0) {
                $requiredType = 0x8000
                if ($isDirectory) {
                    $requiredType = 0x4000
                }
                if ($fileType -ne $requiredType) {
                    Write-IteronFailure "release archive contains a link or special file: $name"
                }
            }
            if ((($attributes -band 0xFFFF) -band 0x400) -ne 0) {
                Write-IteronFailure "release archive contains a reparse point: $name"
            }

            if ($isDirectory) {
                if ($entry.Length -ne 0) {
                    Write-IteronFailure "release archive directory entry carries data: $name"
                }
            } else {
                if ($entry.Length -lt 0) {
                    Write-IteronFailure "release archive entry reports a negative size: $name"
                }
                $unpackedBytes += [long]$entry.Length
                if ($unpackedBytes -gt $IteronMaxUnpackedBytes) {
                    Write-IteronFailure 'release archive exceeds the safe unpacked size limit'
                }
            }

            try {
                $relative = $name.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
                $full = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($destinationRoot, $relative))
            } catch {
                Write-IteronFailure "release archive entry has an unusable path: $name"
            }
            if (-not $full.StartsWith($destinationRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-IteronFailure "release archive entry escapes the destination directory: $name"
            }

            $null = $plan.Add([pscustomobject]@{
                Entry       = $entry
                Destination = $full
                IsDirectory = $isDirectory
            })
        }

        if (-not $directorySeen) {
            Write-IteronFailure 'release archive is missing its root directory entry'
        }
        if ($unpackedBytes -le 0) {
            Write-IteronFailure 'release archive is empty'
        }

        foreach ($item in $plan) {
            if ($item.IsDirectory) {
                $null = New-Item -ItemType Directory -Path $item.Destination -Force
                continue
            }
            $parent = [System.IO.Path]::GetDirectoryName($item.Destination)
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                $null = New-Item -ItemType Directory -Path $parent -Force
            }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($item.Entry, $item.Destination, $false)
        }
    } finally {
        $archive.Dispose()
    }

    $binary = Join-Path -Path (Join-Path -Path $DestinationPath -ChildPath $RootName) -ChildPath $IteronBinaryName
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        Write-IteronFailure 'archive iteron.exe entry is not a regular file'
    }
    return (Get-Item -LiteralPath $binary).FullName
}

# Run the short `-V` smoke test install.sh uses at every stage.
function Get-IteronReportedVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # A native command writing to stderr must not become a terminating error
    # here; the exit code is the signal that matters.
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Path -V 2>&1
    } catch {
        Write-IteronFailure "could not run ${Path}: $($_.Exception.Message)"
    }
    if ($LASTEXITCODE -ne 0) {
        Write-IteronFailure "$Path failed its version smoke test with exit code $LASTEXITCODE"
    }
    return (($output | Out-String).Trim())
}

# Compare the smoke-test output against the exact expected release version.
function Assert-IteronReportedVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$VersionNumber,

        [Parameter(Mandatory = $true)]
        [string]$Stage
    )

    $reported = Get-IteronReportedVersion -Path $Path
    if ($reported -cne "iteron $VersionNumber") {
        Write-IteronFailure "$Stage binary reported an unexpected version: $reported"
    }
    return $reported
}

# Install the verified executable, replacing any previous copy in place.
function Install-IteronBinary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$BinDirectory,

        [Parameter(Mandatory = $true)]
        [string]$VersionNumber
    )

    if (-not (Test-Path -LiteralPath $BinDirectory -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $BinDirectory -Force
    }
    $BinDirectory = (Get-Item -LiteralPath $BinDirectory).FullName
    $target = Join-Path -Path $BinDirectory -ChildPath $IteronBinaryName
    if (Test-Path -LiteralPath $target -PathType Container) {
        Write-IteronFailure "installation destination is a directory: $target"
    }

    # Re-running the installer must not accumulate debris from earlier runs.
    Get-ChildItem -LiteralPath $BinDirectory -Filter '.iteron.exe.*' -File -Force -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }

    $staged = Join-Path -Path $BinDirectory -ChildPath ('.iteron.exe.new.' + [System.IO.Path]::GetRandomFileName())
    $retired = $null
    try {
        Copy-Item -LiteralPath $SourcePath -Destination $staged -Force
        $null = Assert-IteronReportedVersion -Path $staged -VersionNumber $VersionNumber -Stage 'staged'

        if (Test-Path -LiteralPath $target -PathType Leaf) {
            try {
                [System.IO.File]::Replace($staged, $target, $null)
            } catch {
                # A running executable cannot be overwritten on Windows, but it
                # can be renamed aside. Keep the upgrade atomic from the
                # command's point of view either way.
                $retired = Join-Path -Path $BinDirectory -ChildPath ('.iteron.exe.old.' + [System.IO.Path]::GetRandomFileName())
                try {
                    [System.IO.File]::Move($target, $retired)
                } catch {
                    Write-IteronFailure "could not replace $target. Close any running iteron.exe and try again."
                }
                [System.IO.File]::Move($staged, $target)
            }
        } else {
            [System.IO.File]::Move($staged, $target)
        }
    } finally {
        if (Test-Path -LiteralPath $staged -PathType Leaf) {
            Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }
    }

    if ($null -ne $retired -and (Test-Path -LiteralPath $retired -PathType Leaf)) {
        Remove-Item -LiteralPath $retired -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $retired -PathType Leaf) {
            Write-Warning "the previous executable is still in use and was left at $retired"
        }
    }

    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        Write-IteronFailure 'installation did not produce a regular destination file'
    }
    return $target
}

# Add the destination to the user PATH once, without corrupting the existing
# value. Windows stores the default user PATH as REG_EXPAND_SZ containing
# %USERPROFILE% references, and [Environment]::SetEnvironmentVariable writes a
# plain string, so an expandable value is preserved through the registry.
function Add-IteronPathEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $normalized = $Directory.TrimEnd('\')
    $key = $null
    $raw = $null
    $expandable = $false
    $alreadyPresent = $false
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        if ($null -ne $key -and ($key.GetValueNames() -contains 'Path')) {
            $raw = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $expandable = ($key.GetValueKind('Path') -eq [Microsoft.Win32.RegistryValueKind]::ExpandString)
        }

        if ($null -eq $raw) {
            $raw = [string][Environment]::GetEnvironmentVariable('PATH', 'User')
            $expandable = $false
        }

        foreach ($existing in $raw.Split(';')) {
            $candidate = $existing.Trim().TrimEnd('\')
            if ($candidate -eq '') {
                continue
            }
            $expanded = [Environment]::ExpandEnvironmentVariables($candidate).TrimEnd('\')
            if ($candidate -ieq $normalized -or $expanded -ieq $normalized) {
                $alreadyPresent = $true
                break
            }
        }

        if (-not $alreadyPresent) {
            $updated = $normalized
            if ($raw.Trim() -ne '') {
                $updated = $raw.TrimEnd(';') + ';' + $normalized
            }

            if ($expandable -and $null -ne $key) {
                $key.SetValue('Path', $updated, [Microsoft.Win32.RegistryValueKind]::ExpandString)
            } else {
                [Environment]::SetEnvironmentVariable('PATH', $updated, 'User')
            }
        }
    } finally {
        if ($null -ne $key) {
            $key.Dispose()
        }
    }

    if ($null -eq $env:PATH -or $env:PATH -eq '') {
        $env:PATH = $normalized
    } elseif (-not (($env:PATH.Split(';') | ForEach-Object { $_.TrimEnd('\') }) -icontains $normalized)) {
        $env:PATH = $env:PATH.TrimEnd(';') + ';' + $normalized
    }
    return (-not $alreadyPresent)
}

# Resolve the destination the way install.sh resolves --bin-dir.
function Resolve-IteronBinDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Requested
    )

    $destination = $Requested
    if ([string]::IsNullOrWhiteSpace($destination)) {
        $destination = [string]$env:ITERON_INSTALL_DIR
    }
    if ([string]::IsNullOrWhiteSpace($destination)) {
        # install.sh renamed ITERON_CODE_INSTALL_DIR to ITERON_INSTALL_DIR and kept the old name
        # working with a deprecation warning. Mirror that contract exactly.
        $destination = [string]$env:ITERON_CODE_INSTALL_DIR
        if (-not [string]::IsNullOrWhiteSpace($destination)) {
            Write-Warning 'ITERON_CODE_INSTALL_DIR is deprecated; use ITERON_INSTALL_DIR'
        }
    }
    if ([string]::IsNullOrWhiteSpace($destination)) {
        $localAppData = [string]$env:LOCALAPPDATA
        if ([string]::IsNullOrWhiteSpace($localAppData)) {
            Write-IteronFailure 'LOCALAPPDATA is not set; pass -BinDir'
        }
        $destination = Join-Path -Path $localAppData -ChildPath 'Iteron\bin'
    }

    $destination = [Environment]::ExpandEnvironmentVariables($destination.Trim())
    if ([string]::IsNullOrWhiteSpace($destination)) {
        Write-IteronFailure 'installation directory is empty'
    }
    if (-not [System.IO.Path]::IsPathRooted($destination)) {
        $destination = Join-Path -Path (Get-Location -PSProvider FileSystem).ProviderPath -ChildPath $destination
    }
    return [System.IO.Path]::GetFullPath($destination)
}

# Whole installation, in the order install.sh performs it.
function Invoke-IteronInstall {
    Test-IteronPlatform
    Enable-IteronTransportSecurity

    $requested = $Version
    if ($null -eq $requested) {
        $requested = ''
    }
    $requested = $requested.Trim()
    if ($requested -eq '' -or $requested -match '^@[A-Z_]+@$') {
        # An installer taken from the repository rather than from a release
        # asset has no version bound into it. Resolve the latest release.
        $requested = 'latest'
    }
    if ($requested -ne 'latest' -and $requested -notmatch $IteronTagPattern) {
        Write-IteronFailure 'version must be "latest" or an exact stable tag such as v0.0.1'
    }

    $work = Get-IteronWorkDirectory
    try {

    if ($requested -eq 'latest') {
        $manifestUri = "$IteronReleaseRoot/latest/download/SHA256SUMS"
        $namePattern = $IteronArchiveNamePattern
    } else {
        $manifestUri = "$IteronReleaseRoot/download/$requested/SHA256SUMS"
        $namePattern = '^' + [regex]::Escape("iteron-$requested-$IteronTarget.zip") + '$'
    }

    $manifestPath = Join-Path -Path $work -ChildPath 'SHA256SUMS'
    Invoke-IteronDownload -Uri $manifestUri -OutFile $manifestPath -MaximumBytes $IteronMaxManifestBytes -Description 'SHA256SUMS'
    $entry = Select-IteronManifestEntry -ManifestPath $manifestPath -NamePattern $namePattern

    $named = [regex]::Match($entry.Name, $IteronArchiveNamePattern)
    if (-not $named.Success) {
        Write-IteronFailure "SHA256SUMS names an unexpected Windows archive: $($entry.Name)"
    }
    $tag = $named.Groups[1].Value
    $versionNumber = $tag.Substring(1)
    $archiveRoot = "iteron-$tag-$IteronTarget"
    $archiveName = "$archiveRoot.zip"

    # Even when "latest" resolved the tag, the archive itself is fetched from
    # the immutable per-tag URL, so a release published in between cannot be
    # substituted for the one this digest describes.
    $archivePath = Join-Path -Path $work -ChildPath $archiveName
    Invoke-IteronDownload `
        -Uri "$IteronReleaseRoot/download/$tag/$archiveName" `
        -OutFile $archivePath `
        -MaximumBytes $IteronMaxArchiveBytes `
        -Description $archiveName
    Assert-IteronChecksum -Path $archivePath -ExpectedDigest $entry.Digest

    $extractPath = Join-Path -Path $work -ChildPath 'extract'
    $null = New-Item -ItemType Directory -Path $extractPath
    $binary = Expand-IteronArchive -ArchivePath $archivePath -RootName $archiveRoot -DestinationPath $extractPath
    $null = Assert-IteronReportedVersion -Path $binary -VersionNumber $versionNumber -Stage 'downloaded'

    $binDirectory = Resolve-IteronBinDirectory -Requested $BinDir
    $installed = Install-IteronBinary -SourcePath $binary -BinDirectory $binDirectory -VersionNumber $versionNumber
    $reported = Assert-IteronReportedVersion -Path $installed -VersionNumber $versionNumber -Stage 'installed'

    Write-Output "Iteron $versionNumber installed at $installed"
    Write-Output $reported

    if ($SkipPathUpdate) {
        Write-Output "Add $binDirectory to PATH to run the iteron command."
    } else {
        try {
            if (Add-IteronPathEntry -Directory $binDirectory) {
                Write-Output "Added $binDirectory to the user PATH. Open a new terminal to pick it up."
            } else {
                Write-Output "$binDirectory is already on the user PATH."
            }
        } catch {
            Write-Warning "iteron.exe is installed, but the user PATH could not be updated: $($_.Exception.Message)"
            Write-Warning "Add $binDirectory to PATH to run the iteron command."
        }
    }

    # The same honesty install.sh prints for a missing Linux sandbox: state the
    # confinement reality of this platform, and never fail the install over it.
    Write-Warning 'Windows has no code-execution sandbox backend. Confinement is unavailable, so --confine refuses to run commands and the default operator-authority mode runs them unconfined.'
    } finally {
        if (Test-Path -LiteralPath $work) {
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Invoke-IteronInstall
}
