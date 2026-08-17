<#
.SYNOPSIS
    Helper that computes the SHA-256 of every artifact bootstrap.ps1 downloads and emits a JSON
    block ready to paste into `checksums.json` (or into bootstrap.ps1's pin table).

.DESCRIPTION
    READ THIS BEFORE USING IT.

    For artifacts whose vendor publishes a hash, this script fetches that published hash and
    compares it with what it downloaded. Those entries are marked `verified-against-vendor` and are
    trustworthy in the ordinary sense.

    For the two Microsoft bootstrappers (`vs_BuildTools.exe`, `MicrosoftEdgeWebview2Setup.exe`)
    Microsoft publishes no per-build hash behind its rotating redirect. Those entries are marked
    `trust-on-first-use`: recording them pins the exact bytes you fetched today, which detects a
    later silent change, but it does NOT prove the bytes were the ones Microsoft intended. This is
    a change detector, not a supply-chain proof, and the README says so too.

    Because of that, the trust-on-first-use downloads only happen when you pass
    -IUnderstandTrustOnFirstUse.

    This script installs nothing and modifies nothing outside its download cache.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\refresh-checksums.ps1 `
        -IUnderstandTrustOnFirstUse -OutFile .\checksums.json

.NOTES
    PowerShell 5.1 compatible.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()][string]$DownloadCache = 'C:\bootstrap-cache',
    [Parameter()][string]$OutFile,

    # Keep these in step with the values you pass to bootstrap.ps1.
    [Parameter()][string]$GitVersion = '2.51.0',
    [Parameter()][string]$GitWindowsRevision = '1',
    [Parameter()][string]$NodeVersion = '22.18.0',
    [Parameter()][string]$PythonVersion = '3.12.7',
    [Parameter()][string]$NsisVersion = '3.10',
    [Parameter()][string]$WixReleaseTag = 'wix3141rtm',

    [switch]$IUnderstandTrustOnFirstUse
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

$artifacts = @(
    [pscustomobject]@{
        File    = 'rustup-init.exe'
        Url     = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe'
        # Vendor publishes `<artifact>.sha256` next to the binary: "<hex>  <name>".
        ShaUrl  = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe.sha256'
        Tofu    = $false
    },
    [pscustomobject]@{
        File    = "node-v$NodeVersion-x64.msi"
        Url     = "https://nodejs.org/dist/v$NodeVersion/node-v$NodeVersion-x64.msi"
        ShaUrl  = "https://nodejs.org/dist/v$NodeVersion/SHASUMS256.txt"
        Tofu    = $false
    },
    [pscustomobject]@{
        File    = "python-$PythonVersion-amd64.exe"
        Url     = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
        # python.org publishes an MD5, a GPG signature (`<file>.asc`) and a sigstore bundle, but no
        # SHA-256 file. Verify the signature, THEN pin the sha256 printed below.
        ShaUrl  = ''
        Tofu    = $false
    },
    [pscustomobject]@{
        File    = "Git-$GitVersion-64-bit.exe"
        Url     = "https://github.com/git-for-windows/git/releases/download/v$GitVersion.windows.$GitWindowsRevision/Git-$GitVersion-64-bit.exe"
        # git-for-windows publishes hashes in the release BODY, not as a file. Cross-check by hand:
        #   gh release view v<ver>.windows.<rev> --repo git-for-windows/git --json body --jq .body
        ShaUrl  = ''
        Tofu    = $false
    },
    [pscustomobject]@{
        File    = "nsis-$NsisVersion-setup.exe"
        Url     = "https://downloads.sourceforge.net/project/nsis/NSIS%203/$NsisVersion/nsis-$NsisVersion-setup.exe"
        # SourceForge shows a SHA-256 in the file listing UI; cross-check there.
        ShaUrl  = ''
        Tofu    = $false
    },
    [pscustomobject]@{
        File    = 'wix314.exe'
        Url     = "https://github.com/wixtoolset/wix3/releases/download/$WixReleaseTag/wix314.exe"
        # Published in the release body; cross-check with:
        #   gh release view <tag> --repo wixtoolset/wix3 --json body --jq .body
        ShaUrl  = ''
        Tofu    = $false
    },
    [pscustomobject]@{
        File    = 'vs_BuildTools.exe'
        Url     = 'https://aka.ms/vs/17/release/vs_BuildTools.exe'
        ShaUrl  = ''
        Tofu    = $true
    },
    [pscustomobject]@{
        File    = 'MicrosoftEdgeWebview2Setup.exe'
        Url     = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703'
        ShaUrl  = ''
        Tofu    = $true
    }
)

if (-not (Test-Path -LiteralPath $DownloadCache)) {
    [void](New-Item -ItemType Directory -Path $DownloadCache -Force)
}

$out = [ordered]@{}
$out['_comment'] = 'SHA-256 pins for ops/windows-runner/bootstrap.ps1. Keys are artifact file names. Regenerate deliberately, never blindly.'

foreach ($a in $artifacts) {
    Write-Host ''
    Write-Host "==> $($a.File)" -ForegroundColor Cyan
    if ($a.Tofu -and -not $IUnderstandTrustOnFirstUse) {
        Write-Host '    skipped: trust-on-first-use artifact; pass -IUnderstandTrustOnFirstUse' -ForegroundColor Yellow
        continue
    }

    $path = Join-Path $DownloadCache $a.File
    Write-Host "    downloading $($a.Url)"
    Invoke-WebRequest -Uri $a.Url -OutFile $path -UseBasicParsing -MaximumRedirection 10
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()

    $status = 'trust-on-first-use'
    if (-not [string]::IsNullOrWhiteSpace($a.ShaUrl)) {
        $published = (Invoke-WebRequest -Uri $a.ShaUrl -UseBasicParsing).Content
        $expected = $null
        foreach ($line in ($published -split "`n")) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
                # `<hex>  <name>` / `<hex> *<name>` -- take the line naming THIS artifact.
                if ($Matches[2].Trim() -eq $a.File) {
                    $expected = $Matches[1].ToLowerInvariant()
                    break
                }
            } elseif ($trimmed -match '^([0-9a-fA-F]{64})$') {
                # Some `.sha256` files carry the bare digest and nothing else.
                $expected = $trimmed.ToLowerInvariant()
                break
            }
        }
        if ($null -eq $expected) {
            Write-Host "    could not parse a hash out of $($a.ShaUrl); cross-check by hand" -ForegroundColor Yellow
        } elseif ($expected -ne $hash) {
            throw "VENDOR HASH MISMATCH for $($a.File): published $expected, downloaded $hash. Stop and investigate."
        } else {
            $status = 'verified-against-vendor'
        }
    } else {
        $status = 'unpublished-hash: cross-check the vendor release notes by hand'
    }

    Write-Host "    sha256 : $hash"
    Write-Host "    status : $status"
    $out[$a.File] = $hash
}

$json = ([pscustomobject]$out) | ConvertTo-Json -Depth 3
Write-Host ''
Write-Host '==> paste this into checksums.json (or bootstrap.ps1 pin table)' -ForegroundColor Cyan
Write-Host $json

if ($OutFile) {
    Set-Content -LiteralPath $OutFile -Value $json -Encoding utf8
    Write-Host "written to $OutFile" -ForegroundColor Green
}
