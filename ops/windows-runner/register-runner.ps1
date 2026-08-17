<#
.SYNOPSIS
    Bridges a short-lived runner registration token from process environment into the secure
    parameter accepted by install-runner.ps1.

.DESCRIPTION
    This wrapper exists for non-interactive SSH provisioning. The caller supplies the token only
    in the current process environment; the wrapper clears it before invoking install-runner.ps1.
    It never writes or prints the token.
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Repo,
    [Parameter(Mandatory)][string]$Instance,
    [Parameter(Mandatory)][string]$Labels,
    [Parameter(Mandatory)][string]$RunnerVersion,
    [Parameter(Mandatory)][string]$RunnerSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$variableName = 'ITERON_RUNNER_REGISTRATION_TOKEN'
$plain = [Environment]::GetEnvironmentVariable($variableName, 'Process')
try {
    [Environment]::SetEnvironmentVariable($variableName, $null, 'Process')
    if ([string]::IsNullOrWhiteSpace($plain)) {
        throw "$variableName was not supplied to this process."
    }
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    $plain = $null
    & (Join-Path $PSScriptRoot 'install-runner.ps1') `
        -Repo $Repo `
        -Instance $Instance `
        -Labels $Labels `
        -RunnerVersion $RunnerVersion `
        -RunnerSha256 $RunnerSha256 `
        -Token $secure
} finally {
    $plain = $null
    [Environment]::SetEnvironmentVariable($variableName, $null, 'Process')
}
