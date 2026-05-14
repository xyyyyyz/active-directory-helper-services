<#
.SYNOPSIS
Registers a scheduled task that syncs a published AD CS certificate manifest.

.DESCRIPTION
Creates a Windows scheduled task that runs the certificate sync script on a
recurring schedule so a member server can pull updated certificates.

.PARAMETER ManifestPath
Path to the published certificate manifest JSON file.

.PARAMETER SyncScriptPath
Path to the Sync-AdcsCertificate.ps1 script.

.PARAMETER TaskName
Name of the scheduled task to create or replace.

.PARAMETER RepeatMinutes
Number of minutes between sync attempts.

.PARAMETER RunAsSystem
Registers the scheduled task to run as SYSTEM.

.EXAMPLE
.\Install-AdcsCertificatePullTask.ps1 -ManifestPath C:\AdcsHelper\web.json -SyncScriptPath C:\Scripts\Sync-AdcsCertificate.ps1 -RunAsSystem
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ManifestPath,

    [Parameter(Mandatory)]
    [string]$SyncScriptPath,

    [string]$TaskName = 'ADCS Certificate Pull',

    [int]$RepeatMinutes = 60,

    [switch]$RunAsSystem
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Manifest path '$ManifestPath' does not exist."
}

if (-not (Test-Path -LiteralPath $SyncScriptPath)) {
    throw "Sync script path '$SyncScriptPath' does not exist."
}

$pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $pwshPath) {
    $pwshPath = (Get-Command powershell -ErrorAction Stop).Source
}

$argument = "-NoProfile -ExecutionPolicy Bypass -File `"$SyncScriptPath`" -ManifestPath `"$ManifestPath`""
$action = New-ScheduledTaskAction -Execute $pwshPath -Argument $argument
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $RepeatMinutes) `
    -RepetitionDuration ([TimeSpan]::MaxValue)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew

$registerTaskParameters = @{
    TaskName = $TaskName
    Action   = $action
    Trigger  = $trigger
    Settings = $settings
    RunLevel = 'Highest'
    Force    = $true
}

if ($RunAsSystem) {
    $registerTaskParameters.User = 'SYSTEM'
}

Register-ScheduledTask @registerTaskParameters | Out-Null

Write-Host "Scheduled task '$TaskName' registered to sync certificate manifest '$ManifestPath'."
