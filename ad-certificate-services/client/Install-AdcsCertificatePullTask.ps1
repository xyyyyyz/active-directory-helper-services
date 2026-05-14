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

if ($RunAsSystem) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
}
else {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
}

Write-Host "Scheduled task '$TaskName' registered to sync certificate manifest '$ManifestPath'."
