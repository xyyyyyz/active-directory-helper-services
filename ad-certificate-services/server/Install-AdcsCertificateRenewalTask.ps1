<#
.SYNOPSIS
Registers a scheduled task that periodically runs the AD CS certificate renewal job.

.DESCRIPTION
Creates a Windows scheduled task on the AD CS helper host (or CA server) that
calls Invoke-AdcsCertificateRenewalJob.ps1 on a repeating schedule.  The task
checks every manifest in the central repository and renews any certificate that
is missing or approaching expiry.

.PARAMETER RepositoryPath
Base path to the central helper repository created by
Initialize-AdcsCentralHelper.ps1.

.PARAMETER CaConfig
AD CS CA configuration string in the form "CAServer\CAName" passed through to
the renewal script.  Use "-" to select the default CA from Active Directory.

.PARAMETER RenewalScriptPath
Path to Invoke-AdcsCertificateRenewalJob.ps1 on this machine.

.PARAMETER TaskName
Name of the scheduled task to create or replace.

.PARAMETER RepeatMinutes
Interval in minutes between renewal job runs.  Defaults to 1440 (once per day).

.PARAMETER RunAsSystem
Register the scheduled task to run as the SYSTEM account.  Omit this switch to
register the task without a specific user account (interactive selection applies
when the task is registered manually).

.EXAMPLE
.\Install-AdcsCertificateRenewalTask.ps1 `
    -RepositoryPath  C:\AdcsHelper `
    -CaConfig        "dc01\MyCA" `
    -RenewalScriptPath C:\Scripts\Invoke-AdcsCertificateRenewalJob.ps1 `
    -RunAsSystem
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RepositoryPath,

    [Parameter(Mandatory)]
    [string]$CaConfig,

    [Parameter(Mandatory)]
    [string]$RenewalScriptPath,

    [string]$TaskName = 'ADCS Certificate Renewal',

    [int]$RepeatMinutes = 1440,

    [switch]$RunAsSystem
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $RepositoryPath)) {
    throw "Repository path '$RepositoryPath' does not exist."
}

if (-not (Test-Path -LiteralPath $RenewalScriptPath)) {
    throw "Renewal script path '$RenewalScriptPath' does not exist."
}

# Prefer Windows PowerShell first because it is the default on most AD-joined
# Windows Server hosts and has the broadest compatibility with inbox modules.
$preferredShellCommand = Get-Command powershell -ErrorAction SilentlyContinue
if ($preferredShellCommand) {
    $shellPath = $preferredShellCommand.Source
}
else {
    $shellPath = (Get-Command pwsh -ErrorAction Stop).Source
}

$argument = "-NoProfile -ExecutionPolicy Bypass -File `"$RenewalScriptPath`" -RepositoryPath `"$RepositoryPath`" -CaConfig `"$CaConfig`""
$action   = New-ScheduledTaskAction -Execute $shellPath -Argument $argument
$trigger  = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(5) `
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

Write-Host "Scheduled task '$TaskName' registered."
Write-Host "Repository:    $RepositoryPath"
Write-Host "CA config:     $CaConfig"
Write-Host "Renewal script:$RenewalScriptPath"
Write-Host "Schedule:      every $RepeatMinutes minute(s), first run in 5 minutes."
