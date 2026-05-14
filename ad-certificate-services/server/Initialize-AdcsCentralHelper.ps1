<#
.SYNOPSIS
Initializes a central AD CS helper repository layout.

.DESCRIPTION
Creates the directory structure and sample manifest used by a central helper
host to publish shared certificates for member-server pull jobs.

.PARAMETER RepositoryPath
Base path for the helper repository or share.

.PARAMETER CertificateName
Logical certificate name used for the sample manifest and file names.

.PARAMETER Force
Overwrites an existing sample manifest.

.EXAMPLE
.\Initialize-AdcsCentralHelper.ps1 -RepositoryPath C:\AdcsHelper -CertificateName shared-web
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RepositoryPath,

    [string]$CertificateName = 'shared-service-cert',

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifestPath = Join-Path -Path $RepositoryPath -ChildPath ("certificates/{0}.json" -f $CertificateName)
$passwordPath = Join-Path -Path $RepositoryPath -ChildPath ("passwords/{0}.txt" -f $CertificateName)
$pfxPath = Join-Path -Path $RepositoryPath -ChildPath ("certificates/{0}.pfx" -f $CertificateName)

if ((Test-Path -LiteralPath $manifestPath) -and -not $Force) {
    throw "Manifest already exists at '$manifestPath'. Use -Force to overwrite."
}

$directories = @(
    $RepositoryPath,
    (Join-Path -Path $RepositoryPath -ChildPath 'certificates'),
    (Join-Path -Path $RepositoryPath -ChildPath 'passwords'),
    (Join-Path -Path $RepositoryPath -ChildPath 'logs'),
    (Join-Path -Path $RepositoryPath -ChildPath 'requests'),
    (Join-Path -Path $RepositoryPath -ChildPath 'templates')
)

foreach ($directory in $directories) {
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory | Out-Null
    }
}

$manifest = [ordered]@{
    CertificateName          = $CertificateName
    Subject                  = 'CN=service.example.com'
    DnsNames                 = @('service.example.com', 'listener.example.com')
    Applications             = @('IIS', 'SQL')
    CertificateTemplate      = 'WebServer'
    PublishMode              = 'CentralHelperIssued'
    RepositoryPfxPath        = $pfxPath
    PasswordFilePath         = $passwordPath
    PasswordEnvironmentVariable = ''
    FriendlyName             = 'Shared service certificate'
    TargetStore              = 'Cert:\LocalMachine\My'
    IisBindings              = @(
        [ordered]@{
            SiteName  = 'Default Web Site'
            Port      = 443
            IPAddress = '*'
            HostName  = 'service.example.com'
        }
    )
    RdpEnabled               = $false
    PostImportScriptPath     = ''
    RenewalWindowDays        = 30
    ReuseKeyOnRenewal        = $true
    Notes                    = 'Update this manifest after issuing the real certificate.'
}

$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Repository initialized at $RepositoryPath"
Write-Host "Sample manifest: $manifestPath"
Write-Host "Create a secure password file or set a password environment variable before publishing a PFX."
Write-Host "Suggested password file path: $passwordPath"
Write-Host "Publish the issued PFX to: $pfxPath"
