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
    Subject                  = 'CN=ag-listener.example.com'
    # DnsNames contains the AG node FQDNs for the SAN set sent to the CA.
    # ListenerNames contains the AG listener and FCI virtual-network DNS names.
    # The central helper merges both arrays when building the certificate request,
    # so listener names should not be duplicated in DnsNames.
    DnsNames                 = @('node1.example.com', 'node2.example.com', 'node3.example.com')
    # ListenerNames are the AG listener (or FCI virtual network) DNS names that
    # must also appear in the SAN set.  Keep them separate so helper tooling can
    # distinguish listener names from node names when building the certificate request.
    ListenerNames            = @('ag-listener.example.com', 'ag-listener2.example.com')
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
    # SqlBindings configures the SQL Server TLS certificate binding on each node.
    # InstanceRegistryPath must match the registry key for the SQL Server instance,
    # for example 'MSSQL16.MSSQLSERVER' for a SQL Server 2022 default instance or
    # 'MSSQL16.SQLEXPRESS' for a named instance.
    # Set RestartService to true only during a planned maintenance window; the
    # new certificate does not take effect until the SQL Server service is restarted.
    SqlBindings              = @(
        [ordered]@{
            InstanceName         = 'MSSQLSERVER'
            InstanceRegistryPath = 'MSSQL16.MSSQLSERVER'
            ServiceName          = 'MSSQLSERVER'
            RestartService       = $false
        }
    )
    RdpEnabled               = $false
    PostImportScriptPath     = ''
    RenewalWindowDays        = 30
    ReuseKeyOnRenewal        = $true
    Notes                    = 'Update this manifest after issuing the real certificate.'
}

$manifestJson = $manifest | ConvertTo-Json -Depth 5
$manifestEncoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8NoBOM' } else { 'utf8' }
Set-Content -LiteralPath $manifestPath -Value $manifestJson -Encoding $manifestEncoding

Write-Host "Repository initialized at $RepositoryPath"
Write-Host "Sample manifest: $manifestPath"
Write-Host "Create a secure password file or set a password environment variable before publishing a PFX."
Write-Host "Suggested password file path: $passwordPath"
Write-Host "Publish the issued PFX to: $pfxPath"
