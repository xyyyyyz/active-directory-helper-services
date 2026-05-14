<#
.SYNOPSIS
Imports and applies a shared AD CS certificate from a published manifest.

.DESCRIPTION
Reads a manifest that describes a published PFX, imports the certificate into
the local machine store, and optionally updates IIS or RDP bindings.

.PARAMETER ManifestPath
Path to the manifest JSON file describing the published certificate.

.EXAMPLE
.\Sync-AdcsCertificate.ps1 -ManifestPath C:\AdcsHelper\certificates\shared-web.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-CertificateSupportsServerAuthentication {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $serverAuthenticationOid = '1.3.6.1.5.5.7.3.1'
    $ekuExtension = $Certificate.Extensions |
        Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
        Select-Object -First 1

    if (-not $ekuExtension) {
        return $false
    }

    foreach ($usage in $ekuExtension.EnhancedKeyUsages) {
        if ($usage.Value -eq $serverAuthenticationOid) {
            return $true
        }
    }

    return $false
}

function Get-CertificatePassword {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest
    )

    if ($Manifest.PasswordEnvironmentVariable) {
        $environmentVariableName = [string]$Manifest.PasswordEnvironmentVariable
        $environmentVariableValue = [Environment]::GetEnvironmentVariable($environmentVariableName)
        if (-not [string]::IsNullOrWhiteSpace($environmentVariableValue)) {
            return ConvertTo-SecureString -String $environmentVariableValue -AsPlainText -Force
        }

        throw "Environment variable '$environmentVariableName' is not set."
    }

    if (-not (Test-Path -LiteralPath $Manifest.PasswordFilePath)) {
        throw "Password file '$($Manifest.PasswordFilePath)' does not exist."
    }

    Write-Verbose 'Reading the PFX password from a file. Prefer an injected environment variable or managed secret store.'
    $passwordText = (Get-Content -LiteralPath $Manifest.PasswordFilePath -Raw).Trim()
    return ($passwordText | ConvertTo-SecureString -AsPlainText -Force)
}

function Import-SharedCertificate {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest
    )

    if (-not (Test-Path -LiteralPath $Manifest.RepositoryPfxPath)) {
        throw "PFX path '$($Manifest.RepositoryPfxPath)' does not exist."
    }

    $password = Get-CertificatePassword -Manifest $Manifest
    $targetStore = if ($Manifest.TargetStore) { $Manifest.TargetStore } else { 'Cert:\LocalMachine\My' }

    $pfxData = Get-PfxData -FilePath $Manifest.RepositoryPfxPath -Password $password
    if (-not $pfxData.EndEntityCertificates -or $pfxData.EndEntityCertificates.Count -lt 1) {
        throw "PFX path '$($Manifest.RepositoryPfxPath)' does not contain an end-entity certificate."
    }

    $endEntityThumbprint = $pfxData.EndEntityCertificates[0].Thumbprint
    $existingCertificate = Get-ChildItem -Path $targetStore | Where-Object Thumbprint -eq $endEntityThumbprint | Select-Object -First 1

    if ($existingCertificate) {
        Write-Host "Certificate $endEntityThumbprint already present in $targetStore"
        return $existingCertificate
    }

    $imported = Import-PfxCertificate -FilePath $Manifest.RepositoryPfxPath -Password $password -CertStoreLocation $targetStore -Exportable
    Write-Host "Imported certificate $($imported.Thumbprint) into $targetStore"
    return $imported
}

function Set-IisCertificateBindings {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $Manifest.IisBindings) {
        return
    }

    Import-Module WebAdministration -ErrorAction Stop

    foreach ($binding in $Manifest.IisBindings) {
        $sslFlagsSni = 1
        $bindingInformation = '{0}:{1}:{2}' -f $binding.IPAddress, $binding.Port, $binding.HostName
        $existingBinding = Get-WebBinding -Name $binding.SiteName -Protocol https -ErrorAction SilentlyContinue |
            Where-Object bindingInformation -eq $bindingInformation |
            Select-Object -First 1

        if (-not $existingBinding) {
            New-WebBinding -Name $binding.SiteName -Protocol https -Port $binding.Port -IPAddress $binding.IPAddress -HostHeader $binding.HostName | Out-Null
        }

        $sslPath = 'IIS:\SslBindings\{0}!{1}!{2}' -f $binding.IPAddress, $binding.Port, $binding.HostName
        if (Test-Path -LiteralPath $sslPath) {
            Remove-Item -LiteralPath $sslPath -Force
        }

        New-Item -Path $sslPath -Thumbprint $Certificate.Thumbprint -SSLFlags $sslFlagsSni | Out-Null
        Write-Host "Bound certificate $($Certificate.Thumbprint) to IIS site '$($binding.SiteName)' on $bindingInformation"
    }
}

function Set-RdpCertificateBinding {
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not (Test-CertificateSupportsServerAuthentication -Certificate $Certificate)) {
        throw "Certificate $($Certificate.Thumbprint) does not include the Server Authentication EKU required for RDP."
    }

    $rdpSetting = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
    if (-not $rdpSetting) {
        throw 'Could not locate the RDP-Tcp listener configuration.'
    }

    $null = Set-CimInstance -InputObject $rdpSetting -Property @{ SSLCertificateSHA1Hash = $Certificate.Thumbprint }
    Write-Host "Updated RDP listener certificate to $($Certificate.Thumbprint)"
}

function Set-SqlServerCertificateBinding {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $Manifest.SqlBindings) {
        return
    }

    if (-not (Test-CertificateSupportsServerAuthentication -Certificate $Certificate)) {
        throw "Certificate $($Certificate.Thumbprint) does not include the Server Authentication EKU required for SQL Server TLS."
    }

    # SQL Server registry expects the thumbprint in lowercase with no spaces.
    $thumbprint = $Certificate.Thumbprint.ToLowerInvariant()

    foreach ($binding in $Manifest.SqlBindings) {
        $registryPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\{0}\MSSQLServer\SuperSocketNetLib' -f $binding.InstanceRegistryPath

        if (-not (Test-Path -LiteralPath $registryPath)) {
            throw "SQL Server registry path '$registryPath' not found for instance '$($binding.InstanceName)'. Verify the InstanceRegistryPath in the manifest."
        }

        $currentValue = (Get-ItemProperty -LiteralPath $registryPath -Name Certificate -ErrorAction SilentlyContinue).Certificate
        if ($currentValue -eq $thumbprint) {
            Write-Host "SQL Server instance '$($binding.InstanceName)' already bound to certificate $($Certificate.Thumbprint)"
            continue
        }

        Set-ItemProperty -LiteralPath $registryPath -Name Certificate -Value $thumbprint
        Write-Host "Bound certificate $($Certificate.Thumbprint) to SQL Server instance '$($binding.InstanceName)'"

        if ($binding.RestartService) {
            $serviceName = if ($binding.ServiceName) { [string]$binding.ServiceName } else { 'MSSQLSERVER' }
            Write-Host "Restarting SQL Server service '$serviceName' to apply the new certificate binding"
            Restart-Service -Name $serviceName -Force
            Write-Host "Restarted SQL Server service '$serviceName'"
        }
        else {
            $serviceName = if ($binding.ServiceName) { [string]$binding.ServiceName } else { 'MSSQLSERVER' }
            Write-Host "SQL Server service '$serviceName' must be restarted manually for the new certificate to take effect."
        }
    }
}

function Invoke-TrustedPostImportScript {
    param(
        [Parameter(Mandatory)]
        [string]$PostImportScriptPath,

        [Parameter(Mandatory)]
        [string]$ManifestPath,

        [Parameter(Mandatory)]
        [string]$CertificateThumbprint
    )

    $resolvedPostImportScriptPath = (Resolve-Path -LiteralPath $PostImportScriptPath).Path
    if ($resolvedPostImportScriptPath.StartsWith('\\')) {
        throw "Post-import script '$resolvedPostImportScriptPath' must be a trusted local path, not a UNC path."
    }

    $signature = Get-AuthenticodeSignature -FilePath $resolvedPostImportScriptPath
    if ($signature.Status -ne 'Valid') {
        throw "Post-import script '$resolvedPostImportScriptPath' must have a valid Authenticode signature."
    }

    & $resolvedPostImportScriptPath -CertificateThumbprint $CertificateThumbprint -ManifestPath $ManifestPath
}

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Manifest path '$ManifestPath' does not exist."
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$certificate = Import-SharedCertificate -Manifest $manifest

if ($manifest.IisBindings) {
    Set-IisCertificateBindings -Manifest $manifest -Certificate $certificate
}

if ($manifest.RdpEnabled) {
    Set-RdpCertificateBinding -Certificate $certificate
}

if ($manifest.SqlBindings) {
    Set-SqlServerCertificateBinding -Manifest $manifest -Certificate $certificate
}

if ($manifest.PostImportScriptPath) {
    if (-not (Test-Path -LiteralPath $manifest.PostImportScriptPath)) {
        throw "Post-import script '$($manifest.PostImportScriptPath)' does not exist."
    }

    Invoke-TrustedPostImportScript `
        -PostImportScriptPath $manifest.PostImportScriptPath `
        -ManifestPath $ManifestPath `
        -CertificateThumbprint $certificate.Thumbprint
}
