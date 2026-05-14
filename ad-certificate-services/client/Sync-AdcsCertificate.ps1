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

    return ((Get-Content -LiteralPath $Manifest.PasswordFilePath -Raw).Trim() | ConvertTo-SecureString -AsPlainText -Force)
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

    Set-CimInstance -InputObject $rdpSetting -Property @{ SSLCertificateSHA1Hash = $Certificate.Thumbprint } | Out-Null
    Write-Host "Updated RDP listener certificate to $($Certificate.Thumbprint)"
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

if ($manifest.PostImportScriptPath) {
    if (-not (Test-Path -LiteralPath $manifest.PostImportScriptPath)) {
        throw "Post-import script '$($manifest.PostImportScriptPath)' does not exist."
    }

    & $manifest.PostImportScriptPath -CertificateThumbprint $certificate.Thumbprint -ManifestPath $ManifestPath
}
