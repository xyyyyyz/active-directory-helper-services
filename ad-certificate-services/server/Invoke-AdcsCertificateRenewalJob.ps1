<#
.SYNOPSIS
Periodic job that checks repository certificates and renews them via AD CS.

.DESCRIPTION
Scans every manifest JSON file found in the certificates folder of the central
helper repository.  For each manifest the script determines whether the
certificate needs to be generated for the first time or renewed:

  - No PFX exists yet              → generate
  - Certificate is already expired → renew
  - Certificate expires within the RenewalWindowDays threshold → renew

When a certificate needs action the script:

  1. Writes a certreq INF file containing the subject, SAN set, key parameters,
     and certificate-template name taken from the manifest.
  2. Runs  certreq -new   to generate the private key and CSR.
  3. Runs  certreq -submit  to send the CSR to the specified AD CS CA and
     collect the issued certificate response.
  4. Runs  certreq -accept  to install the issued certificate together with its
     private key into the local machine certificate store.
  5. Exports the certificate and chain as a PFX file to the repository path
     declared in the manifest.
  6. Writes or reuses the PFX password in the manifest password file.

Run this script on the AD CS server or on a dedicated helper host that holds
Certificate Services enrollment rights for the templates named in the manifests.

.PARAMETER RepositoryPath
Base path to the central helper repository created by
Initialize-AdcsCentralHelper.ps1.

.PARAMETER CaConfig
AD CS CA configuration string in the form "CAServer\CAName".  Pass "-" to let
certreq use the default CA published in Active Directory.

.PARAMETER CertStoreLocation
Local machine certificate store path used for private-key operations.
Defaults to Cert:\LocalMachine\My.

.PARAMETER KeyLength
RSA key length used when generating a new private key.  Defaults to 2048.

.PARAMETER HashAlgorithm
Signature hash algorithm written into the CSR.  Defaults to SHA256.

.EXAMPLE
.\Invoke-AdcsCertificateRenewalJob.ps1 -RepositoryPath C:\AdcsHelper -CaConfig "dc01\MyCA"

.EXAMPLE
.\Invoke-AdcsCertificateRenewalJob.ps1 -RepositoryPath C:\AdcsHelper -CaConfig "-" -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$RepositoryPath,

    [Parameter(Mandatory)]
    [string]$CaConfig,

    [string]$CertStoreLocation = 'Cert:\LocalMachine\My',

    [ValidateSet(2048, 3072, 4096)]
    [int]$KeyLength = 2048,

    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$HashAlgorithm = 'SHA256'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function Write-RenewalLog {
    param(
        [string]$Message,
        [string]$LogPath,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = '[{0}][{1}] {2}' -f $timestamp, $Level, $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8

    switch ($Level) {
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Error $Message -ErrorAction Continue }
        default   { Write-Host $Message }
    }
}

function Get-PfxPasswordFromManifest {
    <#
    Read-only password retrieval used when inspecting an existing PFX.
    Returns $null when the password cannot be determined without creating one.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest
    )

    if ($Manifest.PasswordEnvironmentVariable) {
        $envName  = [string]$Manifest.PasswordEnvironmentVariable
        $envValue = [Environment]::GetEnvironmentVariable($envName)
        if (-not [string]::IsNullOrWhiteSpace($envValue)) {
            return ConvertTo-SecureString -String $envValue -AsPlainText -Force
        }
    }

    $passwordFilePath = [string]$Manifest.PasswordFilePath
    if (-not [string]::IsNullOrWhiteSpace($passwordFilePath) -and (Test-Path -LiteralPath $passwordFilePath)) {
        $passwordText = (Get-Content -LiteralPath $passwordFilePath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($passwordText)) {
            return ConvertTo-SecureString -String $passwordText -AsPlainText -Force
        }
    }

    return $null
}

function Get-OrCreatePfxPassword {
    <#
    Returns the PFX password for a manifest, reusing an existing password file
    when one is present and generating a new cryptographically random password
    when one is not.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest
    )

    # Environment variable takes precedence and is never overwritten from here.
    if ($Manifest.PasswordEnvironmentVariable) {
        $envName  = [string]$Manifest.PasswordEnvironmentVariable
        $envValue = [Environment]::GetEnvironmentVariable($envName)
        if (-not [string]::IsNullOrWhiteSpace($envValue)) {
            return ConvertTo-SecureString -String $envValue -AsPlainText -Force
        }
        throw "Environment variable '$envName' is not set or is empty."
    }

    $passwordFilePath = [string]$Manifest.PasswordFilePath
    if ([string]::IsNullOrWhiteSpace($passwordFilePath)) {
        throw "Manifest for '$($Manifest.CertificateName)' specifies no PasswordFilePath and no PasswordEnvironmentVariable."
    }

    # Reuse an existing password so client pull jobs do not need reconfiguring.
    if (Test-Path -LiteralPath $passwordFilePath) {
        $existingText = (Get-Content -LiteralPath $passwordFilePath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($existingText)) {
            return ConvertTo-SecureString -String $existingText -AsPlainText -Force
        }
    }

    # Generate a cryptographically random 32-character base-64 password.
    $randomBytes = [byte[]]::new(24)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($randomBytes)
    $newPassword = [Convert]::ToBase64String($randomBytes)

    $passwordDir = Split-Path -LiteralPath $passwordFilePath
    if (-not (Test-Path -LiteralPath $passwordDir)) {
        New-Item -Path $passwordDir -ItemType Directory | Out-Null
    }

    $encoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8NoBOM' } else { 'utf8' }
    Set-Content -LiteralPath $passwordFilePath -Value $newPassword -Encoding $encoding

    return ConvertTo-SecureString -String $newPassword -AsPlainText -Force
}

function Test-CertificateNeedsRenewal {
    <#
    Returns a PSCustomObject with:
      NeedsRenewal        [bool]
      Reason              [string]  e.g. NoPfxFound | Expired | WithinRenewalWindow | Current | CertNotInStore
      ExistingThumbprint  [string]  thumbprint of the current cert, or $null
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest,

        [string]$CertStoreLocation = 'Cert:\LocalMachine\My'
    )

    $pfxPath           = [string]$Manifest.RepositoryPfxPath
    $renewalWindowDays = if ($Manifest.RenewalWindowDays) { [int]$Manifest.RenewalWindowDays } else { 30 }
    $renewalThreshold  = (Get-Date).AddDays($renewalWindowDays)

    if (-not (Test-Path -LiteralPath $pfxPath)) {
        return [pscustomobject]@{ NeedsRenewal = $true; Reason = 'NoPfxFound'; ExistingThumbprint = $null }
    }

    # Primary check: look for the issued certificate in the local machine store.
    # certreq -accept installs it there, so this will be accurate on the helper host.
    $subject    = [string]$Manifest.Subject
    $storeCert  = Get-ChildItem -Path $CertStoreLocation -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($storeCert) {
        if ($storeCert.NotAfter -le (Get-Date)) {
            return [pscustomobject]@{ NeedsRenewal = $true; Reason = 'Expired'; ExistingThumbprint = $storeCert.Thumbprint }
        }
        if ($storeCert.NotAfter -le $renewalThreshold) {
            return [pscustomobject]@{ NeedsRenewal = $true; Reason = 'WithinRenewalWindow'; ExistingThumbprint = $storeCert.Thumbprint }
        }
        return [pscustomobject]@{ NeedsRenewal = $false; Reason = 'Current'; ExistingThumbprint = $storeCert.Thumbprint }
    }

    # Secondary check: read the published PFX directly when the cert is not in
    # the local store (e.g. first run after the store was cleared).
    try {
        $pfxPassword = Get-PfxPasswordFromManifest -Manifest $Manifest
        if ($pfxPassword) {
            $pfxData     = Get-PfxData -FilePath $pfxPath -Password $pfxPassword -ErrorAction Stop
            $endEntityCert = $pfxData.EndEntityCertificates |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1

            if ($endEntityCert) {
                if ($endEntityCert.NotAfter -le (Get-Date)) {
                    return [pscustomobject]@{ NeedsRenewal = $true; Reason = 'Expired'; ExistingThumbprint = $endEntityCert.Thumbprint }
                }
                if ($endEntityCert.NotAfter -le $renewalThreshold) {
                    return [pscustomobject]@{ NeedsRenewal = $true; Reason = 'WithinRenewalWindow'; ExistingThumbprint = $endEntityCert.Thumbprint }
                }
                return [pscustomobject]@{ NeedsRenewal = $false; Reason = 'Current'; ExistingThumbprint = $endEntityCert.Thumbprint }
            }
        }
    }
    catch {
        Write-Verbose "Could not read PFX for '$($Manifest.CertificateName)': $_"
    }

    # Cannot determine status from store or PFX — trigger renewal to be safe.
    return [pscustomobject]@{ NeedsRenewal = $true; Reason = 'CertNotInStore'; ExistingThumbprint = $null }
}

function New-CertificateRequestInf {
    <#
    Writes a certreq INF file built from a manifest.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest,

        [Parameter(Mandatory)]
        [string]$InfPath,

        [int]$KeyLength,
        [string]$HashAlgorithm,

        # When set and ReuseKeyOnRenewal is true, instructs certreq to reuse the
        # existing private key associated with the old certificate.
        [string]$ExistingThumbprint
    )

    $reuseKey = $Manifest.ReuseKeyOnRenewal -and (-not [string]::IsNullOrWhiteSpace($ExistingThumbprint))

    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add('[Version]')
    $lines.Add('Signature="$Windows NT$"')
    $lines.Add('')
    $lines.Add('[NewRequest]')
    $lines.Add('Subject = "{0}"'                   -f $Manifest.Subject)
    $lines.Add('KeySpec = 1')
    $lines.Add('KeyLength = {0}'                   -f $KeyLength)
    $lines.Add('Exportable = TRUE')
    $lines.Add('MachineKeySet = TRUE')
    $lines.Add('SMIME = FALSE')
    $lines.Add('PrivateKeyArchive = FALSE')
    $lines.Add('UserProtected = FALSE')
    $lines.Add('UseExistingKeySet = {0}'            -f $(if ($reuseKey) { 'TRUE' } else { 'FALSE' }))
    $lines.Add('ProviderName = "Microsoft RSA SChannel Cryptographic Provider"')
    $lines.Add('ProviderType = 12')
    $lines.Add('RequestType = PKCS10')
    $lines.Add('KeyUsage = 0xa0')
    $lines.Add('HashAlgorithm = {0}'               -f $HashAlgorithm)

    if ($Manifest.FriendlyName) {
        $lines.Add('FriendlyName = "{0}"'          -f $Manifest.FriendlyName)
    }

    if ($reuseKey) {
        $lines.Add('RenewalCert = "{0}"'           -f $ExistingThumbprint)
    }

    $lines.Add('')
    $lines.Add('[EnhancedKeyUsageExtension]')
    $lines.Add('OID=1.3.6.1.5.5.7.3.1 ; Server Authentication')

    if ($Manifest.DnsNames -and $Manifest.DnsNames.Count -gt 0) {
        $lines.Add('')
        $lines.Add('[Extensions]')
        $lines.Add('2.5.29.17 = "{text}"')
        foreach ($dnsName in $Manifest.DnsNames) {
            $lines.Add('_continue_ = "dns={0}&"' -f $dnsName)
        }
    }

    if ($Manifest.CertificateTemplate) {
        $lines.Add('')
        $lines.Add('[RequestAttributes]')
        $lines.Add('CertificateTemplate = {0}' -f $Manifest.CertificateTemplate)
    }

    [System.IO.File]::WriteAllLines($InfPath, $lines, [System.Text.Encoding]::UTF8)
}

function Invoke-CertreqProcess {
    <#
    Runs certreq.exe with the given arguments and returns a result object.
    #>
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $pinfo                          = [System.Diagnostics.ProcessStartInfo]::new()
    $pinfo.FileName                 = 'certreq.exe'
    $pinfo.Arguments                = $Arguments -join ' '
    $pinfo.RedirectStandardOutput   = $true
    $pinfo.RedirectStandardError    = $true
    $pinfo.UseShellExecute          = $false

    $process            = [System.Diagnostics.Process]::new()
    $process.StartInfo  = $pinfo
    $process.Start() | Out-Null

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout   = $stdout
        Stderr   = $stderr
    }
}

function New-CsrFromManifest {
    <#
    Generates a CSR and matching private key for a manifest.
    Returns the path to the generated .csr file.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest,

        [Parameter(Mandatory)]
        [string]$WorkDir,

        [int]$KeyLength,
        [string]$HashAlgorithm,
        [string]$ExistingThumbprint
    )

    $certName = $Manifest.CertificateName
    $infPath  = Join-Path -Path $WorkDir -ChildPath "$certName.inf"
    $csrPath  = Join-Path -Path $WorkDir -ChildPath "$certName.csr"

    New-CertificateRequestInf `
        -Manifest           $Manifest `
        -InfPath            $infPath `
        -KeyLength          $KeyLength `
        -HashAlgorithm      $HashAlgorithm `
        -ExistingThumbprint $ExistingThumbprint

    $result = Invoke-CertreqProcess -Arguments @('-new', '-f', "`"$infPath`"", "`"$csrPath`"")
    if ($result.ExitCode -ne 0) {
        throw "certreq -new failed for '$certName' (exit $($result.ExitCode)): $($result.Stderr.Trim())"
    }

    return $csrPath
}

function Submit-CsrToCa {
    <#
    Submits a CSR to the AD CS CA and retrieves the issued certificate response.
    Returns the path to the issued .cer file.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$CsrPath,

        [Parameter(Mandatory)]
        [string]$CaConfig,

        [Parameter(Mandatory)]
        [string]$WorkDir,

        [Parameter(Mandatory)]
        [pscustomobject]$Manifest
    )

    $certName = $Manifest.CertificateName
    $cerPath  = Join-Path -Path $WorkDir -ChildPath "$certName.cer"
    $rspPath  = Join-Path -Path $WorkDir -ChildPath "$certName.rsp"

    $result = Invoke-CertreqProcess -Arguments @(
        '-submit', '-f',
        "-config `"$CaConfig`"",
        "`"$CsrPath`"",
        "`"$cerPath`"",
        "`"$rspPath`""
    )

    if ($result.ExitCode -ne 0) {
        throw "certreq -submit failed for '$certName' (exit $($result.ExitCode)): $($result.Stderr.Trim())"
    }

    if (-not (Test-Path -LiteralPath $cerPath)) {
        throw "certreq -submit completed but the issued certificate file '$cerPath' was not created. CA output: $($result.Stdout.Trim())"
    }

    return $cerPath
}

function Install-IssuedCertificate {
    <#
    Runs certreq -accept to install the issued certificate and its private key
    into the local machine store.  Returns the thumbprint of the installed cert.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$CerPath,

        [Parameter(Mandatory)]
        [string]$CertName
    )

    $result = Invoke-CertreqProcess -Arguments @('-accept', '-f', '-machine', "`"$CerPath`"")
    if ($result.ExitCode -ne 0) {
        throw "certreq -accept failed for '$CertName' (exit $($result.ExitCode)): $($result.Stderr.Trim())"
    }

    # certreq -accept outputs the thumbprint on a line like:
    #   Thumbprint: abc123...
    $thumbprintMatch = [regex]::Match($result.Stdout, '(?i)Thumbprint:\s*([0-9a-fA-F]+)')
    if ($thumbprintMatch.Success) {
        return $thumbprintMatch.Groups[1].Value.ToUpper()
    }

    # Fallback: read the thumbprint directly from the CER file.
    $issuedCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CerPath)
    return $issuedCert.Thumbprint.ToUpper()
}

function Export-IssuedCertificateAsPfx {
    <#
    Locates the installed certificate by thumbprint in the local machine store,
    exports it (with chain) to the repository PFX path declared in the manifest,
    and returns the thumbprint of the exported certificate.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint,

        [Parameter(Mandatory)]
        [pscustomobject]$Manifest,

        [Parameter(Mandatory)]
        [string]$CertStoreLocation
    )

    $cert = Get-ChildItem -Path $CertStoreLocation |
        Where-Object Thumbprint -eq $Thumbprint |
        Select-Object -First 1

    if (-not $cert) {
        throw "Issued certificate with thumbprint '$Thumbprint' was not found in $CertStoreLocation after certreq -accept."
    }

    $pfxPath = [string]$Manifest.RepositoryPfxPath
    $pfxDir  = Split-Path -LiteralPath $pfxPath
    if (-not (Test-Path -LiteralPath $pfxDir)) {
        New-Item -Path $pfxDir -ItemType Directory | Out-Null
    }

    $password = Get-OrCreatePfxPassword -Manifest $Manifest
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password -Force | Out-Null

    return $cert.Thumbprint
}

function Invoke-CertificateRenewal {
    <#
    Orchestrates the full CSR → submit → accept → export pipeline for one manifest.
    Returns the thumbprint of the newly issued certificate.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Manifest,

        [Parameter(Mandatory)]
        [string]$WorkDir,

        [Parameter(Mandatory)]
        [string]$CaConfig,

        [Parameter(Mandatory)]
        [string]$CertStoreLocation,

        [int]$KeyLength,
        [string]$HashAlgorithm,
        [string]$ExistingThumbprint,
        [string]$LogPath
    )

    $certName = $Manifest.CertificateName

    Write-RenewalLog -Message "[$certName] Step 1/4 – Generating CSR in '$WorkDir'." -LogPath $LogPath
    $csrPath = New-CsrFromManifest `
        -Manifest           $Manifest `
        -WorkDir            $WorkDir `
        -KeyLength          $KeyLength `
        -HashAlgorithm      $HashAlgorithm `
        -ExistingThumbprint $ExistingThumbprint

    Write-RenewalLog -Message "[$certName] Step 2/4 – Submitting CSR to CA '$CaConfig'." -LogPath $LogPath
    $cerPath = Submit-CsrToCa `
        -CsrPath   $csrPath `
        -CaConfig  $CaConfig `
        -WorkDir   $WorkDir `
        -Manifest  $Manifest

    Write-RenewalLog -Message "[$certName] Step 3/4 – Accepting issued certificate." -LogPath $LogPath
    $issuedThumbprint = Install-IssuedCertificate -CerPath $cerPath -CertName $certName

    Write-RenewalLog -Message "[$certName] Step 4/4 – Exporting PFX to '$($Manifest.RepositoryPfxPath)'." -LogPath $LogPath
    Export-IssuedCertificateAsPfx `
        -Thumbprint         $issuedThumbprint `
        -Manifest           $Manifest `
        -CertStoreLocation  $CertStoreLocation | Out-Null

    return $issuedThumbprint
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $RepositoryPath)) {
    throw "Repository path '$RepositoryPath' does not exist."
}

$certificatesPath = Join-Path -Path $RepositoryPath -ChildPath 'certificates'
$logsPath         = Join-Path -Path $RepositoryPath -ChildPath 'logs'
$requestsPath     = Join-Path -Path $RepositoryPath -ChildPath 'requests'

foreach ($dir in @($certificatesPath, $logsPath, $requestsPath)) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory | Out-Null
    }
}

$logFile = Join-Path -Path $logsPath -ChildPath ('renewal-{0}.log' -f (Get-Date -Format 'yyyy-MM-dd'))

Write-RenewalLog -Message 'Certificate renewal job started.' -LogPath $logFile

$manifests = Get-ChildItem -Path $certificatesPath -Filter '*.json' -File -ErrorAction SilentlyContinue

if (-not $manifests) {
    Write-RenewalLog -Message "No manifests found in '$certificatesPath'. Nothing to do." -LogPath $logFile
    return
}

$totalProcessed = 0
$totalRenewed   = 0
$totalSkipped   = 0
$totalFailed    = 0

foreach ($manifestFile in $manifests) {
    $certName = $manifestFile.BaseName

    Write-RenewalLog -Message "Checking manifest: $($manifestFile.Name)" -LogPath $logFile

    $manifest = $null
    try {
        $manifest = Get-Content -LiteralPath $manifestFile.FullName -Raw | ConvertFrom-Json
    }
    catch {
        Write-RenewalLog -Message "Failed to parse manifest '$($manifestFile.FullName)': $_" -LogPath $logFile -Level Error
        $totalFailed++
        continue
    }

    $renewalCheck = $null
    try {
        $renewalCheck = Test-CertificateNeedsRenewal -Manifest $manifest -CertStoreLocation $CertStoreLocation
    }
    catch {
        Write-RenewalLog -Message "Error checking renewal status for '$certName': $_" -LogPath $logFile -Level Error
        $totalFailed++
        continue
    }

    $totalProcessed++

    if (-not $renewalCheck.NeedsRenewal) {
        Write-RenewalLog -Message "Certificate '$certName' is current (thumbprint $($renewalCheck.ExistingThumbprint)). Skipping." -LogPath $logFile
        $totalSkipped++
        continue
    }

    Write-RenewalLog -Message "Certificate '$certName' needs action. Reason: $($renewalCheck.Reason)." -LogPath $logFile

    if (-not $PSCmdlet.ShouldProcess($certName, 'Request and publish certificate')) {
        continue
    }

    $workDir = Join-Path -Path $requestsPath -ChildPath ('{0}-{1}' -f $certName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -Path $workDir -ItemType Directory | Out-Null

    try {
        $issuedThumbprint = Invoke-CertificateRenewal `
            -Manifest           $manifest `
            -WorkDir            $workDir `
            -CaConfig           $CaConfig `
            -CertStoreLocation  $CertStoreLocation `
            -KeyLength          $KeyLength `
            -HashAlgorithm      $HashAlgorithm `
            -ExistingThumbprint $renewalCheck.ExistingThumbprint `
            -LogPath            $logFile

        Write-RenewalLog -Message "Certificate '$certName' renewed successfully. Thumbprint: $issuedThumbprint" -LogPath $logFile
        $totalRenewed++
    }
    catch {
        Write-RenewalLog -Message "Renewal failed for '$certName': $_" -LogPath $logFile -Level Error
        $totalFailed++
    }
    finally {
        # Remove the INF file from the work directory so no key metadata is
        # retained longer than necessary; the CER and CSR are kept for audit.
        $infToRemove = Join-Path -Path $workDir -ChildPath "$certName.inf"
        if (Test-Path -LiteralPath $infToRemove) {
            Remove-Item -LiteralPath $infToRemove -Force
        }
    }
}

Write-RenewalLog -Message ("Renewal job complete. Processed: {0}  Renewed: {1}  Skipped: {2}  Failed: {3}" -f $totalProcessed, $totalRenewed, $totalSkipped, $totalFailed) -LogPath $logFile
