# AD certificate services helper

This folder contains a starting point for automating certificate issuance and distribution for Active Directory Certificate Services (AD CS) workloads.

## Recommended operating model

### 1. Central AD CS helper service

Use a central Windows helper host for certificates that must be shared across more than one member server, especially:

- IIS farms behind a load balancer
- SQL Server availability groups, failover cluster instances, and listener names
- Other commercial off-the-shelf (COTS) applications that require the same certificate and private key on multiple hosts

The helper host should:

1. Request certificates from AD CS by **DNS/FQDN**, never by IP address.
2. Use certificate templates that allow the required usages, for example:
   - **Server Authentication** for IIS, RDP, SQL Server TLS endpoints
   - **Client Authentication** when the same certificate must also be used for mutual TLS
3. Build the SAN set from all required DNS names, including:
   - service FQDN
   - listener name(s)
   - management alias(es) only if required by the application
4. Keep the issued PFX in a restricted repository or share.
5. Publish a small manifest beside each PFX so client helper jobs know what to import and where to bind it.
6. Renew certificates ahead of expiry and replace the repository copy before the old certificate expires.

### 2. Client helper job on member servers

Use a lightweight pull model on member servers:

1. A scheduled helper job reads the repository manifest.
2. If the published thumbprint differs from the currently installed certificate, the helper imports the new PFX into `LocalMachine\My`.
3. The helper applies service-specific binding logic:
   - **IIS**: update HTTPS bindings by hostname/port.
   - **RDP**: set the RDP listener thumbprint.
   - **SQL Server**: import the cert, then run a SQL-specific post-import step to update the SQL binding and restart during a maintenance window.
4. The job records what it changed and exits without re-importing unchanged certs.

This approach works well for HA services because the central helper controls a single exported certificate and each member server independently pulls the same artifact.

## Tooling recommendation

### Preferred default: PowerShell + Task Scheduler

For a Windows-only AD environment, **PowerShell with Task Scheduler is a good default choice** because:

- AD CS, certificate stores, IIS, scheduled tasks, and RDP listener settings are all natively manageable from PowerShell.
- It keeps dependencies low and fits locked-down enterprise environments.
- It works even if servers cannot accept inbound orchestration from a controller.
- It supports a pull model from a hardened SMB share.

Recommended split:

- **Central helper**: PowerShell scripts running on a fixed helper host or dedicated management server.
- **Member servers**: PowerShell helper script registered as a scheduled task running as `SYSTEM` or a gMSA.

### When Ansible is better

Use **Ansible** instead when you already have it in place for Windows automation, inventory, secrets, and change control. It is a strong choice for:

- standardizing configuration across many IIS or SQL hosts
- centrally tracking rollout status
- coordinating service restarts and maintenance windows
- integrating with vault-backed secrets instead of password files on shares

A common hybrid pattern is:

- PowerShell on the helper host for AD CS enrollment and packaging
- Ansible for distribution, import, and application binding

### When endpoint management or software distribution tools are better

An endpoint-management-style deployment platform is useful when your organisation already uses it for Windows package delivery and scheduling. It is best at:

- broad software rollout
- compliance reporting
- controlled deployments to endpoint populations

It is usually **less natural than PowerShell or Ansible** for certificate lifecycle operations because certificate enrollment, renewal, binding, and private-key handling still need custom scripts.

## Suggested service handling

### IIS

- Template EKUs: Server Authentication, optionally Client Authentication
- SANs: load balancer VIP FQDN plus any required hostnames
- Preferred model: central helper requests exportable cert, member servers pull/import, helper updates IIS bindings

### SQL Server

- Template EKUs: Server Authentication
- SANs: node FQDNs plus listener DNS names where required
- Prefer central request for shared listener-style certificates or when consistent rollout matters
- After import, run a SQL-specific binding step and plan a service restart
- Reusing the same private key during renewal can simplify rollover where application behavior expects continuity

### RDP

- Usually each server can request and renew its own certificate directly from AD CS
- Use a server-specific template with auto-enrollment or a local helper job
- Central sharing is normally unnecessary unless a gateway or broker design requires it

## Security and operations guidance

- Store exported PFX files only on a restricted share or repository.
- Restrict read access to the exact machine accounts, gMSAs, or admin groups that need the certificate.
- Keep the PFX password outside the manifest, ideally in a secret store or injected environment variable; if that is not possible, store it in a separately ACL'd file.
- Log certificate issuance, renewal, import, and binding actions.
- Renew early enough to support phased deployment.
- Keep a rollback option by retaining the previous PFX until the new certificate is verified.

## Folder contents

### Server (AD CS helper host / CA server)

- `server/Initialize-AdcsCentralHelper.ps1` – prepares the repository/share layout and creates a sample manifest.
- `server/Invoke-AdcsCertificateRenewalJob.ps1` – periodic job that reads every manifest, determines whether each certificate needs to be generated or renewed, generates a CSR from the manifest properties, submits it to the AD CS CA, accepts the issued certificate, and publishes a PFX back to the repository.
- `server/Install-AdcsCertificateRenewalTask.ps1` – registers a Windows scheduled task that calls `Invoke-AdcsCertificateRenewalJob.ps1` on a recurring schedule (default: once per day).

### Client (member servers)

- `client/Install-AdcsCertificatePullTask.ps1` – registers a scheduled pull job on a member server.
- `client/Sync-AdcsCertificate.ps1` – imports the published PFX and optionally applies IIS or RDP bindings.

## Example workflow

### One-time setup

1. Run `server/Initialize-AdcsCentralHelper.ps1` on the helper host to create the repository layout and a sample manifest.
2. Edit the generated manifest (under `certificates/`) to reflect the real subject, SAN set, certificate template, and binding configuration.
3. Run `server/Install-AdcsCertificateRenewalTask.ps1` on the helper host to register the renewal scheduled task:

   ```powershell
   .\server\Install-AdcsCertificateRenewalTask.ps1 `
       -RepositoryPath   C:\AdcsHelper `
       -CaConfig         "dc01\MyCA" `
       -RenewalScriptPath C:\Scripts\Invoke-AdcsCertificateRenewalJob.ps1 `
       -RunAsSystem
   ```

4. The scheduled task fires `Invoke-AdcsCertificateRenewalJob.ps1` on the configured interval.  For every manifest it finds:
   - Checks whether a PFX already exists and whether the certificate is within the `RenewalWindowDays` threshold.
   - If action is needed, generates a certreq INF file from the manifest, runs `certreq -new` to produce the CSR, submits it to the CA with `certreq -submit`, accepts the issued certificate with `certreq -accept`, and exports a PFX to the repository path.
   - Writes a log entry to `logs/renewal-<date>.log` for each manifest processed.

### Client pull setup (member servers)

5. Copy the client scripts to each member server.
6. Run `client/Install-AdcsCertificatePullTask.ps1` with the repository path and manifest path.
7. Let the scheduled task run `client/Sync-AdcsCertificate.ps1` on a schedule.
8. For SQL Server or other COTS apps, call an application-specific post-import script after the certificate is in `LocalMachine\My`.

### Renewal command reference

Run the renewal job manually at any time (use `-WhatIf` for a dry run):

```powershell
# Dry run — shows which certificates would be acted on
.\server\Invoke-AdcsCertificateRenewalJob.ps1 `
    -RepositoryPath C:\AdcsHelper `
    -CaConfig       "dc01\MyCA" `
    -WhatIf

# Live run
.\server\Invoke-AdcsCertificateRenewalJob.ps1 `
    -RepositoryPath C:\AdcsHelper `
    -CaConfig       "dc01\MyCA"
```
