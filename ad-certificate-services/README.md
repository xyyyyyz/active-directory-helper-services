# AD certificate services helper

This folder contains a starting point for automating certificate issuance and distribution for Active Directory Certificate Services (AD CS) workloads.

## Recommended operating model

### 1. Central AD CS helper service

Use a central Windows helper host for certificates that must be shared across more than one member server, especially:

- IIS farms behind a load balancer
- SQL Server availability groups, failover cluster instances, and listener names
- Other COTS applications that require the same certificate and private key on multiple hosts

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
2. If the published thumbprint differs from the currently installed certificate, the helper imports the new PFX into `LocalMachine\\My`.
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

### When DSM / endpoint software distribution tools are better

A DSM-style endpoint deployment platform is useful when your organisation already uses it for Windows package delivery and scheduling. It is best at:

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
- Keep the PFX password outside the manifest, ideally in a secret store; if that is not possible, store it in a separately ACL'd file.
- Log certificate issuance, renewal, import, and binding actions.
- Renew early enough to support phased deployment.
- Keep a rollback option by retaining the previous PFX until the new certificate is verified.

## Folder contents

- `server/Initialize-AdcsCentralHelper.ps1` - prepares a repository/share layout and sample manifest.
- `client/Install-AdcsCertificatePullTask.ps1` - registers a scheduled pull job on a member server.
- `client/Sync-AdcsCertificate.ps1` - imports the published PFX and optionally applies IIS or RDP bindings.

## Example workflow

1. Run `server/Initialize-AdcsCentralHelper.ps1` on the helper host to create the repository layout.
2. Have the helper host request or renew the certificate and publish:
   - the PFX
   - a manifest JSON file
   - a separately protected password file or vault reference
3. Copy the client scripts to each member server.
4. Run `client/Install-AdcsCertificatePullTask.ps1` with the repository path and manifest path.
5. Let the scheduled task run `client/Sync-AdcsCertificate.ps1` on a schedule.
6. For SQL Server or other COTS apps, call an application-specific post-import script after the certificate is in `LocalMachine\\My`.
