# SMB over QUIC Deployment Guide

This guide configures a Windows Server 2025 file server and Windows 11 clients for SMB over QUIC. It also covers optional TLS client certificate authentication and Kerberos over KDC Proxy.

The FQDNs chosen are for demonstration purposes of multiple scenarios. The ones I use internally in the lab and one public domain, workinghardinit.work (the one of my blog).

## Architecture

Clients connect to `\\fsquic.datawisetech.com\Share` over QUIC on UDP 443. The file server presents a TLS certificate whose Subject Alternative Name (SAN) contains `fsquic.datawisetech.com`. SMB user authentication remains Kerberos or NTLM. When enabled, a client certificate adds TLS mutual authentication before SMB authentication; it does not replace Kerberos or NTLM.

When clients are off the corporate network, KDC Proxy relays their Kerberos requests over HTTPS through the `/KdcProxy` endpoint. It is normally, in production, deployed on a separate, domain-joined, highly secured server,and is not the SMB over QUIC endpoint. However in the lab to save a VM is use the same server. Windows Administration Center (WAC) however does this as well and I have mixed feelings about this. Ideally you make this redundant and place it behing a reverse proxy or Microsoft Entra Application Proxy if you have connectivity to the servers from there.

## Prerequisites

Use an account with local administrator rights on each server. Domain changes such as SPNs and computer aliases require appropriate Active Directory permissions.

The file server needs Windows Server 2025, the File Server role, a share with appropriate NTFS and share permissions, and an internet-reachable UDP 443 path. The client needs Windows 11 with current updates, DNS resolution for the file-server name, and trust for the issuing certificate authority.

Create a public or private DNS record for every name clients will use. Do not expose TCP 445 to the internet. Publish only UDP 443 through the perimeter firewall or load balancer, and preserve UDP support end to end.

The scripts prefer native PowerShell when it can fully express the task. `Get-Certificate` can submit Enterprise CA template requests with a subject and multiple DNS SANs, so the certificate enrollment scripts use it rather than `certreq.exe`. Other Windows tools remain appropriate when they provide required functionality PowerShell lacks. For KDC Proxy, Microsoft documents an HTTP.SYS IP:port binding; an SNI hostname:port binding is an optional design choice that must be validated in the target environment.

## Certificate Requirements

Install the server certificate, including its private key, in `Cert:\LocalMachine\My` on the file server. It must be currently valid and have the Server Authentication EKU. Its SAN list must include every DNS or NetBIOS name used in an SMB over QUIC UNC path.

A separate mapping is required for each name. A single certificate may contain all names as SANs, but one SMB mapping is created per name. Renewed certificates normally have a new thumbprint; the mapping script selects the newest valid certificate with the configured subject and replaces stale mappings.

For client certificate authentication, each Windows 11 client needs a certificate with a private key and Client Authentication EKU. The server must trust its issuing chain. This adds mutual TLS and certificate-based access control to the SMB over QUIC connection. After TLS completes, SMB still authenticates the user with Kerberos or NTLM and enforces normal share and NTFS permissions.

## Enterprise CA Certificate Templates

Create two separate version 2 or later templates using `certtmpl.msc`: one server certificate template for SMB over QUIC and one machine client certificate template for optional mutual TLS. Template configuration is normally a manual AD CS administration task; the scripts automate enrollment and certificate mapping after the templates are published.

### Server Certificate Template

1. Open `certtmpl.msc` with Enterprise Admin or delegated template-administration rights. Right-click **Web Server**, then select **Duplicate Template**.
2. On **Compatibility**, select **Windows Server 2016** for the certification authority and **Windows 10 / Windows Server 2016** for the certificate recipient. These settings create a version 4 template and permit modern cryptographic providers. Select older compatibility values only when an older CA or client must enroll from this template.
3. On **General**, set both the Template display name and Template name to `SmbOverQuicServer`. The template name is the value supplied to `-CertificateTemplate`.
4. On **Request Handling**, choose a non-exportable private key unless a documented backup or migration requirement needs exportability. The certificate must contain the **Digital signature** key usage.
5. On **Cryptography**, select an approved provider. Use ECDSA P-256 or stronger where supported; RSA is also supported with a minimum 2048-bit key. Require SHA-256 or stronger for the certificate signature and hash algorithm.
6. On **Extensions**, confirm **Application Policies** contains only **Server Authentication** (`1.3.6.1.5.5.7.3.1`) unless another documented server use requires an additional EKU. Remove Client Authentication and unrelated EKUs.
7. On **Subject Name**, select **Supply in the request**. This is required because `Request-SmbQuicServerCertificate.ps1` supplies the common name and every client-facing DNS name as SANs. Do not add IP address SANs: SMB over QUIC uses DNS names, and IP-address access prevents Kerberos. Do not permit arbitrary untrusted users to enroll in this template, because they could request names they do not own.
8. On **Security**, grant the file-server computer accounts or a dedicated file-server security group `Read` and `Enroll`. Grant `Autoenroll` only if you want Group Policy to renew these certificates automatically.
9. Select **OK** to create the template. On the issuing CA, open `certsrv.msc`, right-click **Certificate Templates**, select **New**, then **Certificate Template to Issue**, and select `SmbOverQuicServer`. Refresh the CA template cache with `certutil -pulse` or restart the **Active Directory Certificate Services** service if the new template is not immediately visible.

### Client Certificate Template

1. In `certtmpl.msc`, duplicate **Workstation Authentication**. This produces a machine-oriented starting point for Windows 11 client certificates.
2. On **Compatibility**, select **Windows Server 2016** for the certification authority and **Windows 10 / Windows Server 2016** for the certificate recipient. Keep the client template separate from the server template so its enrollment scope and EKUs remain limited.
3. On **General**, use `SmbOverQuicClientCert` for both the Template display name and Template name.
4. On **Request Handling**, use a non-exportable private key. Client private keys identify the device during mutual TLS and should not be portable by default.
5. On **Cryptography**, use an approved provider with a minimum RSA 2048-bit key or an approved ECDSA key, and SHA-256 or stronger signing.
6. On **Extensions**, confirm **Application Policies** contains **Client Authentication** (`1.3.6.1.5.5.7.3.2`). Remove Server Authentication unless the same certificate is intentionally used for another role.
7. On **Subject Name**, choose **Supply in the request** when using `Request-SmbQuicClientCertificate.ps1` as written; it supplies `-CertificateSubject`. Alternatively, choose **Build from this Active Directory information** and change the script to match the CA-issued subject before using autoenrollment.
8. On **Security**, grant the Windows 11 computer accounts or a workstation security group `Read`, `Enroll`, and `Autoenroll` as appropriate. Do not grant enrollment to broad groups unless every member should receive a device certificate trusted by the SMB file server.
9. Publish the template on the issuing CA using `certsrv.msc`: **Certificate Templates** > **New** > **Certificate Template to Issue** > `SmbOverQuicClientCert`.
10. For GPO-based renewal, enable **Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Certificate Services Client - Auto-Enrollment** and choose **Enabled** with certificate renewal and update options.

Use the template name, not merely the friendly display name, when running the enrollment scripts. If a renamed template is not visible on a CA, refresh the CA cache and wait for AD replication. See Ned Pyle's SMB over QUIC deployment guidance, [Step 1: Install a server certificate](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic#step-1-install-a-server-certificate), for the Microsoft SMB over QUIC certificate requirements.

### Enrollment, Approval, and Renewal Behavior

The enrollment scripts use `Get-Certificate` and normally expect the Enterprise CA to issue the certificate immediately. A `Pending` result is not required for a normal deployment. It occurs only when the certificate template or CA policy requires an approval step, such as **CA certificate manager approval**, required authorized signatures, or a custom policy workflow.

The scripts reuse an existing matching certificate while it has more than the configured renewal threshold remaining. By default, they request a replacement when the certificate has 30 days or less remaining. This prevents a scheduled run from requesting a new certificate on every execution.

If a request is placed in `Pending` state:

1. Record the request details returned by `Get-Certificate` and approve the request in the issuing CA's **Pending Requests** node, if the template or CA policy requires approval.
2. Retrieve the approved certificate using the enrollment request returned by `Get-Certificate`, or use the normal certificate enrollment update process configured by your organization. Confirm that the certificate is installed in `Cert:\LocalMachine\My` and has the required private key, EKU, SANs, validity period, and issuing chain.
3. Rerun the appropriate script after the certificate is installed. For a file server, rerun `ConfigureSMBQUICCertMapping.ps1`; for a KDC Proxy, rerun `KDCProxySetup.ps1` so HTTP.SYS uses the new certificate; for a client certificate, rerun the client access-control configuration with the new SHA-256 certificate hash.

The current scripts stop with an explanatory error when the enrollment status is `Pending`, `Denied`, or another non-issued state; they do not silently replace the currently working certificate. During a pending renewal, the old certificate remains available and should continue serving until the replacement is issued, validated, and mapped. Do not delete the old certificate or remove its SMB/HTTP.SYS mapping until the replacement has been tested. A denied request requires correcting the template, permissions, subject/SAN request, or CA policy before submitting another request.

## File Server Setup

1. Install the File Server role if it is not already installed:

   ```powershell
   Install-WindowsFeature FS-FileServer
   ```

2. Enable SMB over QUIC and confirm the setting:

   ```powershell
   Set-SmbServerConfiguration -EnableSMBQUIC $true -Force
   Get-SmbServerConfiguration | Select-Object EnableSMBQUIC
   ```

3. Import the server certificate into the Local Computer personal store and verify the names it contains:

   ```powershell
   Get-ChildItem Cert:\LocalMachine\My |
       Select-Object Subject, Thumbprint, NotBefore, NotAfter, DnsNameList
   ```

4. Create or update certificate mappings. Supply all names clients use, not just the primary FQDN. The script also adds alternate computer names with `NETDOM computername /add` and registers `CIFS/` SPNs with `setspn -S` for those names. In this lab, `fsquic.workinghardinit.work` is deliberately excluded from CIFS SPN registration so that name can demonstrate NTLM fallback:

   ```powershell
   .\Scripts\ConfigureSMBQUICCertMapping.ps1 `
      -CertificateSubject 'CN=file01' `
      -DisplayName 'File01QuicCertMapping' `
      -DnsName 'file01', 'file01.workinghardinit.work', 'file01.datawisetech.corp', 'file01.datawisetech.com', 'fsquic', 'fsquic.datawisetech.corp', 'fsquic.datawisetech.com', 'fsquic.workinghardinit.work' `
      -ComputerFqdn 'file01.datawisetech.corp' `
      -ComputerAccountName 'file01' `
      -ComputerAlias 'fsquic.datawisetech.corp', 'fsquic.datawisetech.com', 'file01.workinghardinit.work', 'kps.datawisetech.com' `
      -ServicePrincipalName 'CIFS/file01.datawisetech.corp', 'CIFS/file01.datawisetech.com', 'CIFS/fsquic.datawisetech.corp', 'CIFS/fsquic.datawisetech.com', 'HTTP/kps.datawisetech.com' `
      -SkippedNtlmFallbackName 'fsquic.workinghardinit.work'
   ```

   5. Configure an alias only when clients use a name other than the file server's primary computer name. `NETDOM computername /add` associates the alternate DNS name with the file server computer account in Active Directory. `setspn -S` then maps the `CIFS/<alias>` Kerberos service identity to that same account. Together, these settings let clients receive a Kerberos ticket for the alias instead of falling back to NTLM. Do not use `-A`; `-S` detects duplicate SPNs before adding one. If you do this manually, omit only the SPN for `fsquic.workinghardinit.work` when you want that FQDN to keep falling back to NTLM for the demo.

   ```powershell
   NETDOM computername file01.datawisetech.corp /add fsquic.datawisetech.corp
   NETDOM computername file01.datawisetech.corp /add fsquic.datawisetech.com
   NETDOM computername file01.datawisetech.corp /add file01.workinghardinit.work
   NETDOM computername file01.datawisetech.corp /add kps.datawisetech.com
   setspn -S CIFS/file01.datawisetech.corp file01
   setspn -S CIFS/file01.datawisetech.com file01
   setspn -S CIFS/fsquic.datawisetech.corp file01
   setspn -S CIFS/fsquic.datawisetech.com file01
   setspn -S HTTP/kps.datawisetech.com file01
   setspn -L file01
   ```

   Do not add aliases or SPNs for the server's existing primary DNS name. DNS records, the certificate SAN, `NETDOM` aliases, and CIFS SPNs must describe the same client-facing name.

5. Allow inbound UDP 443 to the file server. Do not create an internet-facing TCP 445 rule. Verify the endpoint:

   ```powershell
   Get-SmbServerCertificateMapping | Format-Table Name, Thumbprint, Type, RequireClientAuthentication
   ```

## Windows 11 Client Setup

1. Join the client to the domain and ensure it can resolve the file-server FQDN:

   ```powershell
   Resolve-DnsName fsquic.datawisetech.com
   ```

2. Deploy the issuing CA certificates through Group Policy, Intune, or another managed method. The client must trust the file server's TLS certificate.

3. Connect using the FQDN that appears in the server certificate SAN. This is required for TLS name validation and Kerberos SPN matching. Windows SMB clients prefer TCP and use QUIC only when a TCP connection fails. To require QUIC even when TCP 445 is reachable, use `New-SmbMapping -TransportType QUIC` or `NET USE /TRANSPORT:QUIC`:

   ```powershell
   New-SmbMapping -LocalPath 'F:' -RemotePath '\\fsquic.datawisetech.com\Share' -TransportType QUIC
   ```

   ```cmd
   NET USE F: \\fsquic.datawisetech.com\Share /TRANSPORT:QUIC
   ```

   To open a document directly from a UNC path with the locally registered Windows application, use the supplied helper. It supports `.txt`, `.docx`, and `.xlsx` files:

   ```powershell
   .\Scripts\Open-DocumentFromUncPath.ps1 -Path '\\fsquic.datawisetech.com\Share\Runbook.docx'
   ```

   To open multiple UNC documents one at a time, pausing before each next document:

   ```powershell
   .\Scripts\Open-DocumentSequenceFromUncPath.ps1 -Path @(
      '\\fsquic.datawisetech.com\Share\Notes.txt',
      '\\fsquic.datawisetech.com\Share\Runbook.docx',
      '\\fsquic.datawisetech.com\Share\Budget.xlsx'
   )
   ```

4. Verify that the mapping requests QUIC and that the active SMB session is actually using it. `Get-SmbMapping` shows the mapping's requested transport and ports. `Get-SmbMultichannelConnection` shows the active channel counts, including whether the session has a QUIC connection:

   ```powershell
   Get-SmbMapping | Select-Object LocalPath, RemotePath, Status, TransportType, QuicPort, TcpPort
   Get-SmbMultichannelConnection | Select-Object ServerName, QuicConnectionCount, TcpConnectionCount, CurrentChannels, Failed
   ```

   A mapping created with `-TransportType QUIC` or `/TRANSPORT:QUIC` should report `TransportType` `QUIC` and `QuicPort` `443`. An active QUIC session should show `QuicConnectionCount` greater than zero. `TcpConnectionCount` can also be nonzero when multiple channels or fallback behavior are present, so use the QUIC count rather than assuming that the absence of TCP proves QUIC. An automatically created mapping may use TCP while port `445` is reachable; that is expected unless QUIC is explicitly requested.

   Confirm the transport independently with Wireshark on the client. Start a capture on the active network adapter, connect to the share, and filter on `udp.port == 443` or `quic`. SMB over QUIC traffic is encrypted, but the UDP 443 flow and QUIC packets confirm that the connection is using QUIC. A TCP 445 flow indicates SMB over TCP instead. Do not expect to see SMB payloads in clear text inside the QUIC stream.

## Optional: Require Client Certificates

Use this only when TLS client certificate authentication is an explicit requirement. Client access control on Windows Server 2025 requires Windows 11 version 24H2 or later. The file server will require a valid client certificate and, by default, a matching SMB access-control rule. Client certificate access control applies to one SMB certificate mapping at a time. For demonstration purposes, the example below protects only `fsquic.datawisetech.com`; it does not affect the `file01` or `workinghardinit.work` mappings. Run the script separately for each additional name that should require mutual TLS.

Calculate the client certificate SHA-256 thumbprint on the Windows 11 client. This is different from its default SHA-1 thumbprint:

```powershell
$certificate = Get-ChildItem Cert:\LocalMachine\My\<Thumbprint>
$certificate.GetCertHashString('SHA256')
```

Map the client certificate to the SMB server namespace. The supplied client-side script selects the current certificate by subject and updates the mapping after certificate renewal:

```powershell
.\Scripts\ConfigureSMBQUICClientCertificateMapping.ps1 `
   -Namespace 'fsquic.datawisetech.com' `
   -CertificateSubject 'CN=CLIENT01'
```

The script uses the certificate's default SHA-1 `Thumbprint` because `New-SmbClientCertificateMapping` expects that value. The server access-control script uses the same certificate's SHA-256 hash.

Configure the server with the resulting 64-character value:

```powershell
.\Scripts\ConfigClientAccessControl.ps1 `
   -DnsName 'fsquic.datawisetech.com' `
   -ClientCertificateSha256Hash '<ClientCertificateSha256Thumbprint>' `
    -EnableAudit
```

The SHA-256 option permits one exact client certificate. It is the narrowest policy, but needs an updated entry after client certificate renewal. `-ClientCertificateIssuer` permits certificates issued by that CA for the named SMB endpoint and is therefore broader. SHA-256 and issuer allow entries can be combined: the client is permitted if at least one allow entry matches and no deny entry matches anywhere in its certificate chain. Do not use `SkipClientCertificateAccessCheck $true` unless certificate validation without an SMB allow list is intentional.

## Optional: KDC Proxy for Remote Kerberos

KDC Proxy lets a remote Windows client obtain Kerberos tickets through HTTPS. It does not tunnel SMB: SMB still connects directly to the file server on UDP 443.

1. Deploy KDC Proxy on a domain-joined file server or a separate domain-joined server. It needs a server certificate in `Cert:\LocalMachine\My` with Server Authentication EKU and the proxy FQDN in its SAN, for example `kps.datawisetech.com`.

2. Publish TCP 443 for `https://kps.datawisetech.com/KdcProxy`. The proxy must have network access to domain controllers for Kerberos ticket requests and password-change traffic, including Kerberos TCP/UDP 88 and Kerberos password change TCP/UDP 464 where firewalls separate the proxy from domain controllers. Create an inbound Windows Defender Firewall rule on the proxy and allow the same port on the edge firewall. Do not reuse the SMB server certificate unless the same certificate is intentionally deployed to both servers and includes both names.

   ```powershell
   New-NetFirewallRule -DisplayName 'KDC Proxy HTTPS Inbound' -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Domain
   ```

3. Configure the proxy server:

   ```powershell
   .\Scripts\KDCProxySetup.ps1 `
      -KdcProxyFqdn 'kps.datawisetech.com' `
      -CertificateSubject 'CN=kps.datawisetech.com'
   ```

   Microsoft documents `Add-NetIPHttpsCertBinding -IPPort 0.0.0.0:443` for KDC Proxy. The supplied script uses an SNI `hostnameport` binding to target `kps.datawisetech.com`; this design has been validated in the lab. SNI is useful when multiple HTTPS services or proxy FQDNs share the same server IP address and TCP port 443, because HTTP.SYS selects the correct certificate from the hostname provided during the TLS handshake. Validate it in each production topology before standardizing it.

   The script also creates the `https://+:443/KdcProxy` URL reservation for Network Service, configures the `KPSSVC` settings `HttpsClientAuth=0` and `DisallowUnprotectedPasswordAuth=0`, and starts the `kpssvc` service. These settings allow password-authenticated Kerberos requests through the proxy. If the deployment requires certificate-based client authentication instead, review and change the `KPSSVC` policy for that security model rather than copying these defaults.

   Keep the script's `ApplicationId` stable for this HTTP.SYS binding. Generate a new value only when creating a separate KDC Proxy application. The optional `-Port` parameter changes the HTTPS listener, while `-ComputerAlias`, `-ComputerFqdn`, `-CifsServicePrincipalName`, and `-ComputerAccountName` are only for deployments that deliberately add an Active Directory computer alias or CIFS SPNs. They are not needed when the proxy uses its own primary computer name and is separate from the SMB file server.

4. Configure the Windows 11 client through **Computer Configuration > Administrative Templates > System > Kerberos > Specify KDC proxy servers for Kerberos clients**. For a locally managed or test client, the same settings can be applied with the supplied script:

   ```powershell
   .\Scripts\Configure-KdcProxyClient.ps1 `
      -ActiveDirectoryRealm 'datawisetech.corp' `
      -KdcProxyFqdn 'kps.datawisetech.com' `
      -ConfigureKerberosTiming
   ```

   Use Group Policy for enterprise-wide deployment. Add a realm mapping: the value name is the Active Directory DNS domain and the value is the proxy endpoint in the documented KDC Proxy format:

   ```text
   Value name: datawisetech.corp
   Value: <https kps.datawisetech.com:443:kdcproxy />
   ```

   A bare URL is not sufficient because the client needs the AD realm associated with the proxy. The proxy hostname does not need to be in the Active Directory DNS namespace. It must resolve externally, match the HTTPS certificate SAN, and be trusted by the client.

   The policy and client script create the following client-side registry state; use Group Policy rather than local registry edits for enterprise-wide deployment:

   ```text
   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos
      KdcProxyServer_Enabled = 1 (REG_DWORD)

   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\KdcProxy\ProxyServers
      datawisetech.corp = <https kps.datawisetech.com:443:kdcproxy /> (REG_SZ)
   ```

   ### Optional Kerberos Timing Tuning

   The following optional values control KDC retry and rediscovery behavior on the client. `Configure-KdcProxyClient.ps1 -ConfigureKerberosTiming` applies the documented values; omit that switch when timing changes are not wanted:

   ```text
   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters
      KdcBackoffTime
      KdcSendRetries
      KdcWaitTime
      RediscoverKdcTimeout
      NoRevocationCheck
   ```

   These values affect how quickly Windows gives up on or retries a KDC attempt; they do not force KDC Proxy selection. The values shown in the example configuration are already aggressive:

   ```text
   KdcBackoffTime       = 3
   KdcSendRetries       = 2
   KdcWaitTime          = 3
   RediscoverKdcTimeout = 3
   NoRevocationCheck    = 0
   ```

   Do not lower the timing values further until the delay has been measured. Values that are too low can cause false authentication failures on slow or intermittent networks. Change these settings on a test client first, then run `klist purge` and reboot or restart the affected authentication session before retesting. Keep `NoRevocationCheck` at `0` in production so the client validates the KDC Proxy certificate's revocation status. Setting it to `1` disables that check and should be limited to lab troubleshooting when CRL/OCSP reachability is the diagnosed problem; it is not a general performance optimization.

5. Test off-network with no direct access to a domain controller. Obtain and inspect a ticket while capturing the connection to the KDC Proxy endpoint:

   ```powershell
   klist purge
   klist get krbtgt
   Get-SmbMultichannelConnection | Select-Object ServerName, QuicConnectionCount, TcpConnectionCount, CurrentChannels, Failed
   ```

   `Get-SmbMultichannelConnection` confirms active SMB channel information, not whether the Kerberos request used KDC Proxy. Confirm KDC Proxy usage with a network trace showing HTTPS traffic from the client to `kps.datawisetech.com:443` and the `/KdcProxy` path.

MS-KKDCP specifies support for password changes as well as ticket requests. If password change or password reset workflows fail while `klist get krbtgt` succeeds, confirm that the KDC Proxy server can reach a writable domain controller for Kerberos password change on TCP/UDP 464 and that the user is allowed to change the password according to domain policy. Current Windows 11 builds can nevertheless select direct domain-controller connectivity for password changes instead of contacting the proxy. If that occurs, capture a client network trace and do not diagnose the KDC Proxy server until the client actually sends HTTPS traffic to `/KdcProxy`.

## Clustered SMB Shares

SMB over QUIC works with clustered SMB shares because it is still SMB after the TLS 1.3 QUIC connection is established. SMB capabilities such as permissions, signing, compression, multichannel behavior, directory leasing, and continuously available shares continue to follow the normal file-server cluster rules. The cluster-specific requirement is that every node that might own the clustered file server can terminate QUIC for the same client-facing name.

Configure SMB over QUIC for the clustered file server name that clients use in the UNC path, not only for the physical node names. For example, clients should connect to `\\fsquic.datawisetech.com\Share` when `fsquic.datawisetech.com` represents the clustered file server access name or an approved external alias for it.

1. Confirm the clustered file server role and the names clients will use:

   ```powershell
   Get-ClusterGroup
   Get-ClusterResource
   ```

2. Issue a server certificate whose SAN list contains every clustered SMB name used by clients, such as `fsquic`, `fsquic.datawisetech.corp`, and `fsquic.datawisetech.com`. Do not use IP address SANs. Install the certificate, including its private key, in `Cert:\LocalMachine\My` on every possible owner node. Using the same PFX on each node keeps the thumbprint identical and simplifies renewal.

3. Enable SMB over QUIC on every cluster node:

   ```powershell
   $nodes = (Get-ClusterNode).Name

   Invoke-Command -ComputerName $nodes -ScriptBlock {
      Set-SmbServerConfiguration -EnableSMBQUIC $true -Force
      Get-SmbServerConfiguration | Select-Object EnableSMBQUIC
   }
   ```

4. Create or update the SMB server certificate mappings on every possible owner node for the clustered names. The existing mapping script can be run remotely or locally on each node after the certificate is installed:

   ```powershell
   $nodes = (Get-ClusterNode).Name

   Invoke-Command -ComputerName $nodes -FilePath .\Scripts\ConfigureSMBQUICCertMapping.ps1 -ArgumentList @(
      'CN=fsquic',
      'FsQuicClusterCertMapping',
      @('fsquic', 'fsquic.datawisetech.corp', 'fsquic.datawisetech.com')
   )
   ```

   If the nodes use separately issued certificates, ensure each node's certificate contains the same clustered DNS names and rerun the mapping script on each node whenever that node's certificate renews.

5. Align DNS, Kerberos, and routing with the clustered name. Public or private DNS must resolve the client-facing clustered name to the endpoint that reaches the current owner or the load-balanced cluster access path over UDP 443. Add any required `CIFS/` SPNs to the clustered file server computer object, not to the physical node computer accounts:

   ```powershell
   setspn -S CIFS/fsquic.datawisetech.com <ClusteredFileServerComputerObject>
   setspn -S CIFS/fsquic <ClusteredFileServerComputerObject>
   setspn -L <ClusteredFileServerComputerObject>
   ```

   If the name is already the clustered file server's primary client access name, the required SPNs may already exist. Add SPNs only for additional aliases that clients use.

6. Allow inbound UDP 443 to the nodes that can serve the clustered file server. Do not expose TCP 445 to the internet. If a perimeter firewall, NAT device, or load balancer is used, validate that UDP is preserved end to end and that failover sends traffic to a node that already has the certificate and mapping.

7. Test the clustered name from a Windows 11 client and then move the clustered file server role to another node before testing again:

   ```powershell
   New-SmbMapping -LocalPath 'Q:' -RemotePath '\\fsquic.datawisetech.com\Share' -TransportType QUIC
   Get-SmbMapping | Select-Object LocalPath, RemotePath, Status, TransportType, QuicPort
   Get-SmbMultichannelConnection | Select-Object ServerName, QuicConnectionCount, TcpConnectionCount, CurrentChannels, Failed
   Move-ClusterGroup -Name '<ClusteredFileServerRoleName>'
   ```

   A successful failover test proves that QUIC was not configured only on the first owner node. If the share works on one node but fails after failover, check the certificate store, SMB certificate mapping, UDP 443 firewall path, and SPNs on the new owner.

## Operations and Troubleshooting

Run all configuration scripts first with `-WhatIf` where supported, then rerun after certificate renewal. Keep the server certificate subject stable if using the supplied renewal logic. Review mappings, client access rules, SMB connections, and KDC Proxy HTTPS bindings:

```powershell
Get-SmbServerCertificateMapping
Get-SmbClientAccessToServer -Name 'fsquic.datawisetech.com'
Get-SmbConnection
netsh http show sslcert hostnameport=kps.datawisetech.com:443
Get-Service kpssvc
```

For failed client certificate access, enable auditing with `-EnableAudit` and inspect the SMB Server operational logs. For failed remote Kerberos, verify the proxy URL, DNS, certificate chain, TCP 443 reachability, and whether the client is actually attempting `/KdcProxy`.

Use the following logs together when troubleshooting a connection:

- **SMB Server:** On the file server, open **Applications and Services Logs > Microsoft > Windows > SMBServer > Operational**. This is useful for SMB session, transport, and client-certificate access troubleshooting. The `-EnableAudit` option also enables server-side client-certificate access auditing.
- **SMB Client:** On the Windows 11 client, open **Applications and Services Logs > Microsoft > Windows > SMBClient > Connectivity**. On Windows 11 24H2 and later, event `30832` provides SMB over QUIC client connection information.
- **KDC Proxy:** On the proxy server, check **Applications and Services Logs > Microsoft > Windows > Kerberos-KDCProxy** for KDC Proxy request and service events. Also check **Windows Logs > System** and filter the source for `Kpssvc` or `Service Control Manager`; these logs show service startup and service-level failures. Use a network capture to confirm that the client actually sends HTTPS requests to `/KdcProxy`.

To determine whether the SMB session authenticated with Kerberos or NTLM, inspect the server's **Windows Logs > Security** log after enabling successful logon auditing. Event ID `4624` contains the `Authentication Package` field: `Kerberos` indicates Kerberos authentication and `NTLM` indicates NTLM authentication. Filter the event by the client address, account, and logon time. If KDC Proxy is being used, the client's Kerberos ticket request is carried over HTTPS, but the resulting SMB logon still appears as Kerberos on the file server. Kerberos ticket-granting events such as `4768` and `4769` are recorded on the domain controller rather than the file server.

For live monitoring, [Scripts/GrabNetworkLogons.ps1](Scripts/GrabNetworkLogons.ps1) defaults to server `file01`, user `DATAWISETECH\quicdemo`, and SMB Server transport correlation. It filters event `4624` entries by authenticated account with `-UserFilter` and reports the source IP because the client computer name is often unavailable or unreliable in the event. The equivalent explicit command is:

```powershell
.\Scripts\GrabNetworkLogons.ps1 `
   -SmbOverQuicServer 'file01' `
   -UserFilter 'DATAWISETECH\quicdemo' `
   -IncludeServerTransportEvents
```

The monitor displays only events created after monitor startup by default, which avoids old Kerberos, mutual-auth, or NTLM events reappearing during a demo. Add `-ReplayHistory` to replay the selected historical window on every refresh. With `-IncludeServerTransportEvents`, each authentication line includes a nearby SMB Server transport observation as `QUIC`, `TCP`, or `Uncorrelated`; the match uses the event timestamps, the configurable `-CorrelationSeconds` window, and prefers transport events that mention the same source IP. Very fresh Security events are held for `-CorrelationSettleSeconds` before display so the SMB transport and client-certificate events have time to arrive. Add `-ShowLogonDetails` to print the raw `4624` clues, including logon process, LM package, key length, IP port, workstation, and correlation method.

The Security log only contains the relevant logon events when the applicable Advanced Audit Policy is enabled under **Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Logon/Logoff > Audit Logon**. Use the server's SMB logs and the client's Wireshark capture together: the SMB logs identify the authentication package, while Wireshark identifies whether the transport was QUIC.
