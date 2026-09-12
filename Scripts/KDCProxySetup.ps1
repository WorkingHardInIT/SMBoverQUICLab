#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
<#
Generate a GUID for a new, separate KDC Proxy application with:
$Guid= [Guid]::NewGuid().ToString('B')
The 'B' format adds braces, producing {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx},
which is the form expected by netsh's appid argument. Keep the selected GUID
stable for this KDC Proxy endpoint; do not generate a new one on every run.
#>
param(
	[Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
	[string]$KdcProxyFqdn,

	[Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
	[string]$CertificateSubject,

	[Parameter()]
	[ValidateRange(1, 65535)]
	[int]$Port = 443,

	[Parameter()]
	[Guid]$ApplicationId = 'f47ac10b-58cc-4372-a567-0e02b2c3d479',

	[Parameter()]
	[string[]]$ComputerAlias,

	[Parameter()]
	[string]$ComputerFqdn,

	[Parameter()]
	[string[]]$CifsServicePrincipalName,

	[Parameter()]
	[string]$ComputerAccountName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-KdcProxyCertificate {
	param(
		[Parameter(Mandatory)]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
	)

	# KDC Proxy presents a server-authentication certificate through HTTP.SYS. Reject
	# certificates without a private key, Server Authentication EKU, or Digital Signature.
	$ekuExtension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
	$keyUsageExtension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
	$hasServerAuthentication = '1.3.6.1.5.5.7.3.1' -in @($ekuExtension | ForEach-Object { $_.EnhancedKeyUsages.Value })
	$hasDigitalSignature = @($keyUsageExtension | Where-Object {
		($_.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -ne 0
	}).Count -gt 0

	return $Certificate.HasPrivateKey -and $hasServerAuthentication -and $hasDigitalSignature
}

# Certificate renewal usually retains the previous certificate. Use the newest valid
# matching certificate, which may be different from the SMB over QUIC certificate.
$certificate = Get-ChildItem -Path Cert:\LocalMachine\My |
	Where-Object {
		$_.Subject -eq $CertificateSubject -and
		$_.NotBefore -le (Get-Date) -and
		$_.NotAfter -gt (Get-Date) -and
		(Test-KdcProxyCertificate -Certificate $_)
	} |
	Sort-Object NotBefore -Descending |
	Select-Object -First 1

if (-not $certificate) {
	throw "No currently valid certificate with subject '$CertificateSubject' was found in Cert:\LocalMachine\My."
}

# HTTP.SYS presents this certificate for the KDC Proxy endpoint, so its SAN must include
# the hostname that clients use to reach the service.
$certificateDnsNames = @($certificate.DnsNameList | ForEach-Object Unicode)
if ($KdcProxyFqdn -notin $certificateDnsNames) {
	throw "The selected certificate does not contain '$KdcProxyFqdn' in its SAN extension."
}

$hostnamePort = "${KdcProxyFqdn}:$Port"

# Give Network Service permission to host the KDC Proxy URL. The command is harmless if
# the reservation already exists; a conflicting reservation is surfaced as an error.
if ($PSCmdlet.ShouldProcess("https://+:$Port/KdcProxy", 'Create HTTP URL reservation')) {
	& netsh.exe http add urlacl "url=https://+:$Port/KdcProxy" 'user=NT AUTHORITY\NETWORK SERVICE' 2>$null | Out-Null
	if ($LASTEXITCODE -notin 0, 183) {
		throw "Unable to create the KDC Proxy URL reservation. Netsh exited with code $LASTEXITCODE."
	}
}

# The edge firewall and HTTP.SYS binding are not enough by themselves. Permit the
# KDC Proxy service to receive HTTPS traffic on the local server, without duplicating
# an existing rule on reruns.
if ($PSCmdlet.ShouldProcess("TCP $Port", 'Allow inbound KDC Proxy HTTPS in Windows Firewall')) {
	$firewallRule = Get-NetFirewallRule -DisplayName 'KDC Proxy HTTPS Inbound' -ErrorAction SilentlyContinue
	if (-not $firewallRule) {
		New-NetFirewallRule -DisplayName 'KDC Proxy HTTPS Inbound' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Domain | Out-Null
	}
}

# Enable password authentication when certificate-based smart card or Windows Hello
# authentication is not required for KDC Proxy clients.
if ($PSCmdlet.ShouldProcess('KDC Proxy registry settings', 'Enable password authentication')) {
	# Registry.exe equivalents:
	# REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" /v HttpsClientAuth /t REG_DWORD /d 0 /f
	# REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings" /v DisallowUnprotectedPasswordAuth /t REG_DWORD /d 0 /f
	Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings -Name HttpsClientAuth -Type DWord -Value 0 -Force
	Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings -Name DisallowUnprotectedPasswordAuth -Type DWord -Value 0 -Force
}

# HTTP.SYS permits one certificate per hostname:port. Delete an existing binding before
# adding the selected certificate, which updates the listener after certificate renewal.
# A PowerShell alternative is Add-NetIPHttpsCertBinding with an IP:port binding, but
# netsh is preferred here because KDC Proxy uses an SNI hostname:port binding.
if ($PSCmdlet.ShouldProcess($hostnamePort, "Bind certificate $($certificate.Thumbprint) to KDC Proxy")) {
	& netsh.exe http delete sslcert "hostnameport=$hostnamePort" 2>$null | Out-Null
	if ($LASTEXITCODE -notin 0, 2, 1168) {
		throw "Unable to remove the existing HTTPS binding for '$hostnamePort'. Netsh exited with code $LASTEXITCODE."
	}

	& netsh.exe http add sslcert "hostnameport=$hostnamePort" "certhash=$($certificate.Thumbprint)" "appid={$ApplicationId}" certstorename=MY | Out-Null
	if ($LASTEXITCODE -ne 0) {
		throw "Unable to bind certificate $($certificate.Thumbprint) to '$hostnamePort'. Netsh exited with code $LASTEXITCODE."
	}

	# Example PowerShell alternative for a non-SNI IP:port listener:
	# Add-NetIPHttpsCertBinding -IpPort "0.0.0.0:$Port" -CertificateHash $certificate.Thumbprint -CertificateStoreName MY -ApplicationId $ApplicationId
}

# Computer aliases and SPNs are domain-specific. Configure them only when explicitly
# requested, so this script can also be used on standalone KDC Proxy servers. Netdom
# adds an alternate DNS name to the computer account, allowing Active Directory to
# recognize the alias as belonging to that computer. This is needed only for aliases,
# not the computer's own primary name.
if ($ComputerAlias) {
	if (-not $ComputerFqdn) {
		throw 'ComputerFqdn is required when ComputerAlias is specified.'
	}

	foreach ($alias in $ComputerAlias) {
		if ($PSCmdlet.ShouldProcess($ComputerFqdn, "Add computer alias '$alias'")) {
			& netdom.exe computername $ComputerFqdn /add $alias
			if ($LASTEXITCODE -ne 0) {
				throw "Unable to add computer alias '$alias'. Netdom exited with code $LASTEXITCODE."
			}
		}
	}
}

# A CIFS SPN maps an SMB name to the computer account that owns the SMB service. This
# lets clients obtain Kerberos tickets for an alias instead of falling back to NTLM.
# -S checks Active Directory for duplicates; never use -A, which bypasses that check.
if ($CifsServicePrincipalName) {
	if (-not $ComputerAccountName) {
		throw 'ComputerAccountName is required when CifsServicePrincipalName is specified.'
	}

	foreach ($servicePrincipalName in $CifsServicePrincipalName) {
		if ($PSCmdlet.ShouldProcess($ComputerAccountName, "Add SPN '$servicePrincipalName'")) {
			& setspn.exe -S $servicePrincipalName $ComputerAccountName
			if ($LASTEXITCODE -ne 0) {
				throw "Unable to add SPN '$servicePrincipalName'. Setspn exited with code $LASTEXITCODE."
			}
		}
	}
}

if ($PSCmdlet.ShouldProcess('kpssvc', 'Configure and start KDC Proxy service')) {
	Set-Service -Name kpssvc -StartupType Automatic
	Start-Service -Name kpssvc
}

Get-Service -Name kpssvc | Select-Object Name, Status, StartType
& netsh.exe http show sslcert "hostnameport=$hostnamePort"

<#
Example:
.\KDCProxySetup.ps1 `
	-KdcProxyFqdn 'kps.datawisetech.com' `
	-CertificateSubject 'CN=kps.datawisetech.com' `
	-ComputerAlias 'kps.datawisetech.com' `
	-ComputerFqdn 'file01.datawisetech.corp' `
	-CifsServicePrincipalName 'CIFS/fsquic', 'CIFS/fsquic.datawisetech.com' `
	-ComputerAccountName 'file01'
#>