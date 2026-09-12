#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
	[Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
	[string]$DnsName,

	# This is the SHA-256 certificate thumbprint used by SMB client access control, not
	# the default SHA-1 value returned by the certificate Thumbprint property.
	# On the client, replace <Thumbprint> and run:
	# $certificate = Get-ChildItem Cert:\LocalMachine\My\<Thumbprint>
	# $certificate.GetCertHashString('SHA256')
	[ValidatePattern('^[A-Fa-f0-9]{64}$')]
	[string[]]$ClientCertificateSha256Hash,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string[]]$ClientCertificateIssuer,

	[Parameter()]
	[string[]]$CifsServicePrincipalName,

	[Parameter()]
	[string]$ComputerAccountName,

	[Parameter()]
	[switch]$EnableAudit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# At least one authorization method is required. A SHA-256 hash permits one exact client
# certificate; an issuer permits certificates from that CA. The methods can be combined:
# a connection is permitted when at least one allow entry matches and no deny entry matches.
if (-not $ClientCertificateSha256Hash -and -not $ClientCertificateIssuer) {
	throw 'Specify ClientCertificateSha256Hash, ClientCertificateIssuer, or both.'
}

# An SMB over QUIC mapping must exist before its client-authentication policy can be
# changed. Create it first with ConfigureSMBQUICCertMapping.ps1. This script updates
# only the mapping named by DnsName; it does not change other SMB over QUIC names. The
# supplied example deliberately configures one name only for demonstration purposes.
$mapping = @(Get-SmbServerCertificateMapping -Name $DnsName)
if ($mapping.Count -ne 1) {
	throw "Expected exactly one SMB server certificate mapping for '$DnsName'; found $($mapping.Count)."
}

# Require a TLS client certificate and enforce the explicit allow entries below.
# Setting SkipClientCertificateAccessCheck to true still validates the client certificate,
# but skips the SMB-specific client certificate access-control checks.
# Run this script separately for every additional DNS name that should require mutual TLS.
if ($PSCmdlet.ShouldProcess($DnsName, 'Require and authorize SMB over QUIC client certificates')) {
	Set-SmbServerCertificateMapping -Name $DnsName -RequireClientAuthentication $true -SkipClientCertificateAccessCheck $false
}

# Register optional CIFS SPNs for SMB aliases on the file server computer account. An
# SPN maps the name used in the UNC path to this account so clients can obtain a
# Kerberos ticket for the alias instead of falling back to NTLM. Add a computer alias
# first with NETDOM when the DNS name is an alternate name for this server. -S checks
# Active Directory for duplicates; do not use -A because it bypasses that validation.
if ($CifsServicePrincipalName) {
	if (-not $ComputerAccountName) {
		throw 'ComputerAccountName is required when CifsServicePrincipalName is specified.'
	}

	foreach ($servicePrincipalName in $CifsServicePrincipalName) {
		if ($PSCmdlet.ShouldProcess($ComputerAccountName, "Register SPN '$servicePrincipalName'")) {
			& setspn.exe -S $servicePrincipalName $ComputerAccountName
			if ($LASTEXITCODE -ne 0) {
				throw "Unable to register SPN '$servicePrincipalName'. Setspn exited with code $LASTEXITCODE."
			}
		}
	}
}

# SHA256 entries permit only the specified client certificate. Issuer entries are broader:
# each permits certificates from that CA. Both can be present; any matching deny entry in
# the certificate chain overrides all allow entries.
$desiredAccessEntries = @(
	foreach ($hash in $ClientCertificateSha256Hash) {
		[pscustomobject]@{ IdentifierType = 'SHA256'; Identifier = $hash }
	}
	foreach ($issuer in $ClientCertificateIssuer) {
		[pscustomobject]@{ IdentifierType = 'ISSUER'; Identifier = $issuer }
	}
)

$existingAccessEntries = @(Get-SmbClientAccessToServer -Name $DnsName)
foreach ($entry in $desiredAccessEntries) {
	$exists = $existingAccessEntries | Where-Object {
		$_.IdentifierType -eq $entry.IdentifierType -and $_.Identifier -eq $entry.Identifier
	}

	if ($exists) {
		Write-Verbose "Client certificate access entry '$($entry.Identifier)' already exists for '$DnsName'."
		continue
	}

	if ($PSCmdlet.ShouldProcess($DnsName, "Grant $($entry.IdentifierType) certificate access for '$($entry.Identifier)'")) {
		Grant-SmbClientAccessToServer -Name $DnsName -IdentifierType $entry.IdentifierType -Identifier $entry.Identifier -Force
	}
}

# Auditing records allowed and denied certificate access attempts in the SMB Server logs.
if ($EnableAudit -and $PSCmdlet.ShouldProcess('SMB Server', 'Enable client certificate access auditing')) {
	Set-SmbServerConfiguration -AuditClientCertificateAccess $true -Force
}

# Display the effective mapping and allow entries so the resulting policy is visible.
Get-SmbServerCertificateMapping -Name $DnsName
Get-SmbClientAccessToServer -Name $DnsName

<#
Example:
# Replace the sample value with the client certificate's SHA-256 certificate thumbprint.
.\ConfigClientAccessControl.ps1 `
	-DnsName 'fsquic.datawisetech.com' `
	-ClientCertificateSha256Hash '5ABB94D9D279DCA88C0BAE8805C9C5FB7B2F786F3FC415A1F9FC208E3808FAD7' `
	-CifsServicePrincipalName 'CIFS/fsquic.datawisetech.com' `
	-ComputerAccountName 'file01' `
	-EnableAudit

To authorize all client certificates from an issuing CA, use
-ClientCertificateIssuer 'CN=EntRootCA-DWT,DC=datawisetech,DC=corp'. It can be used
instead of, or together with, ClientCertificateSha256Hash:

.\ConfigClientAccessControl.ps1 `
	-DnsName 'fsquic.datawisetech.com' `
	-ClientCertificateIssuer 'CN=EntRootCA-DWT,DC=datawisetech,DC=corp' `
	-EnableAudit
#>