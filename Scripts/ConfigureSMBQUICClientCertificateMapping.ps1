#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
	[Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
	[string]$Namespace,

	[Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
	[string]$CertificateSubject,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$StoreName = 'My'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$clientAuthenticationOid = '1.3.6.1.5.5.7.3.2'

function Test-CertificateEnhancedKeyUsage {
	param(
		[Parameter(Mandatory)]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

		[Parameter(Mandatory)]
		[string]$Oid
	)

	$ekuExtension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
	return $Oid -in @($ekuExtension | ForEach-Object { $_.EnhancedKeyUsages.Value })
}

$certificate = Get-ChildItem "Cert:\LocalMachine\$StoreName" |
	Where-Object {
		$_.HasPrivateKey -and
		$_.NotBefore -le (Get-Date) -and
		$_.NotAfter -gt (Get-Date) -and
		$_.Subject -eq $CertificateSubject -and
		(Test-CertificateEnhancedKeyUsage -Certificate $_ -Oid $clientAuthenticationOid)
	} |
	Sort-Object NotBefore -Descending |
	Select-Object -First 1

if (-not $certificate) {
	throw "No currently valid client-authentication certificate with subject '$CertificateSubject' was found in Cert:\LocalMachine\$StoreName."
}

$existingMappings = @(Get-SmbClientCertificateMapping -Namespace $Namespace -ErrorAction SilentlyContinue)
$matchingMapping = $existingMappings | Where-Object Thumbprint -eq $certificate.Thumbprint

if ($matchingMapping) {
	Write-Verbose "SMB client certificate mapping for '$Namespace' already uses certificate $($certificate.Thumbprint)."
} elseif ($PSCmdlet.ShouldProcess($Namespace, "Map client certificate $($certificate.Thumbprint)")) {
	if ($existingMappings) {
		Remove-SmbClientCertificateMapping -Namespace $Namespace -Force
	}

	New-SmbClientCertificateMapping -Namespace $Namespace -Thumbprint $certificate.Thumbprint -StoreName $StoreName -Type QUIC -Force
}

Get-SmbClientCertificateMapping -Namespace $Namespace

<#
Example:
.\ConfigureSMBQUICClientCertificateMapping.ps1 `
	-Namespace 'fsquic.datawisetech.com' `
	-CertificateSubject 'CN=CLIENT01'

Run Request-SmbQuicClientCertificate.ps1 first when the certificate is not already
installed. Re-run this script after certificate renewal to update the mapping.
#>