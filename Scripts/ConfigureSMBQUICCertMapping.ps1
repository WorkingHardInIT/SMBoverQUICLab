#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$CertificateSubject = 'CN=file01',

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$DisplayName = 'File01QuicCertMapping',

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string[]]$DnsName = @(
		'file01',
		'file01.workinghardinit.work',
		'file01.datawisetech.corp',
		'file01.datawisetech.com',
		'fsquic',
		'fsquic.datawisetech.corp',
		'fsquic.datawisetech.com',
		'fsquic.workinghardinit.work',
		'kps.datawisetech.com'
	),

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$ComputerFqdn = $env:COMPUTERNAME,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$ComputerAccountName = $env:COMPUTERNAME,

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string[]]$ComputerAlias = @(
		'fsquic.datawisetech.corp',
		'fsquic.datawisetech.com',
		'file01.workinghardinit.work',
		'kps.datawisetech.com'
	),

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string[]]$ServicePrincipalName = @(
		'CIFS/file01.datawisetech.corp',
		'CIFS/file01.datawisetech.com',
		'CIFS/fsquic.datawisetech.corp',
		'CIFS/fsquic.datawisetech.com',
		'HTTP/kps.datawisetech.com'
	),

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string[]]$SkippedNtlmFallbackName = @('fsquic.workinghardinit.work'),

	[Parameter()]
	[switch]$SkipAliasAndSpnConfiguration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-SmbQuicServerCertificate {
	param(
		[Parameter(Mandatory)]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
	)

	# SMB over QUIC requires a usable private key, Server Authentication EKU, and the
	# Digital Signature key usage. Checking these avoids selecting an unsuitable renewal.
	$ekuExtension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
	$keyUsageExtension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
	$hasServerAuthentication = '1.3.6.1.5.5.7.3.1' -in @($ekuExtension | ForEach-Object { $_.EnhancedKeyUsages.Value })
	$hasDigitalSignature = @($keyUsageExtension | Where-Object {
		($_.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -ne 0
	}).Count -gt 0

	return $Certificate.HasPrivateKey -and $hasServerAuthentication -and $hasDigitalSignature
}

function Get-ComputerNameCandidates {
	param(
		[Parameter(Mandatory)]
		[string]$ComputerFqdn
	)

	$candidates = @(
		$env:COMPUTERNAME
		$ComputerFqdn
		if ($ComputerFqdn -match '^([^\.]+)\.') {
			$Matches[1]
		}
	)

	try {
		$candidates += [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
	} catch {
		# DNS lookup failure should not block alias/SPN work for explicitly supplied names.
	}

	return @($candidates | Where-Object { $_ } | Select-Object -Unique)
}

function Test-ComputerNameExists {
	param(
		[Parameter(Mandatory)]
		[string]$ComputerFqdn,

		[Parameter(Mandatory)]
		[string]$Name
	)

	$output = & netdom.exe computername $ComputerFqdn /enumerate 2>$null
	if ($LASTEXITCODE -ne 0 -or -not $output) {
		return $false
	}

	$escapedName = [regex]::Escape($Name)
	return [bool]($output -match "(?im)^\s*$escapedName\s*$")
}

function Get-RegisteredServicePrincipalNames {
	param(
		[Parameter(Mandatory)]
		[string]$ComputerAccountName
	)

	$output = & setspn.exe -L $ComputerAccountName 2>$null
	if ($LASTEXITCODE -ne 0) {
		throw "Unable to list SPNs for '$ComputerAccountName'. Setspn exited with code $LASTEXITCODE."
	}

	return @($output | Where-Object { $_ -match '^\s*\S+/\S+' } | ForEach-Object { $_.Trim() })
}

# Certificate renewal normally leaves the previous certificate in the store. Select the
# newest certificate that is currently valid, so the existing mapping is updated to it.
$certificate = @(
	Get-ChildItem -Path Cert:\LocalMachine\My |
		Where-Object {
			$_.Subject -eq $CertificateSubject -and
			$_.NotBefore -le (Get-Date) -and
			$_.NotAfter -gt (Get-Date) -and
			(Test-SmbQuicServerCertificate -Certificate $_)
		} |
		Sort-Object NotBefore -Descending |
		Select-Object -First 1
)

if (-not $certificate) {
	throw "No currently valid certificate with subject '$CertificateSubject' was found in Cert:\LocalMachine\My."
}

$certificate = $certificate[0]
# SMB requires a separate QUIC certificate mapping for every DNS name clients use.
# Refuse to create a mapping that is not present in the certificate's SAN extension.
$certificateDnsNames = @($certificate.DnsNameList | ForEach-Object Unicode)
$missingDnsNames = @($DnsName | Where-Object { $_ -notin $certificateDnsNames })
if ($missingDnsNames) {
	throw "The selected certificate does not contain these requested SAN names: $($missingDnsNames -join ', ')."
}

if (-not $SkipAliasAndSpnConfiguration) {
	$computerNameCandidates = @(Get-ComputerNameCandidates -ComputerFqdn $ComputerFqdn)
	$registeredServicePrincipalNames = @(Get-RegisteredServicePrincipalNames -ComputerAccountName $ComputerAccountName)

	foreach ($name in $ComputerAlias) {
		$isComputerName = @($computerNameCandidates | Where-Object { $_ -ieq $name }).Count -gt 0
		if (-not $isComputerName) {
			$aliasExists = Test-ComputerNameExists -ComputerFqdn $ComputerFqdn -Name $name
			if ($aliasExists) {
				Write-Verbose "Computer alias '$name' already exists on '$ComputerFqdn'."
			} elseif ($PSCmdlet.ShouldProcess($ComputerFqdn, "Add computer alias '$name'")) {
				& netdom.exe computername $ComputerFqdn /add $name
				if ($LASTEXITCODE -ne 0) {
					throw "Unable to add computer alias '$name'. Netdom exited with code $LASTEXITCODE."
				}
			}
		}
	}

	foreach ($name in $SkippedNtlmFallbackName) {
		Write-Host "Skipping SPN for '$name' so this name can demonstrate NTLM fallback." -ForegroundColor Yellow
	}

	foreach ($servicePrincipalName in $ServicePrincipalName) {
		if (@($registeredServicePrincipalNames | Where-Object { $_ -ieq $servicePrincipalName }).Count -gt 0) {
			Write-Verbose "SPN '$servicePrincipalName' already exists on '$ComputerAccountName'."
			continue
		}

		if ($PSCmdlet.ShouldProcess($ComputerAccountName, "Register SPN '$servicePrincipalName'")) {
			& setspn.exe -S $servicePrincipalName $ComputerAccountName
			if ($LASTEXITCODE -ne 0) {
				throw "Unable to register SPN '$servicePrincipalName'. Setspn exited with code $LASTEXITCODE."
			}

			$registeredServicePrincipalNames += $servicePrincipalName
		}
	}
}

$existingMappings = @(Get-SmbServerCertificateMapping)
foreach ($name in $DnsName) {
	$mappingsForName = @($existingMappings | Where-Object Name -eq $name)
	$matchingMapping = $mappingsForName | Where-Object Thumbprint -eq $certificate.Thumbprint

	# Keep mappings already associated with the selected certificate so reruns are safe.
	if ($matchingMapping) {
		Write-Verbose "SMB over QUIC mapping for '$name' already uses certificate $($certificate.Thumbprint)."
		continue
	}

	if ($mappingsForName) {
		# Update the existing mapping in place during certificate renewal. This avoids a
		# period without a listener mapping if a replacement certificate cannot be applied.
		Write-Verbose "Updating SMB over QUIC mapping for '$name' to certificate $($certificate.Thumbprint)."
		Set-SmbServerCertificateMapping -Name $name -Thumbprint $certificate.Thumbprint -StoreName My
	} else {
		# Create the QUIC listener mapping for this DNS name using the validated certificate.
		Write-Verbose "Creating SMB over QUIC mapping for '$name' with certificate $($certificate.Thumbprint)."
		New-SmbServerCertificateMapping -Name $name -Thumbprint $certificate.Thumbprint -StoreName My -Subject $CertificateSubject -DisplayName $DisplayName -Type QUIC -Flags None
	}
}

Get-SmbServerCertificateMapping | Format-Table Name, Thumbprint, DisplayName, Type -AutoSize

<#
Example:
.\ConfigureSMBQUICCertMapping.ps1 `
	-CertificateSubject 'CN=file01' `
	-DisplayName 'File01QuicCertMapping' `
	-DnsName 'file01', 'file01.datawisetech.corp', 'file01.datawisetech.com', 'fsquic', 'fsquic.datawisetech.corp', 'fsquic.datawisetech.com'
#>