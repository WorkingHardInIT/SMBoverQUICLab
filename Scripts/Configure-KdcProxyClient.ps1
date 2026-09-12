#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
	[Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
	[string]$ActiveDirectoryRealm,

	[Parameter(Mandatory)]
	[ValidateNotNullOrEmpty()]
	[string]$KdcProxyFqdn,

	[Parameter()]
	[ValidateRange(1, 65535)]
	[int]$Port = 443,

	[Parameter()]
	[switch]$ConfigureKerberosTiming,

	[Parameter()]
	[ValidateRange(0, 2147483647)]
	[int]$KdcBackoffTime = 1,

	[Parameter()]
	[ValidateRange(0, 2147483647)]
	[int]$KdcSendRetries = 1,

	[Parameter()]
	[ValidateRange(0, 2147483647)]
	[int]$KdcWaitTime = 1,

	[Parameter()]
	[ValidateRange(0, 2147483647)]
	[int]$RediscoverKdcTimeout = 1,

	[Parameter()]
	[ValidateSet(0, 1)]
	[int]$NoRevocationCheck = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$policyKerberosPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos'
$proxyServersPath = "$policyKerberosPath\KdcProxy\ProxyServers"
$kerberosParametersPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
$proxyValue = "<https $KdcProxyFqdn`:$Port`:kdcproxy />"

if ($PSCmdlet.ShouldProcess($policyKerberosPath, 'Enable KDC Proxy for Kerberos clients')) {
	New-Item -Path $proxyServersPath -Force | Out-Null
	New-ItemProperty -Path $policyKerberosPath -Name KdcProxyServer_Enabled -PropertyType DWord -Value 1 -Force | Out-Null
	New-ItemProperty -Path $proxyServersPath -Name $ActiveDirectoryRealm -PropertyType String -Value $proxyValue -Force | Out-Null
}

if ($ConfigureKerberosTiming -and $PSCmdlet.ShouldProcess($kerberosParametersPath, 'Configure Kerberos KDC retry and rediscovery timing')) {
	New-Item -Path $kerberosParametersPath -Force | Out-Null
	$timingValues = @{
		KdcBackoffTime       = $KdcBackoffTime
		KdcSendRetries       = $KdcSendRetries
		KdcWaitTime          = $KdcWaitTime
		RediscoverKdcTimeout = $RediscoverKdcTimeout
		NoRevocationCheck    = $NoRevocationCheck
	}

	foreach ($entry in $timingValues.GetEnumerator()) {
		New-ItemProperty -Path $kerberosParametersPath -Name $entry.Key -PropertyType DWord -Value $entry.Value -Force | Out-Null
	}
}

Get-ItemProperty -Path $policyKerberosPath -Name KdcProxyServer_Enabled
Get-ItemProperty -Path $proxyServersPath -Name $ActiveDirectoryRealm

if ($ConfigureKerberosTiming) {
	Get-ItemProperty -Path $kerberosParametersPath -Name @($timingValues.Keys)
}

<#
Example:
.\Configure-KdcProxyClient.ps1 `
	-ActiveDirectoryRealm 'datawisetech.corp' `
	-KdcProxyFqdn 'kps.datawisetech.com' `
	-ConfigureKerberosTiming

Use Group Policy for enterprise-wide deployment. The script is intended for local
testing or clients that are managed outside the domain policy deployment path.
#>