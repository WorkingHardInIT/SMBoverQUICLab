[CmdletBinding(SupportsShouldProcess)]
param(
	[Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
	[Alias('FullName')]
	[ValidateNotNullOrEmpty()]
	[string[]]$Path,

	[Parameter()]
	[switch]$PassThru
)

begin {
	Set-StrictMode -Version Latest
	$ErrorActionPreference = 'Stop'
	$supportedExtensions = @('.txt', '.docx', '.xlsx')

	function Test-UncDocumentPath {
		param(
			[Parameter(Mandatory)]
			[string]$UncPath
		)

		$match = [regex]::Match($UncPath, '^\\\\[^\\]+\\[^\\]+\\.+')
		if (-not $match.Success) {
			throw "Path '$UncPath' is not a UNC document path. Use the format \\server\share\document.ext."
		}
	}

	function Get-UncDocumentPathInfo {
		param(
			[Parameter(Mandatory)]
			[string]$UncPath
		)

		$match = [regex]::Match($UncPath, '^\\\\(?<server>[^\\]+)\\(?<share>[^\\]+)\\.+')
		if (-not $match.Success) {
			throw "Path '$UncPath' is not a UNC document path. Use the format \\server\share\document.ext."
		}

		[pscustomobject]@{
			ServerName = $match.Groups['server'].Value
			ShareName  = $match.Groups['share'].Value
		}
	}

	function Test-CifsKerberosTicket {
		param(
			[Parameter(Mandatory)]
			[string]$ServerName
		)

		$klist = Get-Command -Name klist.exe -ErrorAction SilentlyContinue
		if (-not $klist) {
			return $false
		}

		$tickets = & $klist.Source tickets 2>$null
		if ($LASTEXITCODE -ne 0 -or -not $tickets) {
			return $false
		}

		$escapedServerName = [regex]::Escape($ServerName)
		return [bool]($tickets -match "(?i)cifs/$escapedServerName(?:\s|@|$)")
	}

	function Get-SmbDocumentAuthenticationStatus {
		param(
			[Parameter(Mandatory)]
			[string]$ServerName,

			[Parameter(Mandatory)]
			[string]$ShareName
		)

		$hasClientCertificateMapping = $false
		try {
			$hasClientCertificateMapping = [bool]@(Get-SmbClientCertificateMapping -Namespace $ServerName -ErrorAction SilentlyContinue)
		} catch {
			$hasClientCertificateMapping = $false
		}

		if (Test-CifsKerberosTicket -ServerName $ServerName) {
			if ($hasClientCertificateMapping) {
				return [pscustomobject]@{ Label = 'Kerberos with Mutual Auth'; Color = 'Cyan' }
			}

			return [pscustomobject]@{ Label = 'Kerberos'; Color = 'Green' }
		}

		return [pscustomobject]@{ Label = 'NTLM'; Color = 'Yellow' }
	}
}

process {
	foreach ($uncPath in $Path) {
		Test-UncDocumentPath -UncPath $uncPath
		$pathInfo = Get-UncDocumentPathInfo -UncPath $uncPath

		$item = Get-Item -LiteralPath $uncPath -ErrorAction Stop
		if ($item.PSIsContainer) {
			throw "Path '$uncPath' is a folder. Specify a document file path."
		}

		if ($item.Extension -notin $supportedExtensions) {
			throw "Path '$uncPath' has extension '$($item.Extension)'. Supported extensions are: $($supportedExtensions -join ', ')."
		}

		$authenticationStatus = [pscustomobject]@{ Label = 'Not opened'; Color = 'DarkGray' }
		$documentProcess = $null

		if ($PSCmdlet.ShouldProcess($item.FullName, 'Open document with the registered Windows application')) {
			Write-Host "Opening: $($item.FullName)" -ForegroundColor Magenta
			$documentProcess = Start-Process -FilePath $item.FullName -PassThru
			$authenticationStatus = Get-SmbDocumentAuthenticationStatus -ServerName $pathInfo.ServerName -ShareName $pathInfo.ShareName
			Write-Host "Authentication: $($authenticationStatus.Label)" -ForegroundColor $authenticationStatus.Color
		}

		if ($PassThru) {
			[pscustomobject]@{
				Path           = $item.FullName
				Extension      = $item.Extension
				Authentication = $authenticationStatus.Label
				ProcessId      = if ($documentProcess) { $documentProcess.Id } else { $null }
				ProcessName    = if ($documentProcess) { $documentProcess.ProcessName } else { $null }
			}
		}
	}
}

<#
Example:
.\Open-DocumentFromUncPath.ps1 -Path '\\fsquic.datawisetech.com\Share\Runbook.docx'

Pipeline input is supported:
'\\fsquic.datawisetech.com\Share\Runbook.docx', '\\fsquic.datawisetech.com\Share\Design.xlsx' |
	.\Open-DocumentFromUncPath.ps1
#>