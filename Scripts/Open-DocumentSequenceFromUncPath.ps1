[CmdletBinding(SupportsShouldProcess)]
param(
	[Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
	[Alias('FullName')]
	[ValidateNotNullOrEmpty()]
	[string[]]$Path,

	[Parameter()]
	[string]$Prompt = 'Review the open document, then press Enter to continue, or type Q to stop',

	[Parameter()]
	[string]$ExitPrompt = 'Press Enter or type X to exit',

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$SmbFileServer = 'file01',

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]$ServerSharePath = 'C:\FileShares\Finance',

	[Parameter()]
	[ValidateRange(1, 3)]
	[int]$Step,

	[Parameter()]
	[switch]$EnableServerOpenFileCleanup
)

begin {
	Set-StrictMode -Version Latest
	$ErrorActionPreference = 'Stop'
	$host.UI.RawUI.WindowTitle = 'Open SMB over QUIC in multiple scenarios'
	$supportedExtensions = @('.txt', '.docx', '.xlsx')

	function Set-ConsoleWindowTopMost {
		param(
			[Parameter()]
			[ValidateRange(0, 10000)]
			[int]$DurationMilliseconds = 0,

			[Parameter()]
			[switch]$Quiet
		)

		$signature = @'
[DllImport("kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool SetWindowPos(
    IntPtr hWnd,
    IntPtr hWndInsertAfter,
    int X,
    int Y,
    int cx,
    int cy,
    uint uFlags);

[DllImport("user32.dll")]
public static extern bool SetForegroundWindow(IntPtr hWnd);
'@

		$type = 'SetWindowPos.SetWindowPosition' -as [type]
		if (-not $type) {
			$type = Add-Type -MemberDefinition $signature -Name SetWindowPosition -Namespace SetWindowPos -Using System.Text -PassThru
		}

		$handle = $type::GetConsoleWindow()
		$processId = $PID
		while ($handle -eq [IntPtr]::Zero -and $processId) {
			$process = Get-Process -Id $processId -ErrorAction SilentlyContinue
			if ($process -and $process.MainWindowHandle -ne 0) {
				$handle = $process.MainWindowHandle
				break
			}

			$processInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
			$processId = if ($processInfo) { $processInfo.ParentProcessId } else { $null }
		}

		if ($handle -eq [IntPtr]::Zero) {
			$terminalProcess = Get-Process -Name WindowsTerminal, WindowsTerminalPreview -ErrorAction SilentlyContinue |
				Where-Object MainWindowHandle -ne 0 |
				Select-Object -First 1
			if ($terminalProcess) {
				$handle = $terminalProcess.MainWindowHandle
			}
		}

		$topMost = New-Object -TypeName System.IntPtr -ArgumentList (-1)
		if ($handle -ne [IntPtr]::Zero) {
			$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
			do {
				$pinned = $type::SetWindowPos($handle, $topMost, 0, 0, 0, 0, 0x0043)
				[void]$type::SetForegroundWindow($handle)
				if ($DurationMilliseconds -gt 0) {
					[System.Threading.Thread]::Sleep(150)
				}
			} until ($DurationMilliseconds -eq 0 -or $stopwatch.ElapsedMilliseconds -ge $DurationMilliseconds)

			if ($pinned -and -not $Quiet) {
				Write-Host "PowerShell console pinned on top (handle $handle)." -ForegroundColor DarkGray
			} elseif (-not $pinned) {
				Write-Warning "SetWindowPos failed for window handle $handle."
			}
		} else {
			Write-Warning 'Could not find a console window to pin on top.'
		}
	}

	function Close-OfficeDocumentByPath {
		param(
			[Parameter(Mandatory)]
			[string]$Path,

			[Parameter(Mandatory)]
			[string]$Extension
		)

		$closed = $false
		$fileName = Split-Path -Path $Path -Leaf
		switch ($Extension.ToLowerInvariant()) {
			'.docx' {
				try {
					$word = [Runtime.InteropServices.Marshal]::GetActiveObject('Word.Application')
					foreach ($document in @($word.Documents)) {
						if ($document.FullName -ieq $Path -or $document.Name -ieq $fileName) {
							[void]$document.Close(0)
							$closed = $true
						}
					}
				} catch {
					$closed = $false
				}
			}
			'.xlsx' {
				try {
					$excel = [Runtime.InteropServices.Marshal]::GetActiveObject('Excel.Application')
					foreach ($workbook in @($excel.Workbooks)) {
						if ($workbook.FullName -ieq $Path -or $workbook.Name -ieq $fileName) {
							[void]$workbook.Close($false)
							$closed = $true
						}
					}
				} catch {
					$closed = $false
				}
			}
		}

		return $closed
	}

	function Close-SmbServerOpenFiles {
		param(
			[Parameter(Mandatory)]
			[string]$DocumentPath,

			[Parameter(Mandatory)]
			[string]$DocumentDirectoryPath,

			[Parameter(Mandatory)]
			[string]$ClientComputerName
		)

		if (-not $EnableServerOpenFileCleanup) {
			return
		}

		$cleanupScript = {
			param(
				[string]$TargetDocumentPath,
				[string]$TargetDocumentDirectoryPath,
				[string]$TargetClientComputerName
			)

			$documentLeaf = Split-Path -Path $TargetDocumentPath -Leaf
			$officeTempLeaf = if ($documentLeaf.Length -gt 2) { '~$' + $documentLeaf.Substring(2) } else { $null }
			$targetPaths = @(
				$TargetDocumentPath
				$TargetDocumentDirectoryPath
				if ($officeTempLeaf) {
					Join-Path -Path $TargetDocumentDirectoryPath -ChildPath $officeTempLeaf
				}
			) | Where-Object { $_ } | Select-Object -Unique

			$openFiles = Get-SmbOpenFile | Where-Object {
				$openFilePath = $_.Path
				$pathMatches = @($targetPaths | Where-Object { $_ -ieq $openFilePath }).Count -gt 0
				$clientProperty = $_.PSObject.Properties['ClientComputerName']
				$clientMatches = -not $clientProperty -or -not $TargetClientComputerName -or $clientProperty.Value -ieq $TargetClientComputerName
				$pathMatches -and $clientMatches
			}

			foreach ($openFile in $openFiles) {
				Close-SmbOpenFile -FileId $openFile.FileId -Force
			}
		}

		try {
			if ($env:COMPUTERNAME -ieq $SmbFileServer -or $SmbFileServer -like "$env:COMPUTERNAME.*") {
				& $cleanupScript $DocumentPath $DocumentDirectoryPath $ClientComputerName | Out-Null
			} else {
				Invoke-Command -ComputerName $SmbFileServer -ScriptBlock $cleanupScript -ArgumentList $DocumentPath, $DocumentDirectoryPath, $ClientComputerName | Out-Null
			}
		} catch {
			Write-Verbose "Unable to close SMB open files on '$SmbFileServer': $($_.Exception.Message)"
		}
	}

	function Close-OpenedDocumentProcess {
		param(
			[Parameter()]
			[object]$DocumentProcess
		)

		if (-not $DocumentProcess) {
			return $true
		}

		$openedDocument = $DocumentProcess |
			Where-Object { $_.PSObject.Properties.Name -contains 'Path' -and $_.Path } |
			Select-Object -First 1
		if ($openedDocument) {
			Write-Host "Closing previous document: $($openedDocument.Path)" -ForegroundColor Magenta
			$closedByOffice = Close-OfficeDocumentByPath -Path $openedDocument.Path -Extension $openedDocument.Extension
			Close-SmbServerOpenFiles -DocumentPath $openedDocument.ServerPath -DocumentDirectoryPath $openedDocument.ServerDirectoryPath -ClientComputerName $env:COMPUTERNAME
			if ($closedByOffice) {
				return $true
			}
		}

		$processId = @($DocumentProcess |
			Where-Object { $_.PSObject.Properties.Name -contains 'ProcessId' -and $_.ProcessId } |
			Select-Object -ExpandProperty ProcessId -First 1)
		if (-not $processId) {
			Write-Warning "Could not identify the application process for '$($openedDocument.Path)'. Continuing to the next document."
			return $true
		}

		$process = Get-Process -Id $processId[0] -ErrorAction SilentlyContinue
		if (-not $process) {
			return $true
		}

		Write-Verbose "Closing previous document process: $($process.ProcessName) ($($process.Id))"
		if ($process.MainWindowHandle -ne 0) {
			[void]$process.CloseMainWindow()
			[void]$process.WaitForExit(3000)
		}

		if (-not $process.HasExited) {
			Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
			try {
				[void]$process.WaitForExit(3000)
			} catch {
				# The process object can become invalid immediately after a forced stop.
			}
		}

		if ($openedDocument) {
			Close-SmbServerOpenFiles -DocumentPath $openedDocument.ServerPath -DocumentDirectoryPath $openedDocument.ServerDirectoryPath -ClientComputerName $env:COMPUTERNAME
		}

		return -not (Get-Process -Id $processId[0] -ErrorAction SilentlyContinue)
	}

	Set-ConsoleWindowTopMost

	function Get-UncDocumentPathInfo {
		param(
			[Parameter(Mandatory)]
			[string]$UncPath
		)

		$match = [regex]::Match($UncPath, '^\\\\(?<server>[^\\]+)\\(?<share>[^\\]+)\\(?<relative>.+)$')
		if (-not $match.Success) {
			throw "Path '$UncPath' is not a UNC document path. Use the format \\server\share\document.ext."
		}

		[pscustomobject]@{
			ServerName        = $match.Groups['server'].Value
			ShareName         = $match.Groups['share'].Value
			ShareRelativePath = $match.Groups['relative'].Value
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
			[string]$ServerName
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

	function Write-DocumentHeader {
		param(
			[Parameter(Mandatory)]
			[string]$ServerName
		)

		$headerColor = if ($ServerName -like '*.workinghardinit.work') {
			'Yellow'
		} elseif ($ServerName -like '*.datawisetech.com') {
			'Cyan'
		} elseif ($ServerName -like '*.datawisetech.corp') {
			'Green'
		} else {
			'Magenta'
		}

		$title = " SMB over QUIC demo | $ServerName "
		$line = '#' * ($title.Length + 4)
		Write-Host ''
		Write-Host $line -ForegroundColor $headerColor
		Write-Host "##$title##" -ForegroundColor $headerColor
		Write-Host $line -ForegroundColor $headerColor
	}

	function Open-UncDocument {
		param(
			[Parameter(Mandatory)]
			[string]$UncPath
		)

		$pathInfo = Get-UncDocumentPathInfo -UncPath $UncPath
		$extension = [System.IO.Path]::GetExtension($UncPath)
		if ($extension -notin $supportedExtensions) {
			throw "Path '$UncPath' has extension '$extension'. Supported extensions are: $($supportedExtensions -join ', ')."
		}

		Write-DocumentHeader -ServerName $pathInfo.ServerName
		Write-Host "Opening: $UncPath" -ForegroundColor Magenta
		$serverPath = Join-Path -Path $ServerSharePath -ChildPath $pathInfo.ShareRelativePath
		Write-Host ("{0:u} | Starting registered application for current UNC target only" -f (Get-Date)) -ForegroundColor DarkGray
		$documentProcess = Start-Process -FilePath $UncPath -PassThru
		$authenticationStatus = Get-SmbDocumentAuthenticationStatus -ServerName $pathInfo.ServerName
		Write-Host "Authentication: $($authenticationStatus.Label)" -ForegroundColor $authenticationStatus.Color

		[pscustomobject]@{
			Path                = $UncPath
			Extension           = $extension
			Authentication      = $authenticationStatus.Label
			ServerPath          = $serverPath
			ServerDirectoryPath = Split-Path -Path $serverPath -Parent
			ProcessId           = if ($documentProcess) { $documentProcess.Id } else { $null }
			ProcessName         = if ($documentProcess) { $documentProcess.ProcessName } else { $null }
		}
	}

	function Read-ContinueKey {
		param(
			[Parameter(Mandatory)]
			[string]$Message,

			[Parameter()]
			[switch]$AllowExit
		)

		if ([Console]::IsInputRedirected) {
			return Read-Host $Message
		}

		while ([Console]::KeyAvailable) {
			[void][Console]::ReadKey($true)
		}

		while ($true) {
			Write-Host $Message -NoNewline
			$key = [Console]::ReadKey($true)
			Write-Host ''

			if ($key.Key -eq [ConsoleKey]::Enter) {
				return ''
			}

			if ($AllowExit -and ($key.Key -eq [ConsoleKey]::X -or $key.Key -eq [ConsoleKey]::Q)) {
				return $key.KeyChar
			}

			if (-not $AllowExit -and $key.Key -eq [ConsoleKey]::Q) {
				return $key.KeyChar
			}
		}
	}

	$documentPaths = [System.Collections.Generic.List[string]]::new()
}

process {
	foreach ($uncPath in $Path) {
		$documentPaths.Add($uncPath)
	}
}

end {
	if ($documentPaths.Count -eq 0 -and -not $MyInvocation.ExpectingInput) {
		$documentPaths.Add('\\fsquic.datawisetech.corp\finance\2024\HELLOSMBOVERQUIC2024.docx')
		$documentPaths.Add('\\fsquic.datawisetech.com\finance\2025\SomeProjections2025.xlsx')
		$documentPaths.Add('\\fsquic.workinghardinit.work\finance\2026\HELLOSMBOVERQUIC2026.docx')
	}

	if ($PSBoundParameters.ContainsKey('Step')) {
		$documentPaths = [System.Collections.Generic.List[string]]::new(@($documentPaths[$Step - 1]))
	}

	$openedDocumentProcess = $null
	for ($index = 0; $index -lt $documentPaths.Count; $index++) {
		$currentPath = $documentPaths[$index]
		$previousDocumentClosed = Close-OpenedDocumentProcess -DocumentProcess $openedDocumentProcess
		if (-not $previousDocumentClosed) {
			Write-Warning 'The previous document could not be closed automatically. Continuing to the next document.'
		}
		$openedDocumentProcess = $null

		if ($PSCmdlet.ShouldProcess($currentPath, 'Open document from UNC path')) {
			Write-Host "Step $($index + 1) of $($documentPaths.Count)" -ForegroundColor DarkGray
			$openedDocumentProcess = Open-UncDocument -UncPath $currentPath
			Set-ConsoleWindowTopMost -DurationMilliseconds 1000 -Quiet
		}

		if ($index -lt ($documentPaths.Count - 1)) {
			Set-ConsoleWindowTopMost -DurationMilliseconds 1000 -Quiet
			$response = Read-ContinueKey -Message $Prompt
			if ($response -match '^(?i:q|quit|stop)$') {
				break
			}
		}
	}

	$lastDocumentClosed = Close-OpenedDocumentProcess -DocumentProcess $openedDocumentProcess
	if (-not $lastDocumentClosed) {
		Write-Warning 'The last document could not be closed automatically.'
	}
	Set-ConsoleWindowTopMost -DurationMilliseconds 1000 -Quiet

	do {
		Set-ConsoleWindowTopMost -DurationMilliseconds 1000 -Quiet
		$exitResponse = Read-ContinueKey -Message $ExitPrompt -AllowExit
	} until ([string]::IsNullOrWhiteSpace($exitResponse) -or $exitResponse -match '^(?i:x|exit)$')
}

<#
Example:
.\Open-DocumentSequenceFromUncPath.ps1 -Path @(
	'\\fsquic.datawisetech.com\Share\Runbook.txt',
	'\\fsquic.datawisetech.com\Share\Design.docx',
	'\\fsquic.datawisetech.com\Share\Budget.xlsx'
)

Pipeline input is supported:
'\\fsquic.datawisetech.com\Share\Runbook.txt', '\\fsquic.datawisetech.com\Share\Design.docx' |
	.\Open-DocumentSequenceFromUncPath.ps1
#>

