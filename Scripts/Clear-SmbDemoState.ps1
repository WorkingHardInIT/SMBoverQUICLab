#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName = 'localhost'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$serverLogNames = @(
    'Security'
    'Microsoft-Windows-SMBServer/Operational'
    'Microsoft-Windows-SMBServer/Audit'
    'Microsoft-Windows-SMBServer/Connectivity'
)
$cleanupScript = {
    param([string[]]$LogNames, [string]$ExcludedClientComputerName)

    $openFiles = @(Get-SmbOpenFile -ErrorAction SilentlyContinue | Where-Object {
        $clientProperty = $_.PSObject.Properties['ClientComputerName']
        -not $clientProperty -or $clientProperty.Value -ine $ExcludedClientComputerName
    })
    foreach ($openFile in $openFiles) {
        Close-SmbOpenFile -FileId $openFile.FileId -Force -Confirm:$false
    }

    $sessions = @(Get-SmbSession -ErrorAction SilentlyContinue | Where-Object {
        $clientProperty = $_.PSObject.Properties['ClientComputerName']
        -not $clientProperty -or $clientProperty.Value -ine $ExcludedClientComputerName
    })
    foreach ($session in $sessions) {
        Close-SmbSession -SessionId $session.SessionId -Force -Confirm:$false
    }

    foreach ($logName in $LogNames) {
        if (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue) {
            & wevtutil.exe cl $logName
            if ($LASTEXITCODE -ne 0) {
                throw "Unable to clear event log '$logName'. Wevtutil exited with code $LASTEXITCODE."
            }
        }
    }

    [pscustomobject]@{
        OpenFilesClosed = $openFiles.Count
        SessionsClosed  = $sessions.Count
        ExcludedClient  = $ExcludedClientComputerName
        LogsCleared     = @($LogNames)
    }
}

$callerComputerName = $env:COMPUTERNAME

if ($PSCmdlet.ShouldProcess($ComputerName, "Close SMB open files and sessions, then clear $($serverLogNames -join ', ')")) {
    if ($ComputerName -eq '.' -or $ComputerName -ieq 'localhost' -or $ComputerName -ieq $env:COMPUTERNAME) {
        & $cleanupScript -LogNames $serverLogNames -ExcludedClientComputerName $callerComputerName
    } else {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock $cleanupScript -ArgumentList $serverLogNames, $callerComputerName
    }
}

<##
Example:
# Preview without changing the server:
.\Clear-SmbDemoState.ps1 -ComputerName file01 -WhatIf

# Clear the Security and SMB Server operational logs and close SMB state:
.\Clear-SmbDemoState.ps1 -ComputerName file01 -Confirm:$false

This closes SMB open files and sessions on the target server except those owned
by the computer running this script. It clears Security and SMB Server logs on
the target server, including SMBServer/Connectivity.
#>
