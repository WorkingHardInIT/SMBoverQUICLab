[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$SmbOverQuicServer = @('file01'),

    [Parameter()]
    [string[]]$UserFilter = @(),

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$PollSeconds = 3,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$LookbackMinutes = 180,

    [Parameter()]
    [switch]$IncludeServerTransportEvents,

    [Parameter()]
    [switch]$ShowAllUsers,

    [Parameter()]
    [switch]$LiveOnly,

    [Parameter()]
    [switch]$ReplayHistory,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$CorrelationSeconds = 30,

    [Parameter()]
    [ValidateRange(0, 60)]
    [int]$CorrelationSettleSeconds = 4,

    [Parameter()]
    [ValidateRange(0, 300)]
    [int]$StartupLookbackSeconds = 180,

    [Parameter()]
    [ValidateRange(10, 5000)]
    [int]$MaxEventsPerPoll = 500,

    [Parameter()]
    [switch]$ShowLogonDetails,

    [Parameter()]
    [switch]$ClearOnRefresh
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$host.UI.RawUI.WindowTitle = 'SMB Login / QUIC Correlation'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $elevatedArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($boundParameter in $PSBoundParameters.GetEnumerator()) {
        $parameterName = "-$($boundParameter.Key)"
        if ($boundParameter.Value -is [switch]) {
            if ($boundParameter.Value.IsPresent) {
                $elevatedArguments += $parameterName
            }
            continue
        }

        $elevatedArguments += $parameterName
        foreach ($parameterValue in @($boundParameter.Value)) {
            $elevatedArguments += [string]$parameterValue
        }
    }

    $elevatedProcess = Start-Process -FilePath 'pwsh.exe' -Verb RunAs -ArgumentList $elevatedArguments -WorkingDirectory (Get-Location) -Wait -PassThru
    exit $elevatedProcess.ExitCode
}

$clearDemoStateScript = Join-Path -Path $PSScriptRoot -ChildPath 'Clear-SmbDemoState.ps1'
if (-not (Test-Path -LiteralPath $clearDemoStateScript -PathType Leaf)) {
    throw "Demo cleanup script was not found at '$clearDemoStateScript'."
}

foreach ($server in $SmbOverQuicServer) {
    Write-Host "Clearing SMB demo state on '$server'..." -ForegroundColor DarkGray
    & $clearDemoStateScript -ComputerName $server -Confirm:$false
}

# Transport correlation is enabled by default for the normal demo scenario.
# Passing -IncludeServerTransportEvents explicitly remains supported.
if (-not $PSBoundParameters.ContainsKey('IncludeServerTransportEvents')) {
    $IncludeServerTransportEvents = $true
}

if (-not $ReplayHistory) {
    $LiveOnly = $true
}

# Keep the PowerShell window on top during demonstrations. This is the original
# working implementation; do not replace it with MainWindowHandle-only logic.
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
'@
$type = 'SetWindowPos.SetWindowPosition' -as [type]
if (-not $type) {
    $type = Add-Type -MemberDefinition $signature -Name SetWindowPosition -Namespace SetWindowPos -Using System.Text -PassThru
}

# Under Windows Terminal, pwsh's console handle is a ConPTY handle and is not the
# visible Terminal window. Prefer the actual WindowsTerminal process window there.
$terminalProcess = Get-Process -Name WindowsTerminal, WindowsTerminalPreview -ErrorAction SilentlyContinue |
    Where-Object MainWindowHandle -ne 0 |
    Select-Object -First 1
$handle = if ($terminalProcess) {
    $terminalProcess.MainWindowHandle
} else {
    $type::GetConsoleWindow()
}

if ($handle -eq [IntPtr]::Zero) {
    $handle = (Get-Process -Id $PID).MainWindowHandle
}

# HWND_TOPMOST is -1. -2 is HWND_NOTOPMOST and disables always-on-top.
$topMost = New-Object -TypeName System.IntPtr -ArgumentList (-1)
if ($handle -ne [IntPtr]::Zero) {
    $pinned = $type::SetWindowPos($handle, $topMost, 0, 0, 0, 0, 0x0053)
    if ($pinned) {
        Write-Host "PowerShell console pinned on top (handle $handle)." -ForegroundColor DarkGray
    } else {
        Write-Warning "SetWindowPos failed for window handle $handle."
    }
} else {
    Write-Warning 'Could not find a console window to pin on top.'
}

if ($ReplayHistory) {
    Write-Host 'Demo mode enabled; the historical window is replayed every refresh.' -ForegroundColor DarkGray
} else {
    Write-Host 'Live-only mode enabled; only events created after monitor startup are displayed.' -ForegroundColor DarkGray
}

function Get-EventDataMap {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    # Event 4624 fields are read by XML name instead of fragile ReplacementStrings
    # indexes, which can vary between Windows versions and event providers.
    $xml = [xml]$Event.ToXml()
    $data = @{}
    foreach ($item in @($xml.Event.EventData.Data)) {
        if ($item.Name) {
            $data[$item.Name] = [string]$item.InnerText
        }
    }

    return $data
}

function Resolve-AccountName {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EventData
    )

    $domain = $EventData['TargetDomainName']
    $user = $EventData['TargetUserName']
    if ($domain -and $user -and $user -ne '-') {
        return "$domain\$user"
    }

    if ($EventData['TargetUserSid'] -and $EventData['TargetUserSid'] -ne '-') {
        try {
            return ([System.Security.Principal.SecurityIdentifier]$EventData['TargetUserSid']).Translate(
                [System.Security.Principal.NTAccount]).Value
        } catch {
            return $EventData['TargetUserSid']
        }
    }

    return $user
}

function Test-UserMatch {
    param(
        [Parameter(Mandatory)]
        [string[]]$AccountCandidates,

        [Parameter(Mandatory)]
        [string[]]$Filter
    )

    foreach ($candidate in $AccountCandidates) {
        if ($candidate -and ($Filter | Where-Object { $_ -ieq $candidate })) {
            return $true
        }
    }

    return $false
}

function Test-EmptyEventQueryError {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    return $ErrorRecord.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or
        $ErrorRecord.Exception.Message -match '(?i)No events were found|There are no events matching'
}

function Get-RemoteWinEventsOrEmpty {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [hashtable]$FilterHashtable,

        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter()]
        [ValidateRange(1, 5000)]
        [int]$MaxEvents = 500
    )

    try {
        if (Test-LocalComputerName -ComputerName $ComputerName) {
            return @(Get-WinEvent -FilterHashtable $FilterHashtable -MaxEvents $MaxEvents -ErrorAction Stop | Sort-Object RecordId)
        }

        return @(Get-WinEvent -ComputerName $ComputerName -FilterHashtable $FilterHashtable -MaxEvents $MaxEvents -ErrorAction Stop | Sort-Object RecordId)
    } catch {
        if (Test-EmptyEventQueryError -ErrorRecord $_) {
            return @()
        }

        Write-Warning "Unable to read $Description events from '$ComputerName': $($_.Exception.Message)"
        return @()
    }
}

function Get-RemoteSecurityNetworkLogonsOrEmpty {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter()]
        [ValidateRange(1, 5000)]
        [int]$MaxEvents = 500
    )

    $securityEvents = Get-RemoteWinEventsOrEmpty -ComputerName $ComputerName -Description 'Security 4624 fallback' -FilterHashtable @{
        LogName = 'Security'
        Id      = 4624
    } -MaxEvents $MaxEvents

    return @($securityEvents | Where-Object {
        $eventData = Get-EventDataMap -Event $_
        $eventData['LogonType'] -eq '3'
    } | Sort-Object RecordId)
}

function Get-NearbyTransportInfo {
    param(
        [Parameter(Mandatory)]
        [datetime]$TimeCreated,

        [Parameter(Mandatory)]
        [object[]]$TransportEvents,

        [Parameter()]
        [string]$SourceIp
    )

    $candidates = @(
        foreach ($transportEvent in @($TransportEvents | Where-Object {
            [math]::Abs(($_.TimeCreated - $TimeCreated).TotalSeconds) -le $CorrelationSeconds
        })) {
            $eventText = $transportEvent.ToXml() + [Environment]::NewLine + $transportEvent.FormatDescription()
            $sourceMatch = $SourceIp -and $SourceIp -ne 'Unavailable' -and $eventText -match [regex]::Escape($SourceIp)
            $hasQuic = $eventText -match '(?i)\bQUIC\b'
            $hasTcp = $eventText -match '(?i)\bTCP\b'
            $hasMutualAuth = $eventText -match '(?i)Mutual\s*authentication\s*[:=]\s*(Yes|No)|MutualAuthentication\s*[:=]\s*(Yes|No)'
            $hasAccessControl = $eventText -match '(?i)Access\s*control\s*[:=]\s*(Yes|No)|AccessControl\s*[:=]\s*(Yes|No)'
            $score = ([int]$sourceMatch * 100) + ([int]$hasMutualAuth * 25) + ([int]$hasAccessControl * 25) + ([int]$hasQuic * 10) + ([int]$hasTcp * 5) - [math]::Abs(($transportEvent.TimeCreated - $TimeCreated).TotalSeconds)

            [pscustomobject]@{
                Event          = $transportEvent
                Text           = $eventText
                Score          = $score
                SourceMatch    = $sourceMatch
            }
        }
    )

    $selected = $candidates | Sort-Object Score -Descending | Select-Object -First 1

    if (-not $selected) {
        return [pscustomobject]@{
            Transport            = 'Uncorrelated'
            MutualAuthentication = 'Uncorrelated'
            AccessControl        = 'Uncorrelated'
            Correlation          = 'None'
        }
    }

    $message = $selected.Text
    $transport = if ($message -match '(?i)\bQUIC\b') { 'QUIC' } elseif ($message -match '(?i)\bTCP\b') { 'TCP' } else { 'Unknown' }
    $mutualAuthentication = if ($message -match '(?i)Mutual\s*authentication\s*[:=]\s*Yes|MutualAuthentication\s*[:=]\s*Yes') { 'Yes' } elseif ($message -match '(?i)Mutual\s*authentication\s*[:=]\s*No|MutualAuthentication\s*[:=]\s*No') { 'No' } else { 'Unknown' }
    $accessControl = if ($message -match '(?i)Access\s*control\s*[:=]\s*Yes|AccessControl\s*[:=]\s*Yes') { 'Yes' } elseif ($message -match '(?i)Access\s*control\s*[:=]\s*No|AccessControl\s*[:=]\s*No') { 'No' } else { 'Unknown' }

    return [pscustomobject]@{
        Transport            = $transport
        MutualAuthentication = $mutualAuthentication
        AccessControl        = $accessControl
        Correlation          = if ($selected.SourceMatch) { 'SourceIp+Time+Evidence' } else { 'Time+Evidence' }
    }
}

function Test-LocalComputerName {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $localNames = @(
        $env:COMPUTERNAME
        'localhost'
        '.'
        try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $null }
    ) | Where-Object { $_ }

    return @($localNames | Where-Object { $_ -ieq $ComputerName }).Count -gt 0
}

function Write-LogonEvent {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event,

        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter()]
        [object[]]$TransportEvents = @()
    )

    $eventData = Get-EventDataMap -Event $Event
    if ($eventData['LogonType'] -ne '3') {
        return
    }

    $accountName = Resolve-AccountName -EventData $eventData
    $accountCandidates = @(
        $accountName
        $eventData['TargetUserName']
        if ($eventData['TargetUserName'] -and $eventData['TargetDomainName']) {
            "$($eventData['TargetUserName'])@$($eventData['TargetDomainName'])"
        }
    ) | Where-Object { $_ -and $_ -ne '-' } | Select-Object -Unique

    $authenticationPackage = if ($eventData['AuthenticationPackageName']) {
        $eventData['AuthenticationPackageName']
    } else {
        'Unknown'
    }
	$isNtlm = $authenticationPackage -match '(?i)^NTLM'

    # Keep Kerberos visible even when the 4624 account fields do not normalize to
    # the requested user name. This prevents the authentication method being hidden
    # by an account-name mismatch; NTLM still follows UserFilter normally.
    $userMatchesFilter = $UserFilter.Count -eq 0 -or (Test-UserMatch -AccountCandidates $accountCandidates -Filter $UserFilter)
    if ($UserFilter.Count -gt 0 -and -not $ShowAllUsers -and -not $userMatchesFilter -and -not $isNtlm -and $authenticationPackage -ine 'Kerberos') {
        return [pscustomobject]@{ Displayed = $false; Retry = $false }
    }
    $sourceIp = if ($eventData['IpAddress'] -and $eventData['IpAddress'] -ne '-') {
        $eventData['IpAddress']
    } else {
        'Unavailable'
    }
    $transportInfo = Get-NearbyTransportInfo -TimeCreated $Event.TimeCreated -TransportEvents $TransportEvents -SourceIp $sourceIp
    $color = if ($isNtlm) {
        'Yellow'
    } elseif ($transportInfo.MutualAuthentication -eq 'Yes' -or $transportInfo.AccessControl -eq 'Yes') {
        'DarkCyan'
    } else {
        'Green'
    }

    $details = if ($ShowLogonDetails) {
        ' | LogonProcess: {0} | LmPackage: {1} | KeyLength: {2} | IpPort: {3} | Workstation: {4} | Correlation: {5}' -f
        $eventData['LogonProcessName'], $eventData['LmPackageName'], $eventData['KeyLength'], $eventData['IpPort'], $eventData['WorkstationName'], $transportInfo.Correlation
    } else {
        ''
    }

    $outputLine = (
        '{0:u} | {1} | Auth: {2} | Nearby transport: {3} | Mutual auth: {4} | Access control: {5} | Server: {6} | Source IP: {7} | Event: {8} | RecordId: {9}{10}' -f
        $Event.TimeCreated, $accountName, $authenticationPackage, $transportInfo.Transport, $transportInfo.MutualAuthentication, $transportInfo.AccessControl, $Server, $sourceIp, $Event.Id, $Event.RecordId, $details
    )

    return [pscustomobject]@{
        Displayed = $true
        Retry     = $false
        Key       = "$Server|$($Event.RecordId)"
        Server    = $Server
        RecordId  = $Event.RecordId
        Line      = $outputLine
        Color     = $color
    }
}

# Keep the last record read for each server and log so polling does not print the
# same events repeatedly. The source IP is retained because client names are often absent.
$lastRecordIds = @{}
$processedSecurityRecords = [System.Collections.Generic.HashSet[string]]::new()
$securityBaselineRecordIds = @{}
$resultHistory = [System.Collections.Generic.List[object]]::new()
$monitorStarted = Get-Date
$queryStartTime = if ($ReplayHistory) {
    $monitorStarted.AddMinutes(-$LookbackMinutes)
} else {
    $monitorStarted.AddSeconds(-$StartupLookbackSeconds)
}
$displayStartTime = $monitorStarted

function Write-MonitorHeader {
    if ($UserFilter.Count -gt 0 -and -not $ShowAllUsers) {
        Write-Host "Monitoring Security 4624 network logons for: $($UserFilter -join ', ')" -ForegroundColor White
    } else {
        Write-Host 'Monitoring all Security 4624 network logons (Kerberos and NTLM).' -ForegroundColor White
    }
    $windowDescription = if ($ReplayHistory) { "history: $LookbackMinutes minutes" } else { "since: $($displayStartTime.ToUniversalTime().ToString('u'))" }
    Write-Host "Servers: $($SmbOverQuicServer -join ', '); $windowDescription; press Ctrl+C to stop." -ForegroundColor Gray
    $remoteServers = @($SmbOverQuicServer | Where-Object { -not (Test-LocalComputerName -ComputerName $_) })
    if ($remoteServers) {
        Write-Host "Remote log polling can create its own Security 4624 Type 3 events on: $($remoteServers -join ', '). Run this monitor on the file server for the cleanest demo signal." -ForegroundColor Yellow
    }
    Write-Host ''
}

function Write-ResultHistory {
    param(
        [Parameter()]
        [object[]]$Results = $resultHistory
    )

    foreach ($result in @($Results | Sort-Object Server, RecordId)) {
        Write-Host -ForegroundColor $result.Color $result.Line
    }
}

if (-not $ReplayHistory) {
    foreach ($server in $SmbOverQuicServer) {
        $baselineEvents = Get-RemoteSecurityNetworkLogonsOrEmpty -ComputerName $server -MaxEvents $MaxEventsPerPoll
        $securityBaselineRecordIds[$server] = if ($baselineEvents) {
            ($baselineEvents | Measure-Object -Property RecordId -Maximum).Maximum
        } else {
            0
        }
    }
}

Write-MonitorHeader

while ($true) {
    if ($ClearOnRefresh) {
        Clear-Host
        Write-MonitorHeader
        Write-ResultHistory
    }

    $pollStarted = Get-Date
    $securityEventCount = 0
    $kerberosEventCount = 0
    $ntlmEventCount = 0
    $displayedEventCount = 0
    $deferredEventCount = 0
    $nonNetworkLogonEventCount = 0
    $filteredEventCount = 0
    $settledNetworkLogonEventCount = 0
    $alreadySeenEventCount = 0
    $ignoredEventSamples = [System.Collections.Generic.List[string]]::new()
    $pollResults = [System.Collections.Generic.List[object]]::new()
    Write-Host ("{0:u} | Poll started | querying {1}" -f $pollStarted, ($SmbOverQuicServer -join ', ')) -ForegroundColor DarkGray

    foreach ($server in $SmbOverQuicServer) {
        $transportEvents = @()
        if ($IncludeServerTransportEvents) {
            # Query a bounded set of recent records, then filter locally. Remote
            # StartTime filtering can miss events after log clearing or clock skew.
            $transportEvents = Get-RemoteWinEventsOrEmpty -ComputerName $server -Description 'SMB Server' -FilterHashtable @{
                LogName = 'Microsoft-Windows-SMBServer/Operational'
            } -MaxEvents $MaxEventsPerPoll | Where-Object { $_.TimeCreated -ge $queryStartTime }
        }

        $securityKey = "$server|Security"
        $securityEvents = Get-RemoteSecurityNetworkLogonsOrEmpty -ComputerName $server -MaxEvents $MaxEventsPerPoll |
            Where-Object { $ReplayHistory -or $_.RecordId -gt $securityBaselineRecordIds[$server] }

        foreach ($event in $securityEvents) {
            $securityEventCount++
            $securityRecordKey = "$server|Security|$($event.RecordId)"
            $isNewEvent = $ReplayHistory -or (-not $processedSecurityRecords.Contains($securityRecordKey))
            $eventIsSettled = ((Get-Date) - $event.TimeCreated).TotalSeconds -ge $CorrelationSettleSeconds
            if (-not $eventIsSettled) {
                $deferredEventCount++
                continue
            }

            $eventData = Get-EventDataMap -Event $event
            $eventUser = Resolve-AccountName -EventData $eventData
            $eventSummary = 'RecordId: {0} | Time: {1:u} | LogonType: {2} | User: {3}\{4} | Auth: {5} | Process: {6} | Source: {7}:{8}' -f
                $event.RecordId,
                $event.TimeCreated,
                $eventData['LogonType'],
                $eventData['TargetDomainName'],
                $eventData['TargetUserName'],
                $eventData['AuthenticationPackageName'],
                $eventData['LogonProcessName'],
                $eventData['IpAddress'],
                $eventData['IpPort']

            if ($LiveOnly -and -not $isNewEvent) {
                $alreadySeenEventCount++
                if ($ignoredEventSamples.Count -lt 5) {
                    $ignoredEventSamples.Add("Already seen | $eventSummary")
                }
                continue
            }

            if ($eventData['LogonType'] -ne '3') {
                $nonNetworkLogonEventCount++
                if ($ignoredEventSamples.Count -lt 5) {
                    $ignoredEventSamples.Add("Not LogonType 3 | $eventSummary")
                }
                if ($isNewEvent) {
                    [void]$processedSecurityRecords.Add($securityRecordKey)
                }
                continue
            }

            if (-not $LiveOnly -or $isNewEvent) {
                $settledNetworkLogonEventCount++
                if ($eventData['AuthenticationPackageName'] -ieq 'Kerberos') {
                    $kerberosEventCount++
                } elseif ($eventData['AuthenticationPackageName'] -match '(?i)^NTLM') {
                    $ntlmEventCount++
                }

                $logonResult = Write-LogonEvent -Event $event -Server $server -TransportEvents $transportEvents
                if ($logonResult.Displayed) {
                    $displayedEventCount++
                    if (-not @($resultHistory | Where-Object Key -eq $logonResult.Key)) {
                        $resultHistory.Add($logonResult)
                    }
                    $pollResults.Add($logonResult)
                    [void]$processedSecurityRecords.Add($securityRecordKey)
                } else {
                    $filteredEventCount++
                    if ($ShowLogonDetails -and $ignoredEventSamples.Count -lt 5) {
                        $ignoredEventSamples.Add("Filtered | $eventSummary")
                    }

                    if (-not $logonResult.Retry) {
                        [void]$processedSecurityRecords.Add($securityRecordKey)
                    }
                }
            }
            if ($isNewEvent -and $eventData['LogonType'] -ne '3') {
                [void]$processedSecurityRecords.Add($securityRecordKey)
            }
        }

        if ($IncludeServerTransportEvents) {
            $transportKey = "$server|SMBServer"
            foreach ($event in $transportEvents) {
                $isNewEvent = -not $lastRecordIds.ContainsKey($transportKey) -or $event.RecordId -gt $lastRecordIds[$transportKey]
                if ($isNewEvent) {
                    $lastRecordIds[$transportKey] = $event.RecordId
                }
            }
        }
    }

    Write-Host ("{0:u} | Poll complete | New read: {1} | New Kerberos: {2} | New NTLM: {3} | New displayed: {4} | History: {5} | Next poll in {6}s" -f
        $pollStarted, $securityEventCount, $kerberosEventCount, $ntlmEventCount, $displayedEventCount, $resultHistory.Count, $PollSeconds) -ForegroundColor DarkGray
    Write-ResultHistory
    if ($displayedEventCount -eq 0) {
        if ($deferredEventCount -gt 0) {
            Write-Host "Waiting for $deferredEventCount fresh logon event(s) to settle for $CorrelationSettleSeconds seconds before display." -ForegroundColor DarkGray
        } elseif ($securityEventCount -eq 0) {
            Write-Host "No Security 4624 network logon events found since $($displayStartTime.ToUniversalTime().ToString('u'))." -ForegroundColor DarkGray
        } elseif ($settledNetworkLogonEventCount -eq 0) {
            if ($ShowLogonDetails -or $alreadySeenEventCount -eq 0) {
                Write-Host "Security 4624 events were found, but none were new settled LogonType 3 network logons. Waiting for SMB network logons." -ForegroundColor DarkGray
            }
            if ($ShowLogonDetails) {
                Write-Host "Ignored this poll: Already seen: $alreadySeenEventCount | Not LogonType 3: $nonNetworkLogonEventCount | Deferred: $deferredEventCount" -ForegroundColor DarkGray
            }
        } else {
            if ($ShowLogonDetails) {
                Write-Host "Security 4624 network logons were found, but $filteredEventCount did not match the current user/correlation filters." -ForegroundColor DarkGray
            } elseif ($filteredEventCount -gt 0) {
                Write-Host "Security 4624 network logons were found, but none matched the current user filter." -ForegroundColor DarkGray
            }
        }

        if ($ShowLogonDetails) {
            foreach ($sample in $ignoredEventSamples) {
                Write-Host "  $sample" -ForegroundColor DarkGray
            }
        }
    }
    Start-Sleep -Seconds $PollSeconds
}
