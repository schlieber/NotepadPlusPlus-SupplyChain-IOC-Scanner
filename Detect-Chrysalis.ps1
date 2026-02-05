#Requires -Version 5.1
<#
.SYNOPSIS
    Notepad++ Supply Chain Attack (Chrysalis/Lotus Blossom) - Indicator of Compromise Scanner

.DESCRIPTION
    Read-only, non-destructive host-based scanner that checks for indicators of compromise
    associated with the Chrysalis backdoor and related malware deployed by Chinese APT group
    Lotus Blossom (also tracked as Billbug, Spring Dragon, Thrip) via a supply chain compromise
    of Notepad++ hosting infrastructure (June - December 2025).

    This script does NOT modify your system. It only reads files, registry keys,
    network state, event logs, and process lists.

    Covers all three infection chains:
    - Chain #1: ProShow exploit (July-August 2025)
    - Chain #2: Lua-based loader (September-October 2025)
    - Chain #3: Chrysalis backdoor via DLL sideloading (October 2025)

    Checks performed (16 total, FP-aware scoring):
      1.  Drop directories with path-based scoring
      2.  USOShared TinyCC artifacts (conf.c, libtcc.dll, svchost.exe)
      3.  SHA-256 / SHA-1 hash verification against known malware
      4.  DNS cache for C2 domains
      5.  Active TCP connections to known C2 IPs (Get-NetTCPConnection + netstat fallback)
      6.  Chrysalis mutex (Global\Jdhfv_1.0.1)
      7.  Running process path analysis
      8.  Registry Run/RunOnce with legitimate updater allowlist
      9.  Scheduled task action path analysis
      10. Hosts file C2 domains (blocking-aware)
      11. Notepad++ install discovery + Notepad++/GUP.exe signature validation + securityError.log context
      12. Exfil staging artifacts (1.txt, a.txt, u.bat)
      13. Windows Event Log correlated pattern matching + DNS client telemetry
      14. High-entropy file detection (Shannon > 7.2)
      15. Campaign string/pattern content scanning
      16. Windows service path analysis

    DeepScan additions:
    - Windows Firewall history parsing (default: %windir%\System32\LogFiles\Firewall\pfirewall.log; profile/policy-defined paths supported)

.PARAMETER OutputPath
    Directory for JSON/CSV report output when export switches are used.

.PARAMETER ExportCSV
    Export findings to CSV format.

.PARAMETER ExportJSON
    Export findings/report to JSON format.

.PARAMETER DeepScan
    Extends hash scanning to include Downloads, Temp, and ProgramData directories,
    expands event log coverage, and parses Windows Firewall history logs if enabled.

.PARAMETER Quiet
    Suppresses console output for clean/OK checks. Only shows findings.

.EXAMPLE
    .\Detect-Chrysalis.ps1
    Run a standard scan with colored output.

.EXAMPLE
    .\Detect-Chrysalis.ps1 -DeepScan
    Run with extended hash scanning across additional directories.

.EXAMPLE
    .\Detect-Chrysalis.ps1 -ExportJSON -OutputPath "C:\Logs"
    Run scan and export results to JSON in C:\Logs.

.EXAMPLE
    .\Detect-Chrysalis.ps1 -ExportJSON -ExportCSV -OutputPath "C:\Logs"
    Run scan and export results to both JSON and CSV in C:\Logs.

.EXAMPLE
    .\Detect-Chrysalis.ps1 -Quiet
    Run with minimal output - only shows findings, not clean checks.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Detect-Chrysalis.ps1
    Run without changing system execution policy.

.NOTES
    Version    : 1.1.2
    Author     : Simon Schlieber (@schlieber)
    Repository : https://github.com/schlieber/NotepadPlusPlus-SupplyChain-IOC-Scanner
    Date       : February 2026
    License    : MIT

    IoC Sources:
    - Rapid7 Labs: "The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit"
    - Kaspersky GReAT: "Notepad++ Supply Chain Attack Analysis"
    - signature-base filename IoC rules (selected path patterns)
      https://github.com/Neo23x0/signature-base/blob/master/iocs/filename-iocs.txt
    - signature-base license reference
      https://github.com/Neo23x0/signature-base/blob/master/LICENSE

    MITRE ATT&CK Techniques:
    - T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain
    - T1574.002 - Hijack Execution Flow: DLL Side-Loading
    - T1059.003 - Command and Scripting Interpreter: Windows Command Shell
    - T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
    - T1053.005 - Scheduled Task/Job: Scheduled Task
    - T1071.001 - Application Layer Protocol: Web Protocols
    - T1041     - Exfiltration Over C2 Channel
    - T1082     - System Information Discovery
    - T1057     - Process Discovery
    - T1140     - Deobfuscate/Decode Files or Information

    Threat Actor: Lotus Blossom (also known as Billbug, Spring Dragon, Thrip)
    - APT group attributed to China
    - Active since at least 2012
    - Targets government, military, and technology sectors

.KEYWORDS
    Notepad++ hack detection, CVE-2025-15556, Chrysalis backdoor, Lotus Blossom,
    Billbug, supply chain compromise, IoC scanner, PowerShell DFIR tool

.LINK
    https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/

.LINK
    https://securelist.com/notepad-supply-chain-attack/118708/

.LINK
    https://www.cve.org/CVERecord?id=CVE-2025-15556

.LINK
    https://attack.mitre.org/groups/G0030/

.LINK
    https://github.com/Neo23x0/signature-base/blob/master/iocs/filename-iocs.txt

.LINK
    https://github.com/Neo23x0/signature-base/blob/master/LICENSE
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop",
    [switch]$ExportJSON,
    [switch]$ExportCSV,
    [switch]$DeepScan,
    [switch]$Quiet
)

# ============================================================================
# CONFIGURATION - INDICATORS OF COMPROMISE
# ============================================================================

$TotalChecks = 16

# Drop dirs observed in chains (directory existence alone is NOT always malicious)
$DropDirs = @{
    ProShow      = "$env:APPDATA\ProShow"           # Chain #1 working dir / stage
    AdobeScripts = "$env:APPDATA\Adobe\Scripts"     # Chain #2 working dir / stage
    Bluetooth    = "$env:APPDATA\Bluetooth"         # Chain #3 drop dir (Chrysalis)
}

# USOShared is legitimate. We only look for SPECIFIC artifacts (Rapid7).
$ProgramDataRoot = if ($env:ProgramData) { $env:ProgramData } elseif ($env:ALLUSERSPROFILE) { $env:ALLUSERSPROFILE } else { $null }
if (-not $ProgramDataRoot) {
    $ProgramDataRoot = if ($env:windir) { Join-Path $env:windir "..\ProgramData" } else { $PSScriptRoot }
}
try {
    $USOSharedPath = Join-Path $ProgramDataRoot "USOShared"
}
catch {
    $USOSharedPath = "$ProgramDataRoot/USOShared"
}
$USOSharedMaliciousFiles = @("conf.c", "libtcc.dll", "svchost.exe")

# Known malicious update deployment filenames (existence != malicious; hash/location matters)
$SuspiciousUpdateNames = @("update.exe", "install.exe", "AutoUpdater.exe")

# C2 infrastructure (Rapid7, Kaspersky)
$MaliciousIPs = @(
    "95.179.213.0",
    "45.76.155.202",
    "45.32.144.255",
    "45.77.31.210",
    "61.4.102.97",
    "59.110.7.32",
    "124.222.137.114"
)

$MaliciousDomains = @(
    "api.skycloudcenter.com",
    "api.wiresguard.com",
    "cdncheck.it.com",
    "safe-dns.it.com",
    "self-dns.it.com",
    "temp.sh"
)

# Observed malicious update delivery URLs from public incident reporting.
$MaliciousUpdateURLs = @(
    "http://45.76.155.202/update/update.exe",
    "http://45.32.144.255/update/update.exe",
    "http://95.179.213.0/update/update.exe",
    "http://95.179.213.0/update/install.exe",
    "http://95.179.213.0/update/AutoUpdater.exe"
)

# Hash indicators (Rapid7, Kaspersky)
$MaliciousSHA256 = @{
    "a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9" = "update.exe (NSIS installer)"
    "8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e" = "[NSIS].nsi"
    "2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924" = "BluetoothService.exe"
    "77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e" = "BluetoothService shellcode"
    "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad" = "log.dll"
    "9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600" = "u.bat"
    "f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a" = "conf.c"
    "4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906" = "libtcc.dll"
    "831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd" = "admin (shellcode/blob)"
    "b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3" = "ConsoleApplication2.exe (Warbird loader)"
    "fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a" = "s047t5g.exe (loader)"
    "0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd" = "Loader 1"
    "e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda" = "Loader 2"
    "4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8" = "uffhxpSy (shellcode)"
    "078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5" = "3yZR31VK (shellcode)"
    "7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd" = "system (shellcode/blob)"
}

$MaliciousSHA1 = @{
    # update.exe variants
    "8e6e505438c21f3d281e1cc257abdbf7223b7f5a" = "update.exe (Chain 1 July)"
    "90e677d7ff5844407b9c073e3b7e896e078e11cd" = "update.exe (Chain 1 Aug)"
    "573549869e84544e3ef253bdba79851dcde4963a" = "update.exe (Chain 2 Mid-Sept)"
    "13179c8f19fbf3d8473c49983a199e6cb4f318f0" = "update.exe (Chain 2 End-Sept)"
    "4c9aac447bf732acc97992290aa7a187b967ee2c" = "update.exe (Chain 2 variant)"
    "821c0cafb2aab0f063ef7e313f64313fc81d46cd" = "update.exe (Chain 2 Oct)"
    "d7ffd7b588880cf61b603346a3557e7cce648c93" = "update.exe (Chain 3)"
    # Chain #1 ProShow
    "defb05d5a91e4920c9e22de2d81c5dc9b95a9a7c" = "ProShow.exe"
    "259cd3542dea998c57f67ffdd4543ab836e3d2a3" = "defscr"
    "46654a7ad6bc809b623c51938954de48e27a5618" = "if.dnt"
    "9df6ecc47b192260826c247bf8d40384aa6e6fd6" = "proshow_e.bmp"
    "06a6a5a39193075734a32e0235bde0e979c27228" = "load"
    "9c3ba38890ed984a25abb6a094b5dbf052f22fa7" = "load (variant)"
    # Chain #2
    "6444dab57d93ce987c22da66b3706d5d7fc226da" = "alien.dll"
    "2ab0758dda4e71aee6f4c8e4c0265a796518f07d" = "lua5.1.dll"
    "bf996a709835c0c16cce1015e6d44fc95e08a38a" = "script.exe"
    "ca4b6fe0c69472cd3d63b212eb805b7f65710d33" = "alien.ini"
    "0d0f315fd8cf408a483f8e2dd1e69422629ed9fd" = "alien.ini (v2)"
    "2a476cfb85fbf012fdbe63a37642c11afa5cf020" = "alien.ini (v3)"
    # Chain #3
    "21a942273c14e4b9d3faa58e4de1fd4d5014a1ed" = "BluetoothService.exe"
    "f7910d943a013eede24ac89d6388c1b98f8b3717" = "log.dll"
    "7e0790226ea461bcc9ecd4be3c315ace41e1c122" = "BluetoothService shellcode"
}

# Mutex
$ChrysalisMutex = "Global\Jdhfv_1.0.1"

# Recon commands observed in chains (Rapid7, Kaspersky)
$SuspiciousCommands = @(
    "whoami&&tasklist",
    "whoami&&tasklist&&systeminfo&&netstat -ano",
    "curl.exe -F `"file=@",
    "curl.exe --user-agent `"https://temp.sh/",
    "-s https://temp.sh/upload",
    "svchost.exe -nostdlib -run",
    "cmd /c whoami >> a.txt",
    "cmd /c tasklist >> a.txt",
    "cmd /c systeminfo >> a.txt",
    "cmd /c netstat -ano >> a.txt"
)

# Additional path rules mapped from signature-base filename IoCs to Rapid7-described behavior.

# ============================================================================

$Findings = [System.Collections.ArrayList]::new()
$CheckExecution = [ordered]@{}
$ScanStartTime = Get-Date
$ScanId = [guid]::NewGuid().Guid
$ScriptVersion = "1.1.2"
$script:CurrentCheckId = 0
$script:CurrentCheckName = "General"

# ============================================================================
# HELPERS
# ============================================================================

function Write-CheckHeader {
    param([int]$Index, [string]$Text)

    Complete-CurrentCheck
    $script:CurrentCheckId = $Index
    $script:CurrentCheckName = $Text

    $checkKey = [string]$Index
    if (-not $CheckExecution.Contains($checkKey)) {
        $CheckExecution[$checkKey] = [ordered]@{
            CheckId      = $Index
            CheckName    = $Text
            StartedAt    = (Get-Date).ToString("o")
            CompletedAt  = $null
            FindingCount = 0
        }
    }
    else {
        $CheckExecution[$checkKey].CheckName = $Text
        if (-not $CheckExecution[$checkKey].StartedAt) {
            $CheckExecution[$checkKey].StartedAt = (Get-Date).ToString("o")
        }
    }

    if (-not $Quiet) {
        Write-Host "`n[$Index/$TotalChecks] $Text" -ForegroundColor Green
    }
}

function Complete-CurrentCheck {
    if ($script:CurrentCheckId -le 0) { return }

    $checkKey = [string]$script:CurrentCheckId
    if ($CheckExecution.Contains($checkKey) -and -not $CheckExecution[$checkKey].CompletedAt) {
        $CheckExecution[$checkKey].CompletedAt = (Get-Date).ToString("o")
    }
}

function Write-Finding {
    param(
        [ValidateSet("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
        [string]$Severity,
        [string]$Category,
        [string]$Message,
        [string]$Details = "",
        [string]$DisplayDetails = ""  # Optional: truncated version for console output
    )

    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "DarkRed" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Cyan" }
        "INFO" { "Gray" }
    }

    # Use DisplayDetails for console if provided, otherwise use Details
    $consoleDetails = if ($DisplayDetails) { $DisplayDetails } else { $Details }

    $findingCheckId = $script:CurrentCheckId
    $findingCheckName = $script:CurrentCheckName
    if ($findingCheckId -gt 0) {
        $checkKey = [string]$findingCheckId
        if ($CheckExecution.Contains($checkKey)) {
            $CheckExecution[$checkKey].FindingCount++
        }
    }

    if (-not $Quiet) {
        Write-Host "  [$Severity] " -ForegroundColor $color -NoNewline
        Write-Host "$Category - " -ForegroundColor White -NoNewline
        Write-Host $Message -ForegroundColor $color
        if ($consoleDetails) {
            Write-Host "            $consoleDetails" -ForegroundColor DarkGray
        }
    }

    # Always store full Details in the findings (for JSON/CSV export)
    [void]$Findings.Add([PSCustomObject]@{
            Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ScanId       = $ScanId
            CheckId      = $findingCheckId
            CheckName    = $findingCheckName
            Severity     = $Severity
            Category     = $Category
            Message      = $Message
            Details      = $Details
            ComputerName = $env:COMPUTERNAME
        })
}

function Expand-Normalize {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    $v = $Value.Trim().Trim('"')
    try { $v = [Environment]::ExpandEnvironmentVariables($v) } catch {}
    return ($v -replace '/', '\').ToLowerInvariant()
}

function Test-DomainIndicatorMatch {
    param(
        [string]$ObservedDomain,
        [string]$IndicatorDomain
    )

    if ([string]::IsNullOrWhiteSpace($ObservedDomain) -or [string]::IsNullOrWhiteSpace($IndicatorDomain)) {
        return $false
    }

    $observed = $ObservedDomain.Trim().Trim('.').ToLowerInvariant()
    $indicator = $IndicatorDomain.Trim().Trim('.').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($observed) -or [string]::IsNullOrWhiteSpace($indicator)) {
        return $false
    }

    return ($observed -eq $indicator -or $observed.EndsWith(".$indicator"))
}

function Get-MatchedMaliciousDomainsFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    $matched = New-Object System.Collections.Generic.HashSet[string]
    $domainPattern = [regex]'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b'

    foreach ($m in $domainPattern.Matches($Text)) {
        $candidate = [string]$m.Value
        foreach ($iocDomain in $MaliciousDomains) {
            if (Test-DomainIndicatorMatch -ObservedDomain $candidate -IndicatorDomain $iocDomain) {
                [void]$matched.Add($iocDomain.ToLowerInvariant())
            }
        }
    }

    return @($matched)
}

function Parse-NetstatEndpoint {
    param([string]$Endpoint)

    if ([string]::IsNullOrWhiteSpace($Endpoint)) { return $null }
    $value = $Endpoint.Trim()

    $bracketMatch = [regex]::Match($value, '^\[(?<Address>[^\]]+)\]:(?<Port>\d+)$')
    if ($bracketMatch.Success) {
        return [PSCustomObject]@{
            Address = $bracketMatch.Groups['Address'].Value
            Port    = [int]$bracketMatch.Groups['Port'].Value
        }
    }

    $plainMatch = [regex]::Match($value, '^(?<Address>[^:]+):(?<Port>\d+)$')
    if ($plainMatch.Success) {
        return [PSCustomObject]@{
            Address = $plainMatch.Groups['Address'].Value
            Port    = [int]$plainMatch.Groups['Port'].Value
        }
    }

    return $null
}

function Get-FirewallLogCandidates {
    $candidates = New-Object System.Collections.Generic.HashSet[string]
    $windir = if ($env:windir) { $env:windir } elseif ($env:SystemRoot) { $env:SystemRoot } else { $null }

    if ($windir) {
        [void]$candidates.Add((Join-Path $windir "System32\LogFiles\Firewall\pfirewall.log"))
        [void]$candidates.Add((Join-Path $windir "System32\LogFiles\Firewall\pfirewall_Domain.log"))
        [void]$candidates.Add((Join-Path $windir "System32\LogFiles\Firewall\pfirewall_Private.log"))
        [void]$candidates.Add((Join-Path $windir "System32\LogFiles\Firewall\pfirewall_Public.log"))
    }

    # Registry-configured log file paths (if set via policy/CSP/GPO)
    $regPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile"
    )

    foreach ($rp in $regPaths) {
        try {
            if (-not (Test-Path -Path $rp)) { continue }
            $val = (Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue).LogFilePath
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            $expanded = $val.Trim().Trim('"')
            try { $expanded = [Environment]::ExpandEnvironmentVariables($expanded) } catch {}
            if (-not [string]::IsNullOrWhiteSpace($expanded)) {
                [void]$candidates.Add($expanded)
            }
        }
        catch {}
    }

    return @($candidates)
}

function Get-FirewallLogFields {
    param([string]$LogPath)

    $fieldsLine = $null
    try {
        $header = Get-Content -Path $LogPath -TotalCount 60 -ErrorAction Stop
        $fieldsLine = $header | Where-Object { $_ -like '#Fields:*' } | Select-Object -Last 1
    }
    catch {}

    if (-not $fieldsLine) { return @() }

    $raw = ($fieldsLine -replace '^#Fields:\s*', '').Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

    $fields = $raw -split '\s+' | Where-Object { $_ }
    return @($fields | ForEach-Object { $_.ToLowerInvariant() })
}

function Parse-FirewallLogLine {
    param(
        [string]$Line,
        [string[]]$Fields,
        [switch]$AllowExtra
    )

    if ([string]::IsNullOrWhiteSpace($Line) -or -not $Fields -or $Fields.Count -eq 0) { return $null }
    $parts = $Line.Trim() -split '\s+'
    if ($parts.Count -lt $Fields.Count) { return $null }

    if (-not $AllowExtra -and $parts.Count -gt $Fields.Count) {
        $head = @()
        if ($Fields.Count -gt 1) {
            $head = $parts[0..($Fields.Count - 2)]
        }
        $tail = ($parts[($Fields.Count - 1)..($parts.Count - 1)] -join ' ')
        $parts = @($head + $tail)
    }

    $map = [ordered]@{}
    for ($i = 0; $i -lt $Fields.Count; $i++) {
        $map[$Fields[$i]] = $parts[$i]
    }
    return $map
}

function Resolve-ExecutablePath {
    param(
        [string]$Value,
        [switch]$TreatAsDirectory
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $v = $Value.Trim()
    try { $v = [Environment]::ExpandEnvironmentVariables($v) } catch {}
    if ([string]::IsNullOrWhiteSpace($v)) { return $null }

    if ($TreatAsDirectory) {
        $dir = $v.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($dir)) { return $null }
        $v = Join-Path -Path $dir -ChildPath "notepad++.exe"
    }
    else {
        $quotedMatch = [regex]::Match($v, '^\s*"([^"]+)"')
        if ($quotedMatch.Success) {
            $v = $quotedMatch.Groups[1].Value
        }
        else {
            $commaMatch = [regex]::Match($v, '^\s*([^,]+?\.exe)\s*(,.*)?$')
            if ($commaMatch.Success) {
                $v = $commaMatch.Groups[1].Value
            }
            else {
                $exeMatch = [regex]::Match($v, '^\s*([^\s]+\.exe)')
                if ($exeMatch.Success) {
                    $v = $exeMatch.Groups[1].Value
                }
            }
        }
        $v = $v.Trim().Trim('"')
        $v = $v -replace ',\s*\d+$', ''
    }

    if ($v -notmatch '(?i)notepad\+\+\.exe$') { return $null }

    try {
        return (Resolve-Path -Path $v -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Path)
    }
    catch {
        if (Test-Path -Path $v -PathType Leaf) { return $v }
    }
    return $null
}

function Get-NotepadInstallCandidates {
    $candidateMap = [ordered]@{}

    function Add-NotepadCandidate {
        param(
            [string]$RawValue,
            [string]$Source,
            [switch]$TreatAsDirectory
        )

        $resolved = Resolve-ExecutablePath -Value $RawValue -TreatAsDirectory:$TreatAsDirectory
        if (-not $resolved) { return }

        $key = Expand-Normalize $resolved
        if (-not $candidateMap.Contains($key)) {
            $candidateMap[$key] = [ordered]@{
                Path             = $resolved
                InstallDirectory = (Split-Path -Path $resolved -Parent)
                Sources          = [System.Collections.ArrayList]::new()
            }
        }

        if (-not $candidateMap[$key].Sources.Contains($Source)) {
            [void]$candidateMap[$key].Sources.Add($Source)
        }
    }

    Add-NotepadCandidate -RawValue "${env:ProgramFiles}\Notepad++\notepad++.exe" -Source "Standard path (ProgramFiles)"
    Add-NotepadCandidate -RawValue "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe" -Source "Standard path (ProgramFiles x86)"
    Add-NotepadCandidate -RawValue "$env:LOCALAPPDATA\Programs\Notepad++\notepad++.exe" -Source "Common per-user install path"
    Add-NotepadCandidate -RawValue "$env:USERPROFILE\scoop\apps\notepadplusplus\current\notepad++.exe" -Source "Scoop path (user profile)"
    Add-NotepadCandidate -RawValue "$env:SCOOP\apps\notepadplusplus\current\notepad++.exe" -Source "Scoop path (SCOOP env var)"
    Add-NotepadCandidate -RawValue "$env:ChocolateyInstall\lib\notepadplusplus\tools\notepad++.exe" -Source "Chocolatey package path"

    $appPathKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad++.exe",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\notepad++.exe",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad++.exe",
        "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\notepad++.exe"
    )

    foreach ($rk in $appPathKeys) {
        try {
            if (-not (Test-Path -Path $rk)) { continue }
            $keyObj = Get-Item -Path $rk -ErrorAction SilentlyContinue
            if (-not $keyObj) { continue }

            Add-NotepadCandidate -RawValue ([string]$keyObj.GetValue("")) -Source "Registry App Paths default: $rk"
            Add-NotepadCandidate -RawValue ([string]$keyObj.GetValue("Path")) -Source "Registry App Paths path: $rk" -TreatAsDirectory
        }
        catch {}
    }

    $uninstallRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($root in $uninstallRoots) {
        try {
            if (-not (Test-Path -Path $root)) { continue }
            Get-ItemProperty -Path "$root\*" -ErrorAction SilentlyContinue | ForEach-Object {
                $displayName = [string]$_.DisplayName
                if ([string]::IsNullOrWhiteSpace($displayName) -or $displayName -notmatch '(?i)^notepad\+\+') { return }

                Add-NotepadCandidate -RawValue ([string]$_.DisplayIcon) -Source "Uninstall DisplayIcon: $root"
                Add-NotepadCandidate -RawValue ([string]$_.InstallLocation) -Source "Uninstall InstallLocation: $root" -TreatAsDirectory
            }
        }
        catch {}
    }

    try {
        Get-Process -Name "notepad++" -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Path) {
                Add-NotepadCandidate -RawValue ([string]$_.Path) -Source "Running process path"
            }
        }
    }
    catch {}

    try {
        $cmd = Get-Command -Name "notepad++.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd -and $cmd.Source) {
            Add-NotepadCandidate -RawValue ([string]$cmd.Source) -Source "PATH lookup"
        }
    }
    catch {}

    $results = foreach ($entry in $candidateMap.Values) {
        [PSCustomObject]@{
            Path             = $entry.Path
            InstallDirectory = $entry.InstallDirectory
            Source           = ($entry.Sources -join "; ")
        }
    }

    return $results | Sort-Object -Property Path
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Get-DefaultOutputPath {
    $desktopCandidates = @(
        "$env:USERPROFILE\Desktop",
        "$env:HOMEDRIVE$env:HOMEPATH\Desktop"
    ) | Where-Object { $_ -and (Test-Path -Path $_ -PathType Container) } | Select-Object -Unique

    if ($desktopCandidates.Count -gt 0) { return $desktopCandidates[0] }
    if ($PSScriptRoot -and (Test-Path -Path $PSScriptRoot -PathType Container)) { return $PSScriptRoot }
    return (Get-Location).Path
}

function Get-SafeFileHash {
    param([string]$FilePath, [ValidateSet("SHA256", "SHA1")] [string]$Algorithm = "SHA256")
    try {
        if (Test-Path -Path $FilePath -PathType Leaf) {
            return (Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop).Hash.ToLower()
        }
    }
    catch { return $null }
    return $null
}

function Test-MutexExists {
    param([string]$MutexName)
    try {
        $m = [System.Threading.Mutex]::OpenExisting($MutexName)
        $m.Close()
        return $true
    }
    catch { return $false }
}

function Get-FileEntropy {
    param([string]$Path, [int]$MaxBytes = 65536)
    try {
        $fi = Get-Item -Path $Path -ErrorAction Stop
        if ($fi.Length -eq 0) { return 0 }

        $toRead = [Math]::Min($fi.Length, $MaxBytes)
        $buf = New-Object byte[] $toRead
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            [void]$fs.Read($buf, 0, $toRead)
        }
        finally {
            $fs.Close()
        }

        $freq = @{}
        foreach ($b in $buf) {
            if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 }
        }

        $entropy = 0.0
        foreach ($f in $freq.Values) {
            $p = $f / $buf.Length
            $entropy -= $p * [Math]::Log($p, 2)
        }
        return [Math]::Round($entropy, 2)
    }
    catch { return $null }
}

function Get-AsciiStrings {
    param([string]$Path, [int]$MaxBytes = 1048576, [int]$MinLen = 4)
    try {
        $fi = Get-Item -Path $Path -ErrorAction Stop
        $toRead = [Math]::Min($fi.Length, $MaxBytes)
        if ($toRead -le 0) { return @() }

        $buf = New-Object byte[] $toRead
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { [void]$fs.Read($buf, 0, $toRead) } finally { $fs.Close() }

        $out = New-Object System.Collections.Generic.List[string]
        $sb = New-Object System.Text.StringBuilder

        foreach ($b in $buf) {
            if ($b -ge 0x20 -and $b -le 0x7E) {
                [void]$sb.Append([char]$b)
            }
            else {
                if ($sb.Length -ge $MinLen) { $out.Add($sb.ToString()) }
                [void]$sb.Clear()
            }
        }
        if ($sb.Length -ge $MinLen) { $out.Add($sb.ToString()) }

        return $out
    }
    catch { return @() }
}

function Test-SuspiciousContent {
    param([string]$Path)

    $patterns = @(
        'whoami.*tasklist',
        'systeminfo.*netstat',
        'curl\.exe.*temp\.sh',
        'curl\.exe.*--user-agent.*temp\.sh',
        'temp\.sh/upload',
        'api\.skycloudcenter\.com',
        'api\.wiresguard\.com',
        'cdncheck\.it\.com',
        'safe-dns\.it\.com',
        'self-dns\.it\.com',
        '45\.76\.155\.202/update/update\.exe',
        '45\.32\.144\.255/update/update\.exe',
        '95\.179\.213\.0/update/(update|install|autoupdater)\.exe',
        'gQ2JR&9;',
        'CRAZY',
        'qwhvb\^435h&\*7',
        'vAuig34%\^325hGV',
        'Global\\Jdhfv',
        '-nostdlib\s+-run'
    )

    foreach ($u in $MaliciousUpdateURLs) {
        if (-not [string]::IsNullOrWhiteSpace($u)) {
            $patterns += [regex]::Escape($u)
        }
    }

    try {
        $fi = Get-Item -Path $Path -ErrorAction Stop
        if ($fi.Length -gt 5MB) { return @() }

        $hits = New-Object System.Collections.Generic.HashSet[string]
        $ext = $fi.Extension.ToLowerInvariant()

        if ($ext -match '\.(txt|ini|bat|cmd|ps1|log)$' -or $ext -eq '') {
            $text = Get-Content -Path $Path -Raw -ErrorAction Stop
            foreach ($p in $patterns) { if ($text -match $p) { [void]$hits.Add($p) } }
        }
        else {
            $strings = Get-AsciiStrings -Path $Path -MaxBytes 1048576 -MinLen 4
            $joined = ($strings -join "`n")
            foreach ($p in $patterns) { if ($joined -match $p) { [void]$hits.Add($p) } }
        }

        return $hits.ToArray()
    }
    catch { return @() }
}

function Get-FileIndicatorScore {
    param([string]$FullPath)

    $p = Expand-Normalize $FullPath
    if ($p -match "\\appdata\\roaming\\bluetooth\\bluetoothservice\.exe") { return "CRITICAL" }
    if ($p -match "\\appdata\\roaming\\bluetooth\\log\.dll") { return "CRITICAL" }
    if ($p -match "\\appdata\\roaming\\bluetooth\\bluetoothservice$") { return "CRITICAL" } # shellcode blob
    if ($p -match "\\programdata\\usoshared\\(conf\.c|libtcc\.dll|svchost\.exe)$") { return "CRITICAL" }
    if ($p -match "\\appdata\\roaming\\proshow\\load$") { return "HIGH" }
    if ($p -match "\\appdata\\roaming\\proshow\\proshow\.exe$") { return "HIGH" } # filename-iocs.txt path rule
    if ($p -match "\\appdata\\roaming\\adobe\\scripts\\alien\.ini$") { return "HIGH" }
    if ($p -match "\\appdata\\roaming\\adobe\\scripts\\script\.exe$") { return "HIGH" } # filename-iocs.txt path rule
    return "INFO"
}

# ============================================================================
# CHECKS
# ============================================================================

function Test-DropDirectories {
    Write-CheckHeader 1 "Checking drop directories (low-FP scoring)..."

    $ruleDetails = @{
        "Bluetooth|log.dll"              = "\\AppData\\Roaming\\Bluetooth\\log\.dll | Score: 75"
        "Bluetooth|BluetoothService.exe" = "\\AppData\\Roaming\\Bluetooth\\BluetoothService\.exe | Score: 75"
        "ProShow|load"                   = "\\AppData\\Roaming\\ProShow\\load$ | Score: 75"
        "ProShow|ProShow.exe"            = "\\AppData\\Roaming\\ProShow\\ProShow\.exe | Score: 75"
        "AdobeScripts|alien.ini"         = "\\AppData\\Roaming\\Adobe\\Scripts\\alien\.ini | Score: 75"
        "AdobeScripts|script.exe"        = "\\AppData\\Roaming\\Adobe\\Scripts\\script.exe | Score: 75"
    }

    foreach ($k in $DropDirs.Keys) {
        $dir = $DropDirs[$k]
        if (-not (Test-Path -Path $dir -PathType Container)) { continue }

        $dirInfo = Get-Item -Path $dir -Force -ErrorAction SilentlyContinue
        $isHidden = $false
        if ($dirInfo) { $isHidden = [bool]($dirInfo.Attributes -band [System.IO.FileAttributes]::Hidden) }

        # Directory existence alone is not a hard IoC (ProShow/Adobe can exist legitimately)
        $sev = switch ($k) {
            "Bluetooth" { if ($isHidden) { "MEDIUM" } else { "INFO" } }
            default { "INFO" }
        }

        Write-Finding -Severity $sev -Category "Directory" `
            -Message "Drop directory present: $dir" `
            -Details "Chain bucket: $k | Hidden: $isHidden (directory alone is not confirmatory)"

        # Look for the high-signal filenames inside each dir
        $targetNames = switch ($k) {
            "Bluetooth" { @("BluetoothService.exe", "log.dll", "BluetoothService", "u.bat") }
            "ProShow" { @("load", "ProShow.exe") }
            "AdobeScripts" { @("alien.ini", "script.exe", "alien.dll", "lua5.1.dll") }
            default { @() }
        }

        foreach ($n in $targetNames) {
            $fp = Join-Path $dir $n
            if (Test-Path -Path $fp -PathType Leaf) {
                $baseSev = Get-FileIndicatorScore -FullPath $fp
                $key = "$k|$n"
                $details = "Path: $fp"
                if ($ruleDetails.ContainsKey($key)) {
                    $details += " | Rule: $($ruleDetails[$key])"
                }

                Write-Finding -Severity $baseSev -Category "File" `
                    -Message "Suspicious artifact present: $n" `
                    -Details $details
            }
        }
    }

    # NSIS runtime temp dirs are common; only log if campaign-relevant names are present.
    $nsisDirs = Get-ChildItem -Path "$env:LOCALAPPDATA\Temp" -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^ns.*\.tmp$' -or $_.Name -eq 'ns.tmp' }

    $nsisIndicators = @(
        "update.exe",
        "[NSIS].nsi",
        "[NSIS.nsi]",
        "BluetoothService.exe",
        "u.bat",
        "log.dll"
    )
    $nsisHitCount = 0

    foreach ($d in $nsisDirs) {
        $hits = Get-ChildItem -Path $d.FullName -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $nsisIndicators -contains $_.Name } |
        Select-Object -ExpandProperty Name -Unique

        if ($hits -and $hits.Count -gt 0) {
            $nsisHitCount++
            Write-Finding -Severity "INFO" -Category "NSIS" `
                -Message "NSIS temp directory contains campaign-relevant filename(s)" `
                -Details "Path: $($d.FullName) | Hits: $($hits -join ', ')"
        }
    }

    if ($nsisDirs -and -not $Quiet -and $nsisHitCount -eq 0) {
        Write-Host "  [OK] NSIS temp directories found, but no campaign-relevant filenames observed" -ForegroundColor Gray
    }
}

function Test-USOSharedPayloads {
    Write-CheckHeader 2 "Checking USOShared for TinyCC secondary payload artifacts..."

    if (-not (Test-Path -Path $USOSharedPath -PathType Container)) {
        if (-not $Quiet) { Write-Host "  [OK] USOShared not present" -ForegroundColor Gray }
        return
    }

    foreach ($f in $USOSharedMaliciousFiles) {
        $p = Join-Path $USOSharedPath $f
        if (Test-Path -Path $p -PathType Leaf) {
            $hash = Get-SafeFileHash -FilePath $p -Algorithm SHA256
            Write-Finding -Severity "CRITICAL" -Category "USOShared" `
                -Message "USOShared artifact present: $f" `
                -Details "Path: $p | SHA256: $hash"
        }
    }

    # filename-iocs.txt-style path rule: \USOShared\[a-zA-Z0-9]{1,15}\.(c|dll|exe)
    Get-ChildItem -Path $USOSharedPath -File -Force -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match '^[a-zA-Z0-9]{1,15}\.(c|dll|exe)$' -and
        ($USOSharedMaliciousFiles -notcontains $_.Name)
    } |
    ForEach-Object {
        Write-Finding -Severity "HIGH" -Category "Path Rule" `
            -Message "USOShared file matches Lotus Blossom suspicious-name rule" `
            -Details "Rule: \\USOShared\\[a-zA-Z0-9]{1,15}\\.(c|dll|exe) | Score: 75 | Path: $($_.FullName)"
    }
}

function Test-FileHashes {
    Write-CheckHeader 3 "Hash verification (high-confidence confirmations)..."
    $libtccLogged = New-Object System.Collections.Generic.HashSet[string]

    $scanRoots = @(
        $DropDirs.ProShow,
        $DropDirs.AdobeScripts,
        $DropDirs.Bluetooth,
        $USOSharedPath,
        "$env:TEMP"
    )

    if ($DeepScan) {
        $scanRoots += @(
            "$env:USERPROFILE\Downloads",
            "$env:PUBLIC\Downloads",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Documents",
            "$env:LOCALAPPDATA\Temp",
            "$env:LOCALAPPDATA\Programs\Notepad++",
            "$env:ProgramFiles\Notepad++",
            "$env:ProgramFiles(x86)\Notepad++",
            "$env:USERPROFILE\scoop\apps\notepadplusplus\current",
            "$env:SCOOP\apps\notepadplusplus\current",
            "$env:ChocolateyInstall\lib\notepadplusplus",
            $ProgramDataRoot
        )
    }

    $scanRoots = $scanRoots | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    # Targeted name-hunt to keep perf + FP sane
    $nameSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($n in ($SuspiciousUpdateNames + @(
                "BluetoothService.exe", "log.dll", "BluetoothService", "u.bat", "conf.c", "libtcc.dll",
                "ConsoleApplication2.exe", "s047t5g.exe", "script.exe", "alien.ini", "load", "alien.dll", "lua5.1.dll",
                "[NSIS].nsi", "[NSIS.nsi]", "admin", "system"
            ))) { [void]$nameSet.Add($n.ToLowerInvariant()) }

    foreach ($root in $scanRoots) {
        try {
            Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $nameSet.Contains($_.Name.ToLowerInvariant()) } |
            ForEach-Object {
                $sha256 = Get-SafeFileHash -FilePath $_.FullName -Algorithm SHA256
                $sha1 = Get-SafeFileHash -FilePath $_.FullName -Algorithm SHA1

                if ($sha256 -and $MaliciousSHA256.ContainsKey($sha256)) {
                    Write-Finding -Severity "CRITICAL" -Category "Hash Match" `
                        -Message "CONFIRMED MALWARE (SHA256): $($MaliciousSHA256[$sha256])" `
                        -Details "File: $($_.FullName)"
                    return
                }

                if ($sha1 -and $MaliciousSHA1.ContainsKey($sha1)) {
                    Write-Finding -Severity "CRITICAL" -Category "Hash Match" `
                        -Message "CONFIRMED MALWARE (SHA1): $($MaliciousSHA1[$sha1])" `
                        -Details "File: $($_.FullName)"
                    return
                }

                if ($_.Name -ieq "libtcc.dll") {
                    $normalizedPath = Expand-Normalize $_.FullName
                    if ($normalizedPath -match "\\programdata\\usoshared\\libtcc\.dll$") { return }
                    if ($libtccLogged.Add($normalizedPath)) {
                        Write-Finding -Severity "MEDIUM" -Category "Path Rule" `
                            -Message "libtcc.dll observed (campaign-associated filename)" `
                            -Details "Rule: \\libtcc\\.dll | Score: 60 | Path: $($_.FullName)"
                    }
                }
                else {
                    # Name hit without hash match -> INFO only
                    Write-Finding -Severity "INFO" -Category "File" `
                        -Message "Suspicious filename observed (hash did not match known IoCs): $($_.Name)" `
                        -Details "Path: $($_.FullName)"
                }
            }
        }
        catch {}
    }

    # Rule coverage backstop for \libtcc\.dll outside targeted filename roots.
    $libtccBackstopRoots = @(
        $ProgramDataRoot,
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:TEMP"
    ) | Where-Object { $_ -and (Test-Path -Path $_ -PathType Container) } | Select-Object -Unique

    foreach ($root in $libtccBackstopRoots) {
        try {
            Get-ChildItem -Path $root -Recurse -File -Filter "libtcc.dll" -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $normalizedPath = Expand-Normalize $_.FullName
                if ($normalizedPath -match "\\programdata\\usoshared\\libtcc\.dll$") { return }
                if (-not $libtccLogged.Add($normalizedPath)) { return }

                Write-Finding -Severity "MEDIUM" -Category "Path Rule" `
                    -Message "libtcc.dll observed (campaign-associated filename)" `
                    -Details "Rule: \\libtcc\\.dll | Score: 60 | Path: $($_.FullName)"
            }
        }
        catch {}
    }
}

function Test-DNSCache {
    Write-CheckHeader 4 "DNS cache for known C2 domains..."

    try {
        $dns = Get-DnsClientCache -ErrorAction Stop
        $seen = New-Object System.Collections.Generic.HashSet[string]

        foreach ($entry in $dns) {
            $domain = [string]$entry.Entry
            if ([string]::IsNullOrWhiteSpace($domain)) { continue }

            $matchedDomains = @()
            foreach ($iocDomain in $MaliciousDomains) {
                if (Test-DomainIndicatorMatch -ObservedDomain $domain -IndicatorDomain $iocDomain) {
                    $matchedDomains += $iocDomain
                }
            }
            if ($matchedDomains.Count -eq 0) { continue }

            $key = "$($domain.ToLowerInvariant())|$($entry.Data)"
            if (-not $seen.Add($key)) { continue }

            # DNS cache alone is a weak signal -> HIGH (not CRITICAL)
            Write-Finding -Severity "HIGH" -Category "DNS" `
                -Message "Suspicious domain in DNS cache: $domain" `
                -Details "MatchedDomains: $($matchedDomains -join ', ') | ResolvedTo: $($entry.Data) | Correlate with file/persistence IoCs"
        }
        if (-not $Quiet -and $seen.Count -eq 0) {
            Write-Host "  [OK] No known malicious domains in DNS cache" -ForegroundColor Gray
        }
    }
    catch {
        Write-Finding -Severity "INFO" -Category "DNS" `
            -Message "Could not query DNS cache" -Details $_.Exception.Message
    }
}

function Test-NetworkConnections {
    Write-CheckHeader 5 "Active TCP connections to known IoC IPs..."

    $reportedConnections = New-Object System.Collections.Generic.HashSet[string]
    $usedFallback = $false

    try {
        if (-not (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
            throw "Get-NetTCPConnection is unavailable"
        }

        $conns = Get-NetTCPConnection -State Established -ErrorAction Stop
        foreach ($ip in $MaliciousIPs) {
            $hits = $conns | Where-Object { $_.RemoteAddress -eq $ip }
            foreach ($c in $hits) {
                $entryKey = "$ip|$($c.OwningProcess)|$($c.RemotePort)|Get-NetTCPConnection"
                if (-not $reportedConnections.Add($entryKey)) { continue }

                $procName = $null
                try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Name } catch {}
                Write-Finding -Severity "CRITICAL" -Category "Network" `
                    -Message "ACTIVE CONNECTION to IoC IP: $ip" `
                    -Details "Source: Get-NetTCPConnection | RemotePort: $($c.RemotePort) | PID: $($c.OwningProcess) | Process: $procName"
            }
        }
    }
    catch {
        $primaryError = $_.Exception.Message
        $usedFallback = $true

        if (-not $Quiet) {
            Write-Host "  [INFO] Get-NetTCPConnection unavailable/failed, falling back to netstat parsing" -ForegroundColor DarkGray
        }

        try {
            $netstatLines = & netstat -ano -p tcp 2>$null
            if (-not $netstatLines) { throw "netstat returned no TCP data" }

            foreach ($line in $netstatLines) {
                $trimmed = [string]$line
                if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
                $parts = $trimmed.Trim() -split '\s+'
                if ($parts.Count -lt 5) { continue }
                if ($parts[0] -ine "TCP") { continue }
                if ($parts[3] -ine "ESTABLISHED") { continue }

                $remote = Parse-NetstatEndpoint -Endpoint $parts[2]
                if (-not $remote) { continue }

                $remoteAddress = [string]$remote.Address
                if ([string]::IsNullOrWhiteSpace($remoteAddress)) { continue }
                if ($remoteAddress.Contains('%')) { $remoteAddress = $remoteAddress.Split('%')[0] }

                if ($MaliciousIPs -notcontains $remoteAddress) { continue }

                $owningProcessId = 0
                [void][int]::TryParse([string]$parts[4], [ref]$owningProcessId)
                $entryKey = "$remoteAddress|$owningProcessId|$($remote.Port)|netstat"
                if (-not $reportedConnections.Add($entryKey)) { continue }

                $procName = $null
                if ($owningProcessId -gt 0) {
                    try { $procName = (Get-Process -Id $owningProcessId -ErrorAction SilentlyContinue).Name } catch {}
                }

                Write-Finding -Severity "CRITICAL" -Category "Network" `
                    -Message "ACTIVE CONNECTION to IoC IP: $remoteAddress" `
                    -Details "Source: netstat | RemotePort: $($remote.Port) | PID: $owningProcessId | Process: $procName"
            }
        }
        catch {
            $fallbackError = $_.Exception.Message
            Write-Finding -Severity "INFO" -Category "Network" `
                -Message "Could not query active network connections" `
                -Details "Get-NetTCPConnectionError: $primaryError | NetstatFallbackError: $fallbackError"
        }
    }

    if ($DeepScan) {
        try {
            $maxLines = 8000
            $maxFindings = 20
            $lineDedup = New-Object System.Collections.Generic.HashSet[string]
            $firewallFindings = 0

            $logCandidates = Get-FirewallLogCandidates | Select-Object -Unique
            $logPaths = $logCandidates | Where-Object { $_ -and (Test-Path -Path $_ -PathType Leaf) } | Select-Object -Unique
            if (-not $logPaths -or $logPaths.Count -eq 0) {
                $checked = $logCandidates -join '; '
                Write-Finding -Severity "INFO" -Category "Firewall Log" `
                    -Message "Windows Firewall log not found (deep history check skipped)" `
                    -Details "Checked: $checked | Logging may be disabled or path customized"
                return
            }

            foreach ($logPath in $logPaths) {
                if ($firewallFindings -ge $maxFindings) { break }

                $fields = Get-FirewallLogFields -LogPath $logPath
                $allowExtra = $false
                if (-not $fields -or $fields.Count -eq 0) {
                    $fields = @("date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port")
                    $allowExtra = $true
                }

                $recentLines = Get-Content -Path $logPath -Tail $maxLines -ErrorAction Stop
                foreach ($rawLine in $recentLines) {
                    if ($firewallFindings -ge $maxFindings) { break }

                    $line = [string]$rawLine
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    if ($line.TrimStart().StartsWith("#")) { continue }

                    $entry = Parse-FirewallLogLine -Line $line -Fields $fields -AllowExtra:$allowExtra
                    if (-not $entry) { continue }

                    $srcIp = if ($entry.Contains("src-ip")) { $entry["src-ip"] } elseif ($entry.Contains("srcip")) { $entry["srcip"] } else { $null }
                    $dstIp = if ($entry.Contains("dst-ip")) { $entry["dst-ip"] } elseif ($entry.Contains("dstip")) { $entry["dstip"] } else { $null }

                    $matchedIp = $null
                    $direction = $null
                    if ($srcIp -and ($MaliciousIPs -contains $srcIp)) {
                        $matchedIp = $srcIp
                        $direction = "Source"
                    }
                    elseif ($dstIp -and ($MaliciousIPs -contains $dstIp)) {
                        $matchedIp = $dstIp
                        $direction = "Destination"
                    }
                    if (-not $matchedIp) { continue }

                    $date = if ($entry.Contains("date")) { $entry["date"] } else { "" }
                    $time = if ($entry.Contains("time")) { $entry["time"] } else { "" }
                    $action = if ($entry.Contains("action")) { $entry["action"] } else { "" }
                    $proto = if ($entry.Contains("protocol")) { $entry["protocol"] } else { "" }
                    $srcPort = if ($entry.Contains("src-port")) { $entry["src-port"] } elseif ($entry.Contains("srcport")) { $entry["srcport"] } else { "" }
                    $dstPort = if ($entry.Contains("dst-port")) { $entry["dst-port"] } elseif ($entry.Contains("dstport")) { $entry["dstport"] } else { "" }
                    $info = if ($entry.Contains("info")) { $entry["info"] } else { "" }
                    $path = if ($entry.Contains("path")) { $entry["path"] } else { "" }

                    $profileMatch = [regex]::Match($logPath, 'pfirewall_(Domain|Private|Public)\.log', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    $firewallProfileName = if ($profileMatch.Success) { $profileMatch.Groups[1].Value } else { "Default" }
                    $entryKey = "$logPath|$matchedIp|$direction|$date|$time|$action|$proto|$srcIp|$dstIp|$srcPort|$dstPort"
                    if (-not $lineDedup.Add($entryKey)) { continue }

                    $detailParts = @(
                        "Source: WindowsFirewallLog",
                        "Profile: $firewallProfileName",
                        "LogPath: $logPath",
                        "Direction: $direction",
                        "Entry: $date $time $action $proto ${srcIp}:$srcPort -> ${dstIp}:$dstPort"
                    )
                    if (-not [string]::IsNullOrWhiteSpace($info)) { $detailParts += "Info: $info" }
                    if (-not [string]::IsNullOrWhiteSpace($path)) { $detailParts += "AppPath: $path" }

                    Write-Finding -Severity "MEDIUM" -Category "Firewall Log" `
                        -Message "Historical firewall log match for IoC IP: $matchedIp" `
                        -Details ($detailParts -join " | ")
                    $firewallFindings++
                }
            }

            if (-not $Quiet -and $firewallFindings -eq 0) {
                Write-Host "  [OK] No IoC IP hits in recent Windows Firewall log history" -ForegroundColor Gray
            }
        }
        catch {
            Write-Finding -Severity "INFO" -Category "Firewall Log" `
                -Message "Could not parse Windows Firewall history log" `
                -Details $_.Exception.Message
        }
    }
    elseif (-not $Quiet -and $usedFallback) {
        Write-Host "  [OK] Network check completed using netstat fallback" -ForegroundColor Gray
    }
}

function Test-ChrysalisMutex {
    Write-CheckHeader 6 "Mutex check (Chrysalis single-instance)..."

    if (Test-MutexExists -MutexName $ChrysalisMutex) {
        Write-Finding -Severity "CRITICAL" -Category "Mutex" `
            -Message "CHRYSALIS MUTEX PRESENT (strong runtime indicator)" `
            -Details "Mutex: $ChrysalisMutex"
    }
    elseif (-not $Quiet) {
        Write-Host "  [OK] Mutex not detected" -ForegroundColor Gray
    }
}

function Test-RunningProcesses {
    Write-CheckHeader 7 "Running process checks (path-based)..."

    $targets = @("BluetoothService", "ProShow", "script", "tcc", "alien", "GUP")
    foreach ($t in $targets) {
        $procs = Get-Process -Name "$t*" -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            $path = $null
            try { $path = $p.Path } catch { $path = $null }

            if (-not $path) {
                # Missing path is common under limited perms -> INFO only
                Write-Finding -Severity "INFO" -Category "Process" `
                    -Message "Process present (path unavailable): $($p.Name)" `
                    -Details "PID: $($p.Id)"
                continue
            }

            $np = Expand-Normalize $path

            if ($np -match "\\appdata\\roaming\\bluetooth\\bluetoothservice\.exe") {
                Write-Finding -Severity "CRITICAL" -Category "Process" `
                    -Message "BluetoothService.exe running from AppData\Bluetooth" `
                    -Details "PID: $($p.Id) | Path: $path"
            }
            elseif ($np -match "\\programdata\\usoshared\\") {
                Write-Finding -Severity "CRITICAL" -Category "Process" `
                    -Message "Suspicious process executing from USOShared" `
                    -Details "PID: $($p.Id) | Path: $path"
            }
            elseif ($np -match "\\appdata\\roaming\\(proshow|adobe\\scripts)\\") {
                # could be legit software, but suspicious in this campaign context -> MEDIUM
                Write-Finding -Severity "MEDIUM" -Category "Process" `
                    -Message "Process executing from chain-associated AppData path: $($p.Name)" `
                    -Details "PID: $($p.Id) | Path: $path"
            }
        }
    }
}

function Test-RegistryPersistence {
    Write-CheckHeader 8 "Registry Run/RunOnce persistence (FP-mitigated)..."

    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    # Allowlist: common legitimate updater autoruns (we only INFO-log if someone searches for update.exe)
    $knownLegitUpdaterRegex = @(
        "\\microsoft\\teams\\update\.exe",
        "\\microsoft\\edgeupdate\\",
        "\\google\\update\\",
        "\\mozilla\\maintenanceservice",
        "\\discord\\update\.exe",
        "\\slack\\update\.exe"
    )

    foreach ($key in $runKeys) {
        if (-not (Test-Path -Path $key)) { continue }

        $vals = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        foreach ($prop in $vals.PSObject.Properties) {
            if ($prop.Name -match "^PS") { continue }
            $raw = [string]$prop.Value
            $v = Expand-Normalize $raw

            if ([string]::IsNullOrWhiteSpace($v)) { continue }

            # High-signal: BluetoothService persistence with -i / -k flags (Rapid7)
            if ($v -match "\\appdata\\roaming\\bluetooth\\bluetoothservice\.exe") {
                $sev = if ($v -match "\s-\w") {
                    if ($v -match "\s-i" -or $v -match "\s-k") { "CRITICAL" } else { "HIGH" }
                }
                else { "HIGH" }

                Write-Finding -Severity $sev -Category "Persistence (RunKey)" `
                    -Message "Suspicious Run entry points to AppData\Bluetooth\BluetoothService.exe" `
                    -Details "Key: $key | Name: $($prop.Name) | Value: $raw"
                continue
            }

            # Medium-signal: chain paths in autorun (rare legit, but possible)
            if ($v -match "\\appdata\\roaming\\proshow\\" -or $v -match "\\appdata\\roaming\\adobe\\scripts\\") {
                Write-Finding -Severity "MEDIUM" -Category "Persistence (RunKey)" `
                    -Message "Autorun references chain-associated AppData path (investigate origin)" `
                    -Details "Key: $key | Name: $($prop.Name) | Value: $raw"
                continue
            }

            # If "update.exe" appears: do NOT treat as malicious by itself (Teams etc.)
            if ($v -match "\\update\.exe") {
                $isLegit = $false
                foreach ($r in $knownLegitUpdaterRegex) { if ($v -match $r) { $isLegit = $true; break } }

                Write-Finding -Severity "INFO" -Category "Autorun (Update.exe)" `
                    -Message "Autorun uses update.exe (often legitimate; not a Chrysalis confirmatory IoC)" `
                    -Details "LegitLikely: $isLegit | Key: $key | Name: $($prop.Name) | Value: $raw"
                continue
            }
        }
    }
}

function Test-ScheduledTasks {
    Write-CheckHeader 9 "Scheduled tasks persistence (path-based)..."

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            foreach ($a in $t.Actions) {
                $exec = Expand-Normalize ([string]$a.Execute)
                $args = Expand-Normalize ([string]$a.Arguments)

                if ([string]::IsNullOrWhiteSpace($exec) -and [string]::IsNullOrWhiteSpace($args)) { continue }

                if ($exec -match "\\appdata\\roaming\\bluetooth\\bluetoothservice\.exe" -or
                    $exec -match "\\appdata\\roaming\\proshow\\" -or
                    $exec -match "\\appdata\\roaming\\adobe\\scripts\\") {

                    $sev = if ($exec -match "\\bluetooth\\bluetoothservice\.exe") { "CRITICAL" } else { "MEDIUM" }

                    Write-Finding -Severity $sev -Category "Scheduled Task" `
                        -Message "Task action executes from chain-associated AppData path" `
                        -Details "Task: $($t.TaskName) | Exec: $($a.Execute) | Args: $($a.Arguments)"
                }

                # campaign command patterns -> MEDIUM signal
                foreach ($cmd in $SuspiciousCommands) {
                    $c = $cmd.ToLowerInvariant()
                    if ($args -like "*$c*" -or $exec -like "*$c*") {
                        Write-Finding -Severity "MEDIUM" -Category "Scheduled Task" `
                            -Message "Task contains suspicious command pattern (campaign-related)" `
                            -Details "Task: $($t.TaskName) | Pattern: $cmd | Exec: $($a.Execute) | Args: $($a.Arguments)"
                    }
                }
            }
        }

        if (-not $Quiet) { Write-Host "  [OK] Task scan complete" -ForegroundColor Gray }
    }
    catch {
        Write-Finding -Severity "INFO" -Category "Scheduled Task" `
            -Message "Could not query scheduled tasks" -Details $_.Exception.Message
    }
}

function Test-HostsFile {
    Write-CheckHeader 10 "Hosts file for known C2 domains (blocking-aware)..."

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $pat = ($MaliciousDomains | ForEach-Object { [regex]::Escape($_) }) -join '|'

    try {
        $hits = Select-String -Path $hostsPath -Pattern $pat -ErrorAction SilentlyContinue
        foreach ($h in $hits) {
            $line = $h.Line.Trim()
            $isBlocking = $line -match '^(127\.0\.0\.1|0\.0\.0\.0)\s+'
            $sev = if ($isBlocking) { "INFO" } else { "HIGH" }

            Write-Finding -Severity $sev -Category "Hosts File" `
                -Message "C2 domain present in hosts file" `
                -Details "BlockingLikely: $isBlocking | Line: $line"
        }

        if (-not $hits -and -not $Quiet) { Write-Host "  [OK] No C2 domains in hosts file" -ForegroundColor Gray }
    }
    catch {
        Write-Finding -Severity "INFO" -Category "Hosts File" `
            -Message "Could not read hosts file" -Details $_.Exception.Message
    }
}

function Test-NotepadVersion {
    Write-CheckHeader 11 "Notepad++ install discovery + signature sanity..."

    $nppExe = Get-NotepadInstallCandidates

    if (-not $nppExe -or $nppExe.Count -eq 0) {
        if (-not $Quiet) { Write-Host "  [OK] Notepad++ not found in discovered install locations" -ForegroundColor Gray }
        return
    }

    foreach ($candidate in $nppExe) {
        $path = $candidate.Path
        $source = $candidate.Source
        $installDir = $candidate.InstallDirectory

        $vi = $null
        try { $vi = (Get-Item -Path $path -ErrorAction Stop).VersionInfo } catch {}

        Write-Finding -Severity "INFO" -Category "Notepad++" `
            -Message "Detected Notepad++ installation candidate" `
            -Details "Path: $path | InstallDir: $installDir | Version: $($vi.FileVersion) | Discovery: $source"

        # Notepad++ project statement: v8.8.9 introduced stronger updater verification.
        if ($vi -and $vi.FileVersion) {
            try {
                $parsed = [version]($vi.FileVersion -replace '[^0-9\.].*$', '')
                if ($parsed -lt [version]'8.8.9') {
                    Write-Finding -Severity "MEDIUM" -Category "Notepad++" `
                        -Message "Notepad++ version predates updater hardening (v8.8.9)" `
                        -Details "DetectedVersion: $($vi.FileVersion) | Recommendation: upgrade to a current version from the official Notepad++ site"
                }
            }
            catch {}
        }

        try {
            $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
            $sev = if ($sig.Status -eq 'Valid') { "INFO" } else { "MEDIUM" }
            $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "[no signer certificate]" }
            Write-Finding -Severity $sev -Category "Signature" `
                -Message "Authenticode signature status: $($sig.Status)" `
                -Details "File: $path | Subject: $subject"
        }
        catch {
            Write-Finding -Severity "INFO" -Category "Signature" `
                -Message "Could not evaluate Authenticode signature" `
                -Details "File: $path | $($_.Exception.Message)"
        }

        # Also check GUP.exe if present
        $gupPath = Join-Path (Split-Path $path -Parent) "GUP.exe"
        if (Test-Path $gupPath) {
            try {
                $sig2 = Get-AuthenticodeSignature -FilePath $gupPath -ErrorAction Stop
                $sev2 = if ($sig2.Status -eq 'Valid') { "INFO" } else { "MEDIUM" }
                $subject2 = if ($sig2.SignerCertificate) { $sig2.SignerCertificate.Subject } else { "[no signer certificate]" }
                Write-Finding -Severity $sev2 -Category "Signature" `
                    -Message "GUP.exe signature status: $($sig2.Status)" `
                    -Details "File: $gupPath | Subject: $subject2"
            }
            catch {}
        }
    }

    $securityLogPath = Join-Path $env:LOCALAPPDATA "Notepad++\log\securityError.log"
    if (Test-Path -Path $securityLogPath -PathType Leaf) {
        Write-Finding -Severity "INFO" -Category "Notepad++ Security Log" `
            -Message "Notepad++ securityError.log present" `
            -Details "Path: $securityLogPath | Presence alone is not malicious"

        try {
            $tailLines = Get-Content -Path $securityLogPath -Tail 300 -ErrorAction Stop
            $matchedDomains = New-Object System.Collections.Generic.HashSet[string]
            $matchedUrls = New-Object System.Collections.Generic.HashSet[string]
            $contextLines = New-Object System.Collections.Generic.List[string]

            foreach ($line in $tailLines) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }

                foreach ($dom in (Get-MatchedMaliciousDomainsFromText -Text $line)) {
                    [void]$matchedDomains.Add($dom)
                }

                $lineLower = $line.ToLowerInvariant()
                foreach ($u in $MaliciousUpdateURLs) {
                    $urlLower = $u.ToLowerInvariant()
                    if ($lineLower.Contains($urlLower)) {
                        [void]$matchedUrls.Add($u)
                    }
                }

                if (($matchedDomains.Count -gt 0 -or $matchedUrls.Count -gt 0) -and $contextLines.Count -lt 5) {
                    $preview = ($line -replace '[\r\n]+', ' ').Trim()
                    if ($preview.Length -gt 180) { $preview = $preview.Substring(0, 180) + "..." }
                    $contextLines.Add($preview)
                }
            }

            if ($matchedDomains.Count -gt 0 -or $matchedUrls.Count -gt 0) {
                Write-Finding -Severity "MEDIUM" -Category "Notepad++ Security Log" `
                    -Message "securityError.log contains campaign-related domain/URL indicators" `
                    -Details "Path: $securityLogPath | MatchedDomains: $(@($matchedDomains) -join ', ') | MatchedURLs: $(@($matchedUrls) -join ', ') | Context: $(@($contextLines) -join ' | ')"
            }
            elseif (-not $Quiet) {
                Write-Host "  [OK] securityError.log present but no campaign IoCs found in recent entries" -ForegroundColor Gray
            }
        }
        catch {
            Write-Finding -Severity "INFO" -Category "Notepad++ Security Log" `
                -Message "Could not parse securityError.log entries" `
                -Details "Path: $securityLogPath | $($_.Exception.Message)"
        }
    }
}

function Test-ExfilArtifacts {
    Write-CheckHeader 12 "Exfil/recon staging artifacts..."

    $ruleTargets = @(
        @{
            Path = $DropDirs.ProShow
            Rule = "\\AppData\\Roaming\\ProShow\\[a-zA-Z0-9]{1}\.txt"
        },
        @{
            Path = $DropDirs.AdobeScripts
            Rule = "\\AppData\\Roaming\\Adobe\\Scripts\\[a-zA-Z0-9]{1}\.txt"
        }
    )

    foreach ($target in $ruleTargets) {
        if (-not (Test-Path -Path $target.Path -PathType Container)) { continue }

        Get-ChildItem -Path $target.Path -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^[a-zA-Z0-9]{1}\.txt$' } |
        ForEach-Object {
            $preview = Get-Content -Path $_.FullName -First 15 -ErrorAction SilentlyContinue
            $s = ($preview -join " ")
            $containsRecon = $s -match "(whoami|tasklist|systeminfo|netstat)"

            $sev = if ($containsRecon) { "HIGH" } else { "MEDIUM" }
            $msg = if ($containsRecon) {
                "Single-character staging file with recon content detected"
            }
            else {
                "Single-character staging filename detected (campaign path rule match)"
            }

            Write-Finding -Severity $sev -Category "Exfiltration" `
                -Message $msg `
                -Details "Rule: $($target.Rule) | Score: 75 | Path: $($_.FullName)"
        }
    }

    $ubat = Join-Path $DropDirs.Bluetooth "u.bat"
    if (Test-Path $ubat) {
        Write-Finding -Severity "HIGH" -Category "Cleanup" `
            -Message "u.bat present (self-removal mechanism observed in campaign)" `
            -Details "Path: $ubat"
    }
}

function Get-EventMessageText {
    param([object]$EventRecord)

    $msg = $null
    try { $msg = $EventRecord.FormatDescription() } catch {}
    if ([string]::IsNullOrWhiteSpace($msg)) {
        try { $msg = [string]$EventRecord.Message } catch {}
    }
    if ([string]::IsNullOrWhiteSpace($msg)) {
        try { $msg = [string]$EventRecord.ToXml() } catch {}
    }
    return $msg
}

function Get-EventDataMap {
    param([object]$EventRecord)

    $map = [ordered]@{}
    try {
        [xml]$xml = $EventRecord.ToXml()
        $idx = 0

        foreach ($d in @($xml.Event.EventData.Data)) {
            if ($null -eq $d) { continue }

            $name = [string]$d.Name
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = "Data$idx"
                $idx++
            }

            $val = [string]$d.'#text'
            if (-not [string]::IsNullOrWhiteSpace($val) -and -not $map.Contains($name)) {
                $map[$name] = $val.Trim()
            }
        }

        if ($xml.Event.UserData) {
            foreach ($root in @($xml.Event.UserData.ChildNodes)) {
                foreach ($child in @($root.ChildNodes)) {
                    if ($null -eq $child) { continue }

                    $name = "UserData.$($child.LocalName)"
                    $val = [string]$child.InnerText
                    if (-not [string]::IsNullOrWhiteSpace($val) -and -not $map.Contains($name)) {
                        $map[$name] = $val.Trim()
                    }
                }
            }
        }
    }
    catch {}

    return $map
}

function Get-EventIndicatorMatches {
    param(
        [string]$Text,
        [array]$IndicatorRules
    )

    # Avoid the built-in automatic $Matches variable and keep a plain object[] output
    # for best compatibility with Windows PowerShell 5.1.
    $indicatorHits = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $IndicatorRules) {
        $regexMatch = [regex]::Match($Text, [string]$rule.Regex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($regexMatch.Success) {
            $sample = [string]$regexMatch.Value
            if ($sample.Length -gt 120) { $sample = $sample.Substring(0, 120) + "..." }
            [void]$indicatorHits.Add([PSCustomObject]@{
                    Name        = $rule.Name
                    Pattern     = [string]$rule.Regex
                    Weight      = $rule.Weight
                    MatchSample = $sample
                })
        }
    }

    $allHits = @($indicatorHits.ToArray())
    $strong = @($allHits | Where-Object { $_.Weight -ge 80 } | Select-Object -ExpandProperty Name -Unique)
    $medium = @($allHits | Where-Object { $_.Weight -lt 80 } | Select-Object -ExpandProperty Name -Unique)
    $isMatch = ($strong.Count -ge 1) -or ($medium.Count -ge 2)

    return [PSCustomObject]@{
        IsMatch = $isMatch
        Strong  = $strong
        Medium  = $medium
        All     = $allHits
    }
}

function Test-EventLogs {
    Write-CheckHeader 13 "Event log sweep (MEDIUM signal, not confirmatory)..."

    if (-not (Get-Command -Name Get-WinEvent -ErrorAction SilentlyContinue)) {
        Write-Finding -Severity "INFO" -Category "Event Log" `
            -Message "Get-WinEvent is unavailable in this PowerShell session" `
            -Details "Event log check skipped"
        return
    }

    $indicatorRules = @(
        @{ Name = "Bluetooth AppData execution path"; Weight = 100; Regex = '\\appdata\\roaming\\bluetooth\\(?:bluetoothservice\.exe|log\.dll|bluetoothservice\b)' },
        @{ Name = "USOShared payload path"; Weight = 100; Regex = '\\programdata\\usoshared\\(?:conf\.c|libtcc\.dll|svchost\.exe)' },
        @{ Name = "ProShow exploit path"; Weight = 85; Regex = '\\appdata\\roaming\\proshow\\(?:load|proshow\.exe)' },
        @{ Name = "Adobe Scripts loader path"; Weight = 85; Regex = '\\appdata\\roaming\\adobe\\scripts\\(?:alien\.ini|script\.exe)' },
        @{ Name = "Chrysalis mutex reference"; Weight = 100; Regex = 'global\\jdhfv_1\.0\.1' },
        @{ Name = "temp.sh exfil upload"; Weight = 90; Regex = 'temp\.sh/upload|curl\.exe\s+-f\s+\"?file=@' },
        # Domain text by itself is often noisy in logs, keep this as supportive evidence only.
        @{ Name = "Known C2 domain"; Weight = 55; Regex = 'api\.skycloudcenter\.com|api\.wiresguard\.com|cdncheck\.it\.com|safe-dns\.it\.com|self-dns\.it\.com' },
        @{ Name = "Known update URL pattern"; Weight = 85; Regex = '45\.76\.155\.202/update/(?:update|install|autoupdater)\.exe|45\.32\.144\.255/update/update\.exe|95\.179\.213\.0/update/(?:update|install|autoupdater)\.exe' },
        @{ Name = "Recon command chain"; Weight = 70; Regex = 'whoami&&tasklist(?:&&systeminfo&&netstat\s+-ano)?' },
        @{ Name = "Split recon command"; Weight = 70; Regex = 'cmd\s+/c\s+(?:whoami|tasklist|systeminfo|netstat\s+-ano)\s*>>\s*a\.txt' },
        @{ Name = "Campaign artifact filename"; Weight = 65; Regex = '\b(?:bluetoothservice\.exe|log\.dll|alien\.ini|script\.exe|libtcc\.dll|conf\.c|u\.bat|s047t5g\.exe|consoleapplication2\.exe)\b' }
    )

    $logQueries = @(
        @{
            LogName = "Microsoft-Windows-PowerShell/Operational"
            EventIds = @(4103, 4104, 4105, 4106)
        },
        @{
            LogName = "Windows PowerShell"
            EventIds = @(800)
        },
        @{
            LogName = "System"
            EventIds = @(7045)
            Providers = @("Service Control Manager")
            QueryType = "Generic"
        },
        @{
            LogName = "Microsoft-Windows-DNS-Client/Operational"
            QueryType = "DNSClient"
        }
    )

    if ($DeepScan) {
        $logQueries += @(
            @{
                LogName = "Microsoft-Windows-TaskScheduler/Operational"
                EventIds = @(106, 140, 141, 200, 201)
                QueryType = "Generic"
            },
            @{
                LogName = "Microsoft-Windows-Sysmon/Operational"
                EventIds = @(1, 3, 7, 11, 13, 22)
                QueryType = "Generic"
            },
            @{
                LogName = "Security"
                EventIds = @(4688)
                QueryType = "Generic"
            },
            @{
                LogName = "Application"
                EventIds = @(1000, 1001)
                QueryType = "Generic"
            }
        )
    }

    # Patterns to exclude (self-references from this scanner)
    $excludePatterns = @(
        "Detect-Chrysalis",
        "ChrysalisScan",
        "Chrysalis/Lotus Blossom.*IoC Scanner",
        "Write-Finding.*-Severity",
        "Test-EventLogs",
        "\$logQueries\s*=",
        "function\s+Test-"
    )

    $maxEvents = if ($DeepScan) { 5000 } else { 2000 }
    $maxFindingsPerLog = if ($DeepScan) { 35 } else { 12 }
    $lookbackDays = if ($DeepScan) { 730 } else { 365 }
    $startTime = (Get-Date).AddDays(-$lookbackDays)

    foreach ($q in $logQueries) {
        $logName = [string]$q.LogName

        try {
            $logInfo = Get-WinEvent -ListLog $logName -ErrorAction Stop
            if (-not $logInfo.IsEnabled) {
                if (-not $Quiet) { Write-Host "  [INFO] Skipping disabled log: $logName" -ForegroundColor DarkGray }
                continue
            }
        }
        catch {
            if (-not $Quiet) { Write-Host "  [INFO] Could not access log metadata: $logName | $($_.Exception.Message)" -ForegroundColor DarkGray }
            continue
        }

        try {
            $filter = @{
                LogName = $logName
                StartTime = $startTime
            }
            if ($q.EventIds -and $q.EventIds.Count -gt 0) { $filter.Id = $q.EventIds }
            if ($q.Providers) { $filter.ProviderName = $q.Providers }

            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $maxEvents -ErrorAction Stop
        }
        catch {
            if (-not $Quiet) { Write-Host "  [INFO] Could not query $logName | $($_.Exception.Message)" -ForegroundColor DarkGray }
            continue
        }

        $findingsInLog = 0

        foreach ($e in $events) {
            if ($findingsInLog -ge $maxFindingsPerLog) { break }

            $msg = Get-EventMessageText -EventRecord $e

            $xml = $null
            try { $xml = $e.ToXml() } catch {}
            $dataMap = Get-EventDataMap -EventRecord $e

            $searchText = @($msg, $xml) -join "`n"
            if ([string]::IsNullOrWhiteSpace($searchText)) { continue }

            if ($q.QueryType -eq "DNSClient") {
                $queryFieldCandidates = @("QueryName", "Query", "Name", "HostName", "TargetName", "UserData.QueryName", "UserData.Query", "UserData.Name")
                $queryValues = New-Object System.Collections.Generic.List[object]

                foreach ($field in $queryFieldCandidates) {
                    if ($dataMap.Contains($field)) {
                        $fieldValue = [string]$dataMap[$field]
                        if ([string]::IsNullOrWhiteSpace($fieldValue)) { continue }

                        $exists = $false
                        foreach ($existing in $queryValues) {
                            if ($existing.Field -eq $field -and $existing.Value -eq $fieldValue) { $exists = $true; break }
                        }
                        if (-not $exists) {
                            $queryValues.Add([PSCustomObject]@{
                                    Field = $field
                                    Value = $fieldValue
                                })
                        }
                    }
                }

                if ($queryValues.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($msg)) {
                    foreach ($dom in (Get-MatchedMaliciousDomainsFromText -Text $msg)) {
                        $queryValues.Add([PSCustomObject]@{ Field = "MessageExtract"; Value = $dom })
                    }
                }

                $matchedDomains = New-Object System.Collections.Generic.HashSet[string]
                $matchedEvidence = New-Object System.Collections.Generic.List[string]

                foreach ($queryItem in $queryValues) {
                    $domainCandidates = New-Object System.Collections.Generic.HashSet[string]
                    $qv = ([string]$queryItem.Value).Trim()
                    $sourceField = [string]$queryItem.Field
                    if (-not [string]::IsNullOrWhiteSpace($qv)) {
                        [void]$domainCandidates.Add($qv.Trim('.'))
                    }

                    $domainsInValue = Get-MatchedMaliciousDomainsFromText -Text $qv
                    foreach ($domainInValue in $domainsInValue) {
                        [void]$domainCandidates.Add($domainInValue)
                    }

                    foreach ($candidateDomain in $domainCandidates) {
                        foreach ($iocDomain in $MaliciousDomains) {
                            if (-not (Test-DomainIndicatorMatch -ObservedDomain $candidateDomain -IndicatorDomain $iocDomain)) { continue }

                            [void]$matchedDomains.Add($iocDomain)
                            if ($matchedEvidence.Count -lt 4) {
                                $evidence = "Field=$sourceField Pattern=$iocDomain Value=$qv"
                                if (-not $matchedEvidence.Contains($evidence)) {
                                    $matchedEvidence.Add($evidence)
                                }
                            }
                        }
                    }
                }

                if ($matchedDomains.Count -eq 0) { continue }

                $contextItems = @(
                    $queryValues |
                    Select-Object -First 3 |
                    ForEach-Object { "$($_.Field)=$($_.Value)" }
                )
                $contextStr = if ($contextItems.Count -gt 0) {
                    ($contextItems | ForEach-Object { ([string]$_ -replace '[\r\n]+', ' ').Trim() } | Where-Object { $_ } | ForEach-Object {
                            if ($_.Length -gt 120) { $_.Substring(0, 120) + "..." } else { $_ }
                        }) -join " | "
                }
                else { "[dns query field unavailable]" }

                $messagePreview = [string]$msg
                $messagePreview = $messagePreview -replace '[\r\n]+', ' '
                if ($messagePreview.Length -gt 220) { $messagePreview = $messagePreview.Substring(0, 220) + "..." }

                $details = "EventTime: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | EventId: $($e.Id) | Log: $logName | Provider: $($e.ProviderName) | Level: $($e.LevelDisplayName) | Confidence: StructuredDNS | MatchedIndicators: Known C2 domain | MatchedEvidence: $(@($matchedEvidence) -join '; ') | MatchedDomains: $(@($matchedDomains) -join ', ') | Context: $contextStr | MessageSample: $messagePreview"
                $displayDetails = "Time: $($e.TimeCreated.ToString('HH:mm:ss')) | DNS exact/subdomain match | Domains: $(@($matchedDomains) -join ', ')"

                Write-Finding -Severity "HIGH" -Category "Event Log" `
                    -Message "DNS query for known C2 domain in $logName (ID: $($e.Id))" `
                    -Details $details `
                    -DisplayDetails $displayDetails

                $findingsInLog++
                continue
            }

            $matchResult = Get-EventIndicatorMatches -Text $searchText -IndicatorRules $indicatorRules
            if (-not $matchResult.IsMatch) { continue }

            # Skip self-references (scanner detecting itself in logs)
            $isSelfReference = $false
            foreach ($ex in $excludePatterns) {
                if ($searchText -match $ex) { $isSelfReference = $true; break }
            }
            if ($isSelfReference) { continue }

            $contextSource = if (-not [string]::IsNullOrWhiteSpace($msg)) { $msg } else { $xml }
            $contextSnippets = @()

            foreach ($hit in $matchResult.All) {
                $pat = [string]$hit.Pattern
                if ($contextSource) {
                    $contextMatch = [regex]::Match($contextSource, "(.{0,70}$pat.{0,70})", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    if (-not $contextMatch.Success) { continue }

                    $snippet = $contextMatch.Groups[1].Value -replace '[\r\n]+', ' '
                    $snippet = $snippet.Trim()
                    if ($snippet.Length -gt 150) { $snippet = $snippet.Substring(0, 150) + "..." }
                    if ($snippet -and $snippet -notin $contextSnippets) {
                        $contextSnippets += $snippet
                    }
                }
                if ($contextSnippets.Count -ge 3) { break }
            }

            # Build clean, structured output
            $matchedStr = (@($matchResult.All | Select-Object -ExpandProperty Name -Unique) -join ", ")
            $matchedEvidence = @(
                $matchResult.All |
                Select-Object -First 4 |
                ForEach-Object {
                    $sample = [string]$_.MatchSample
                    if ([string]::IsNullOrWhiteSpace($sample)) { $sample = "[no sample]" }
                    "$($_.Name) | Pattern=$($_.Pattern) | Sample=$sample"
                }
            ) -join "; "
            $contextStr = if ($contextSnippets.Count -gt 0) {
                ($contextSnippets -join " | ")
            }
            else { "[context extraction failed]" }

            $preferredFields = @(
                "CommandLine", "Image", "ParentImage", "ProcessId", "ParentProcessId",
                "TaskName", "ActionName", "Path", "ServiceName", "ServiceFileName",
                "QueryName", "DestinationIp", "DestinationHostname", "ScriptBlockText"
            )
            $eventDataSummary = New-Object System.Collections.Generic.List[string]
            foreach ($k in $preferredFields) {
                if ($dataMap.Contains($k)) {
                    $v = [string]$dataMap[$k]
                    if ($v.Length -gt 140) { $v = $v.Substring(0, 140) + "..." }
                    $eventDataSummary.Add("$k=$v")
                }
                if ($eventDataSummary.Count -ge 6) { break }
            }
            if ($eventDataSummary.Count -eq 0 -and $dataMap.Count -gt 0) {
                foreach ($kv in $dataMap.GetEnumerator()) {
                    $v = [string]$kv.Value
                    if ($v.Length -gt 120) { $v = $v.Substring(0, 120) + "..." }
                    $eventDataSummary.Add("$($kv.Key)=$v")
                    if ($eventDataSummary.Count -ge 4) { break }
                }
            }

            $messagePreview = [string]$msg
            $messagePreview = $messagePreview -replace '[\r\n]+', ' '
            if ($messagePreview.Length -gt 260) { $messagePreview = $messagePreview.Substring(0, 260) + "..." }

            $confidence = if ($matchResult.Strong.Count -gt 0) { "Strong" } else { "Correlated" }
            $sev = if ($matchResult.Strong.Count -gt 0) { "HIGH" } else { "MEDIUM" }

            # Structured details for JSON
            $details = "EventTime: $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) | EventId: $($e.Id) | Log: $logName | Provider: $($e.ProviderName) | Level: $($e.LevelDisplayName) | Confidence: $confidence | MatchedIndicators: $matchedStr | MatchedEvidence: $matchedEvidence | EventData: $($eventDataSummary -join '; ') | Context: $contextStr | MessageSample: $messagePreview"

            # Shorter display for console
            $displayDetails = "Time: $($e.TimeCreated.ToString('HH:mm:ss')) | $confidence | Matched: $matchedStr"

            Write-Finding -Severity $sev -Category "Event Log" `
                -Message "Suspicious pattern match in $logName (ID: $($e.Id))" `
                -Details $details `
                -DisplayDetails $displayDetails

            $findingsInLog++
        }
    }
}

function Test-HighEntropyFiles {
    Write-CheckHeader 14 "High-entropy files in chain directories..."

    $paths = @($DropDirs.Bluetooth, $DropDirs.ProShow, $DropDirs.AdobeScripts, $USOSharedPath) |
    Where-Object { $_ -and (Test-Path $_) }

    $threshold = 7.2
    foreach ($p in $paths) {
        Get-ChildItem -Path $p -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '\.(exe|dll|dat|bin|tmp)$' -or $_.Extension -eq '' } |
        ForEach-Object {
            $ent = Get-FileEntropy -Path $_.FullName
            if ($null -ne $ent -and $ent -gt $threshold) {
                Write-Finding -Severity "HIGH" -Category "Entropy" `
                    -Message "High entropy file (packed/encrypted candidate): $($_.Name)" `
                    -Details "Entropy: $ent (thr: $threshold) | Path: $($_.FullName)"
            }
        }
    }
}

function Test-FileContents {
    Write-CheckHeader 15 "Content/strings scan (low-FP patterns)..."

    $paths = @($DropDirs.Bluetooth, $DropDirs.ProShow, $DropDirs.AdobeScripts, "$env:TEMP") |
    Where-Object { $_ -and (Test-Path $_) }

    foreach ($p in $paths) {
        Get-ChildItem -Path $p -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 5MB } |
        ForEach-Object {
            $hits = Test-SuspiciousContent -Path $_.FullName
            if ($hits.Count -gt 0) {
                # content matches are supportive evidence; not as strong as hash/mutex/service
                Write-Finding -Severity "MEDIUM" -Category "Content" `
                    -Message "Campaign-related strings/patterns detected in file: $($_.Name)" `
                    -Details "Patterns: $($hits -join ', ') | Path: $($_.FullName)"
            }
        }
    }
}

function Test-ServicePersistence {
    Write-CheckHeader 16 "Windows service persistence (primary persistence path in campaign)..."

    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($s in $svcs) {
            $pn = Expand-Normalize ([string]$s.PathName)
            if ([string]::IsNullOrWhiteSpace($pn)) { continue }

            if ($pn -match "\\appdata\\roaming\\bluetooth\\bluetoothservice\.exe") {
                $sev = if ($pn -match "\s-i" -or $pn -match "\s-k") { "CRITICAL" } else { "HIGH" }
                Write-Finding -Severity $sev -Category "Service" `
                    -Message "Service points to AppData\Bluetooth\BluetoothService.exe" `
                    -Details "Name: $($s.Name) | Display: $($s.DisplayName) | Path: $($s.PathName)"
                continue
            }

            if ($pn -match "\\appdata\\roaming\\(proshow|adobe\\scripts)\\") {
                Write-Finding -Severity "MEDIUM" -Category "Service" `
                    -Message "Service points to chain-associated AppData path (investigate origin)" `
                    -Details "Name: $($s.Name) | Display: $($s.DisplayName) | Path: $($s.PathName)"
            }
        }
    }
    catch {
        Write-Finding -Severity "INFO" -Category "Service" `
            -Message "Could not query services" -Details $_.Exception.Message
    }
}

# ============================================================================
# MAIN
# ============================================================================

$IsAdminContext = Test-IsAdministrator
$IsRemoteSession = $null -ne $PSSenderInfo

$headerLine = "=" * 70
if (-not $Quiet) {
    Write-Host ""
    Write-Host $headerLine -ForegroundColor Cyan
    Write-Host "  CHRYSALIS / LOTUS BLOSSOM - Notepad++ Compromise IoC Scanner" -ForegroundColor White
    Write-Host $headerLine -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Computer : $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "  User     : $env:USERNAME" -ForegroundColor White
    Write-Host "  Started  : $ScanStartTime" -ForegroundColor White
    Write-Host $headerLine -ForegroundColor DarkGray

    if (-not $IsAdminContext) {
        Write-Host "`n[WARN] Running without admin - service and some registry checks may be incomplete" -ForegroundColor Yellow
    }
    if ($IsRemoteSession) {
        Write-Host "[INFO] Running via PowerShell Remoting session" -ForegroundColor DarkGray
    }
}

Test-DropDirectories
Test-USOSharedPayloads
Test-FileHashes
Test-DNSCache
Test-NetworkConnections
Test-ChrysalisMutex
Test-RunningProcesses
Test-RegistryPersistence
Test-ScheduledTasks
Test-HostsFile
Test-NotepadVersion
Test-ExfilArtifacts
Test-EventLogs
Test-HighEntropyFiles
Test-FileContents
Test-ServicePersistence
Complete-CurrentCheck

# ============================================================================
# SUMMARY + EXPORT
# ============================================================================

$ScanEndTime = Get-Date
$Duration = $ScanEndTime - $ScanStartTime

$Critical = ($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$High = ($Findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$Medium = ($Findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$Low = ($Findings | Where-Object { $_.Severity -eq "LOW" }).Count
$Info = ($Findings | Where-Object { $_.Severity -eq "INFO" }).Count
$CheckSummary = @(
    $CheckExecution.GetEnumerator() |
    Sort-Object { [int]$_.Key } |
    ForEach-Object {
        [PSCustomObject]@{
            CheckId      = $_.Value.CheckId
            CheckName    = $_.Value.CheckName
            StartedAt    = $_.Value.StartedAt
            CompletedAt  = $_.Value.CompletedAt
            FindingCount = $_.Value.FindingCount
            Status       = if ($_.Value.FindingCount -gt 0) { "Findings present" } else { "No findings recorded" }
        }
    }
)

if (-not $Quiet) {
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "SCAN COMPLETE" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan

    Write-Host "`nResults:" -ForegroundColor White
    Write-Host "  Duration: $($Duration.TotalSeconds.ToString('F1')) seconds" -ForegroundColor Gray
    Write-Host "  Critical: $Critical" -ForegroundColor $(if ($Critical -gt 0) { "Red" } else { "Green" })
    Write-Host "  High:     $High"     -ForegroundColor $(if ($High -gt 0) { "DarkRed" } else { "Green" })
    Write-Host "  Medium:   $Medium"   -ForegroundColor $(if ($Medium -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Low:      $Low"      -ForegroundColor Cyan
    Write-Host "  Info:     $Info"     -ForegroundColor Gray

    if ($Critical -gt 0) {
        Write-Host "`n" + ("!" * 60) -ForegroundColor Red
        Write-Host "  CRITICAL: POTENTIAL COMPROMISE DETECTED!" -ForegroundColor Red
        Write-Host ("!" * 60) -ForegroundColor Red
        Write-Host @"
  Recommended Actions:
  1. ISOLATE this system from the network immediately
  2. DO NOT reboot - preserve volatile evidence
  3. Capture memory dump before shutdown
  4. Contact incident response team
  5. Preserve all logs and artifacts
"@ -ForegroundColor Yellow
    }
    elseif ($High -gt 0) {
        Write-Host "`n[!] HIGH severity findings - investigation recommended" -ForegroundColor DarkRed
    }
    elseif ($Medium -gt 0 -or $Low -gt 0) {
        Write-Host "`n[i] Only MEDIUM/LOW indicators found - correlate with other telemetry" -ForegroundColor Yellow
    }
    else {
        Write-Host "`n[OK] No CRITICAL/HIGH indicators detected" -ForegroundColor Green
        Write-Host "     This scans known IoCs only. Memory-resident or evolved variants require EDR." -ForegroundColor DarkGray
    }
}

# Optional export (no disk writes unless explicitly requested)
$script:CurrentCheckId = 0
$script:CurrentCheckName = "Export"

$reportCritical = ($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$reportHigh = ($Findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$reportMedium = ($Findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$reportLow = ($Findings | Where-Object { $_.Severity -eq "LOW" }).Count
$reportInfo = ($Findings | Where-Object { $_.Severity -eq "INFO" }).Count

$report = [ordered]@{
    ReportVersion = $ScriptVersion
    ScanId        = $ScanId
    ScanInfo      = [ordered]@{
        Computer          = $env:COMPUTERNAME
        User              = $env:USERNAME
        OSVersion         = [System.Environment]::OSVersion.VersionString
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsAdministrator   = $IsAdminContext
        IsRemoteSession   = $IsRemoteSession
        StartTime         = $ScanStartTime.ToString("o")
        EndTime           = $ScanEndTime.ToString("o")
        DurationSeconds   = [Math]::Round($Duration.TotalSeconds, 2)
    }
    ScanSettings  = [ordered]@{
        OutputPath = $OutputPath
        DeepScan   = [bool]$DeepScan
        ExportJSON = [bool]$ExportJSON
        ExportCSV  = [bool]$ExportCSV
        Quiet      = [bool]$Quiet
    }
    Summary       = [ordered]@{
        Critical = $reportCritical
        High     = $reportHigh
        Medium   = $reportMedium
        Low      = $reportLow
        Info     = $reportInfo
        Total    = $Findings.Count
    }
    CheckSummary  = $CheckSummary
    Findings      = $Findings
}

$shouldExportToDisk = [bool]$ExportJSON -or [bool]$ExportCSV
if (-not $shouldExportToDisk) {
    if (-not $Quiet) {
        Write-Host "[INFO] No report file written. Use -ExportJSON and/or -ExportCSV to export results." -ForegroundColor DarkGray
    }
    return $Findings
}

$requestedOutputPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) { Get-DefaultOutputPath } else { $OutputPath }
$fallbackUsed = $false
$outputReady = $false

$fallbackCandidates = @(
    $requestedOutputPath,
    (Get-DefaultOutputPath),
    $PSScriptRoot,
    (Get-Location).Path
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

foreach ($candidate in $fallbackCandidates) {
    try {
        if (-not (Test-Path -Path $candidate -PathType Container)) {
            New-Item -Path $candidate -ItemType Directory -Force | Out-Null
        }
        if (Test-Path -Path $candidate -PathType Container) {
            $OutputPath = $candidate
            $outputReady = $true
            $fallbackUsed = (Expand-Normalize $candidate) -ne (Expand-Normalize $requestedOutputPath)
            break
        }
    }
    catch {}
}

if (-not $outputReady) {
    Write-Finding -Severity "INFO" -Category "Export" `
        -Message "Could not prepare a writable output path; report export skipped" `
        -Details "RequestedOutputPath: $requestedOutputPath"
    return $Findings
}

if ($fallbackUsed -and -not $Quiet) {
    Write-Host "[INFO] Requested output path was not writable; fallback path selected: $OutputPath" -ForegroundColor DarkYellow
}

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

if ($ExportJSON) {
    $jsonPath = Join-Path -Path $OutputPath -ChildPath "ChrysalisScan_$stamp.json"
    try {
        $report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8
        if (-not $Quiet) { Write-Host "JSON report: $jsonPath" -ForegroundColor Green }
    }
    catch {
        Write-Finding -Severity "INFO" -Category "Export" -Message "Could not write JSON report" -Details $_.Exception.Message
    }
}

if ($ExportCSV) {
    $csvPath = Join-Path -Path $OutputPath -ChildPath "ChrysalisScan_$stamp.csv"
    try {
        $Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        if (-not $Quiet) { Write-Host "CSV report:  $csvPath" -ForegroundColor Green }
    }
    catch {
        Write-Finding -Severity "INFO" -Category "Export" -Message "Could not write CSV report" -Details $_.Exception.Message
    }
}

return $Findings
