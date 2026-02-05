# Notepad++ Supply Chain IOC Scanner (Detect CVE-2025-15556 & Chrysalis)

**Notepad++ Supply Chain Attack IoC Scanner | Chrysalis Backdoor Detection | Lotus Blossom APT Malware Scanner | CVE-2025-15556**

[![PowerShell Script to Scan for Notepad++ Malware](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CVE-2025-15556 Vulnerability Check](https://img.shields.io/badge/CVE-2025--15556-red.svg)](https://www.cve.org/CVERecord?id=CVE-2025-15556)

A free, open-source PowerShell tool to detect the Notepad++ supply chain attack (CVE-2025-15556). Scan Windows systems for Chrysalis backdoor and Lotus Blossom APT indicators without installing external software. It checks for compromised file artifacts, suspicious persistence, and known C2 infrastructure.

---

## 🚨 What Is This?

A **read-only, non-destructive PowerShell scanner** that detects **Indicators of Compromise (IoC)** from the **Notepad++ supply chain attack** (June–December 2025) attributed to the Chinese APT group **Lotus Blossom** (also tracked as Billbug, Spring Dragon, Thrip).

**Use this tool to determine if your Windows system has been compromised** by the **Chrysalis backdoor** or related malware delivered through hijacked Notepad++ software updates.

### Key Features

- ✅ **Zero installation** — single PowerShell script
- ✅ **Non-destructive** — read-only, no system modifications
- ✅ **False-positive aware** — intelligent scoring minimizes noise
- ✅ **Portable-aware** — detects Notepad++ outside default install folders
- ✅ **Incident response ready** — JSON/CSV export for SIEM integration
- ✅ **Comprehensive** — 16 detection checks covering all 3 infection chains

---

## 🔍 Detection Capabilities

| # | Check | Description |
|---|-------|-------------|
| 1 | **Drop Directories** | ProShow, Adobe\Scripts, Bluetooth folders (path-based scoring) |
| 2 | **USOShared Payloads** | TinyCC compiler artifacts (conf.c, libtcc.dll, svchost.exe) |
| 3 | **File Hashes** | SHA-256/SHA-1 verification against known malware samples |
| 4 | **DNS Cache** | C2 domain resolution history |
| 5 | **Network Connections** | Active TCP connections to 7 known C2 IPs (`Get-NetTCPConnection` with `netstat` fallback) + optional DeepScan firewall history (`pfirewall*.log`, profile/policy-aware) |
| 6 | **Chrysalis Mutex** | Runtime backdoor detection (`Global\Jdhfv_1.0.1`) |
| 7 | **Running Processes** | Path-based suspicious process analysis |
| 8 | **Registry Persistence** | Run/RunOnce keys with legitimate updater allowlist |
| 9 | **Scheduled Tasks** | Task action path analysis |
| 10 | **Hosts File** | C2 domain entries (blocking-aware detection) |
| 11 | **Notepad++ Discovery + Signature** | Multi-source install discovery + Notepad++/GUP.exe Authenticode validation + securityError.log context + pre-8.8.9 updater-hardening warning |
| 12 | **Exfil Artifacts** | Recon staging files (1.txt, a.txt, u.bat) |
| 13 | **Event Log Analysis** | Correlated indicator matching across PowerShell/System/Task Scheduler/Sysmon/Security + structured DNS Client telemetry (`Microsoft-Windows-DNS-Client/Operational`) |
| 14 | **Entropy Detection** | Packed/obfuscated files (Shannon entropy > 7.2) |
| 15 | **Content Scanning** | Campaign strings, decryption keys, C2 URLs |
| 16 | **Windows Services** | Service path analysis for persistence |

---

## 📥 How to Scan for Notepad++ Malware

1. **Open PowerShell**: Run as Administrator for full service and registry visibility.
2. **Download scanner**:
   ```powershell
   irm https://raw.githubusercontent.com/schlieber/NotepadPlusPlus-SupplyChain-IOC-Scanner/main/Detect-Chrysalis.ps1 | iex
   ```
3. **Analyze results**: Investigate all `CRITICAL` and `HIGH` findings immediately, then preserve the JSON/CSV report for incident response.
4. **Optional (run locally from clone)**:
   ```powershell
   git clone https://github.com/schlieber/NotepadPlusPlus-SupplyChain-IOC-Scanner.git
   cd NotepadPlusPlus-SupplyChain-IOC-Scanner
   .\Detect-Chrysalis.ps1
   ```

If execution policy blocks script launch:
```powershell
powershell -ExecutionPolicy Bypass -File Detect-Chrysalis.ps1
```

---

## 🛠️ Usage Options

```powershell
# Standard scan with colored output
.\Detect-Chrysalis.ps1

# Deep scan (includes additional user/app/package paths, expanded event logs, and firewall history check)
.\Detect-Chrysalis.ps1 -DeepScan

# Export JSON report
.\Detect-Chrysalis.ps1 -ExportJSON -OutputPath "C:\SecurityLogs"

# Export JSON + CSV
.\Detect-Chrysalis.ps1 -ExportJSON -ExportCSV -OutputPath "C:\SecurityLogs"

# Quiet mode (only shows findings, no OK messages)
.\Detect-Chrysalis.ps1 -Quiet
```

### Command-Line Parameters

| Parameter | Description |
|-----------|-------------|
| `-OutputPath` | Directory for JSON/CSV reports when export switches are used |
| `-ExportJSON` | Export full report to JSON |
| `-ExportCSV` | Export findings to CSV |
| `-DeepScan` | Scan additional directories for hash matches, expand event log coverage, and parse Windows Firewall history logs (`pfirewall*.log`, profile/policy-aware) |
| `-Quiet` | Suppress clean/OK output, only show findings |

---

## 📊 Output & Reporting

By default, the scanner does **not write anything to disk**.  
Use `-ExportJSON` and/or `-ExportCSV` to persist results.

JSON export example:

```
ChrysalisScan_20260204_143052.json
```

CSV export example:

```
ChrysalisScan_20260204_143052.csv
```

### Report Structure (JSON)

The JSON report now includes:

- `ReportVersion` and `ScanId` for case tracking
- `ScanInfo` (host context, PowerShell version, admin context, timing)
- `ScanSettings` (flags used for the scan)
- `Summary` (severity totals)
- `CheckSummary` (all 16 checks, start/end timestamps, finding count)
- `Findings` with per-finding `CheckId`/`CheckName` context
- Event-log findings include matched indicator evidence and context snippets for faster triage
- Firewall-log findings include profile + log-path context when available

### Notepad++ Install Discovery Sources

Check #11 detects `notepad++.exe` from multiple locations, not just default folders:

- Standard install paths (`Program Files`, `Program Files (x86)`)
- Per-user and package paths (e.g. Scoop/Chocolatey/common portable paths)
- Registry `App Paths` and `Uninstall` metadata
- Running process executable path
- `PATH` command resolution

### Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| **CRITICAL** | 🔴 | Confirmed compromise — investigate immediately |
| **HIGH** | 🟠 | Strong indicator — requires investigation |
| **MEDIUM** | 🟡 | Suspicious — worth reviewing |
| **LOW** | 🔵 | Informational anomaly |
| **INFO** | ⚪ | Context information |

---

## 🎯 MITRE ATT&CK Coverage

| Technique ID | Name |
|--------------|------|
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Supply Chain Compromise: Compromise Software Supply Chain |
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | Hijack Execution Flow: DLL Side-Loading |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Command and Scripting Interpreter: Windows Command Shell |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Create or Modify System Process: Windows Service |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols |
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery |
| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery |

---

## 🕵️ Threat Intelligence

### The Notepad++ Supply Chain Attack (June–December 2025)

The **Lotus Blossom** APT group (attributed to China) compromised Notepad++ hosting infrastructure and distributed malicious updates through three distinct infection chains:

| Chain | Period | Technique |
|-------|--------|-----------|
| **#1** | July–August 2025 | ProShow exploit loader |
| **#2** | September–October 2025 | Lua-based loader |
| **#3** | October 2025 onward | Chrysalis backdoor via DLL sideloading |

Timeline notes validated against public reporting:
- Notepad++ incident update states compromise activity started in **June 2025** and provider-side remediation completed by **December 2, 2025**
- Kaspersky reports observed malicious payload deployment from **late July through November 2025**
- Rapid7 details chain #3/USOShared overlap and additional loader/shellcode IoCs

### Chrysalis Backdoor Capabilities

- DLL sideloading via renamed Bitdefender binaries
- HTTPS-based C2 communication
- Cobalt Strike beacon deployment
- System reconnaissance exfiltration to temp.sh

---

## 📚 References & Sources

| Source | Link |
|--------|------|
| **CVE** | [CVE-2025-15556](https://www.cve.org/CVERecord?id=CVE-2025-15556) |
| **Rapid7 Labs** | [The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/) |
| **Kaspersky GReAT** | [Notepad++ Supply Chain Attack](https://securelist.com/notepad-supply-chain-attack/118708/) |
| **Notepad++ Official Update** | [Hijacked Incident Information Update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/#) |
| **MITRE ATT&CK** | [Lotus Blossom G0030](https://attack.mitre.org/groups/G0030/) |

### Additional Rule Coverage

This scanner incorporates selected Lotus Blossom-related filename/path patterns mapped to Rapid7 Chrysalis tradecraft, including:

- USOShared short-name `c/dll/exe` payload pattern
- Single-character `.txt` staging files in `AppData\\Roaming\\ProShow` and `AppData\\Roaming\\Adobe\\Scripts`
- Strong path matches for `BluetoothService.exe`, `log.dll`, `load`, `ProShow.exe`, `alien.ini`, `script.exe`
- Campaign-associated `libtcc.dll` filename sightings
- Additional Rapid7 SHA-256 loader/shellcode artifacts (`admin`, `system`)
- Malicious update URL patterns from Securelist timeline reporting (`update.exe`, `install.exe`, `AutoUpdater.exe` paths)

### Third-Party Rule Source and License

- Detection rules used for mapping: https://github.com/Neo23x0/signature-base/blob/master/iocs/filename-iocs.txt
- License reference: https://github.com/Neo23x0/signature-base/blob/master/LICENSE

---

## ⚠️ Limitations

- Detects **known IoCs only** — zero-day variants may not be detected
- Does **not replace** EDR/AV or full forensic investigation
- Some checks require **elevated privileges** for complete coverage
- Event log coverage depends on local audit/logging policy and available retention
- Network detection may miss **cleared DNS caches**
- Firewall history parsing requires Windows Firewall logging enabled (default: `%windir%\System32\LogFiles\Firewall\pfirewall.log`, or profile/policy-defined `pfirewall*.log`)

---

## ❓ Frequently Asked Questions (FAQ)

### How do I check if my Notepad++ is infected?
Run `Detect-Chrysalis.ps1` on the target Windows host and review `CRITICAL`/`HIGH` findings first. Correlate hits across hashes, persistence, process paths, and network indicators before concluding compromise status.

### Is this scanner safe and non-destructive?
Yes. The script is read-only: it inspects files, registry keys, process/task/service state, and network artifacts without changing host configuration.

### Does this tool fix CVE-2025-15556?
No. It detects known compromise indicators. If infected, rebuild or reimage affected systems, reinstall Notepad++ from trusted sources, rotate credentials, and complete IR containment/eradication steps.

---

## 🤝 Contributing

Contributions welcome! Please submit issues or pull requests for:

- Additional IoCs from new threat intelligence
- False positive reports with context
- Feature enhancements

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

## 👤 Author

**Simon Schlieber** — [@schlieber](https://github.com/schlieber)

---

## 🔑 Keywords

`notepad++` `notepadplusplus` `supply-chain-attack` `supply-chain-compromise` `chrysalis` `chrysalis-backdoor` `lotus-blossom` `billbug` `spring-dragon` `thrip` `apt` `chinese-apt` `ioc` `ioc-scanner` `indicator-of-compromise` `backdoor` `malware-detection` `malware-scanner` `powershell` `powershell-script` `security` `security-tools` `incident-response` `threat-hunting` `threat-detection` `forensics` `dfir` `blue-team` `CVE-2025-15556` `cobalt-strike` `dll-sideloading`
