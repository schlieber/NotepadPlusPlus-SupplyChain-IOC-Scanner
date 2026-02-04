# NotepadPlusPlus-SupplyChain-IOC-Scanner

**Notepad++ Supply Chain Attack IoC Scanner | Chrysalis Backdoor Detection | Lotus Blossom APT Malware Scanner | CVE-2025-15556**

[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CVE-2025-15556](https://img.shields.io/badge/CVE-2025--15556-red.svg)](https://www.cve.org/CVERecord?id=CVE-2025-15556)

---

## 🚨 What Is This?

A **read-only, non-destructive PowerShell scanner** that detects **Indicators of Compromise (IoC)** from the **Notepad++ supply chain attack** (June–December 2025) attributed to the Chinese APT group **Lotus Blossom** (also tracked as Billbug, Spring Dragon, Thrip).

**Use this tool to determine if your Windows system has been compromised** by the **Chrysalis backdoor** or related malware delivered through hijacked Notepad++ software updates.

### Key Features

- ✅ **Zero installation** — single PowerShell script
- ✅ **Non-destructive** — read-only, no system modifications
- ✅ **False-positive aware** — intelligent scoring minimizes noise
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
| 5 | **Network Connections** | Active TCP connections to 7 known C2 IP addresses |
| 6 | **Chrysalis Mutex** | Runtime backdoor detection (`Global\Jdhfv_1.0.1`) |
| 7 | **Running Processes** | Path-based suspicious process analysis |
| 8 | **Registry Persistence** | Run/RunOnce keys with legitimate updater allowlist |
| 9 | **Scheduled Tasks** | Task action path analysis |
| 10 | **Hosts File** | C2 domain entries (blocking-aware detection) |
| 11 | **Notepad++ Signature** | Binary and GUP.exe Authenticode validation |
| 12 | **Exfil Artifacts** | Recon staging files (1.txt, a.txt, u.bat) |
| 13 | **Event Log Analysis** | PowerShell & Application log pattern matching |
| 14 | **Entropy Detection** | Packed/obfuscated files (Shannon entropy > 7.2) |
| 15 | **Content Scanning** | Campaign strings, decryption keys, C2 URLs |
| 16 | **Windows Services** | Service path analysis for persistence |

---

## 📥 Quick Start

```powershell
# Download and run (no installation required)
irm https://raw.githubusercontent.com/schlieber/NotepadPlusPlus-SupplyChain-IOC-Scanner/main/Detect-Chrysalis.ps1 | iex

# Or clone and run locally
git clone https://github.com/schlieber/NotepadPlusPlus-SupplyChain-IOC-Scanner.git
cd NotepadPlusPlus-SupplyChain-IOC-Scanner
.\Detect-Chrysalis.ps1
```

### Bypass Execution Policy (if needed)

```powershell
powershell -ExecutionPolicy Bypass -File Detect-Chrysalis.ps1
```

---

## 🛠️ Usage Options

```powershell
# Standard scan with colored output
.\Detect-Chrysalis.ps1

# Deep scan (includes Downloads, Temp, ProgramData)
.\Detect-Chrysalis.ps1 -DeepScan

# Export results to JSON and CSV
.\Detect-Chrysalis.ps1 -ExportCSV -OutputPath "C:\SecurityLogs"

# Quiet mode (only shows findings, no OK messages)
.\Detect-Chrysalis.ps1 -Quiet
```

### Command-Line Parameters

| Parameter | Description |
|-----------|-------------|
| `-OutputPath` | Directory for JSON/CSV reports (default: Desktop) |
| `-ExportCSV` | Export findings to CSV in addition to JSON |
| `-DeepScan` | Scan additional directories for hash matches |
| `-Quiet` | Suppress clean/OK output, only show findings |

---

## 📊 Output & Reporting

The scanner automatically generates a **JSON report** for incident response:

```
ChrysalisScan_20260204_143052.json
```

With `-ExportCSV`, also generates:

```
ChrysalisScan_20260204_143052.csv
```

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
| **MITRE ATT&CK** | [Lotus Blossom G0030](https://attack.mitre.org/groups/G0030/) |

---

## ⚠️ Limitations

- Detects **known IoCs only** — zero-day variants may not be detected
- Does **not replace** EDR/AV or full forensic investigation
- Some checks require **elevated privileges** for complete coverage
- Network detection may miss **cleared DNS caches**

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
