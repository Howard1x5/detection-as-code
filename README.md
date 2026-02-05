# Detection-as-Code Pipeline

Automated malware detection rule generation and deployment pipeline for security operations. This project implements detection-as-code methodology, operationalizing threat intelligence into YARA, Sigma, and Wazuh detection rules.

## Overview

This pipeline automates the flow from malware analysis to detection deployment:

```
Threat Intelligence / Malware Samples
           │
           ▼
    ┌──────────────┐
    │   Analysis   │  ← FLARE VM / REMnux
    │   Extract    │  ← IOCs, TTPs, Behaviors
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │    Rules     │  ← YARA (file-based)
    │  Generation  │  ← Sigma (behavioral)
    └──────┬───────┘  ← Wazuh (SIEM correlation)
           │
           ▼
    ┌──────────────┐
    │   Wazuh      │  ← Detection Engine
    │   SIEM       │  ← Alert Generation
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │     N8N      │  ← VirusTotal Enrichment
    │  Automation  │  ← Discord Notifications
    └──────────────┘
```

## Detection Coverage

### Malware Families

| Family | Type | YARA | Sigma | Wazuh | Key TTPs |
|--------|------|------|-------|-------|----------|
| **AsyncRAT** | RAT | 4 | 11 | 15 | T1547.001, T1053.005, T1036.005, T1571 |
| **Emotet** | Loader | 3 | 4 | 6 | T1059.001, T1218.011, T1547.001 |
| **QakBot** | Loader | 3 | 4 | 6 | T1218.010, T1055, T1016 |
| **Remcos** | RAT | 3 | 5 | 7 | T1056.001, T1547.001, T1055.012 |
| **LokiBot** | Stealer | 3 | 5 | 8 | T1555.003, T1539, T1041 |
| **Chrysalis** | APT Backdoor | 5 | 10 | 18 | T1574.002, T1620, T1573 |

**Total: 21 YARA rules, 39 Sigma rules, 60 Wazuh rules**

### MITRE ATT&CK Coverage

- **Execution**: T1059.001 (PowerShell), T1059.003 (Cmd), T1047 (WMI)
- **Persistence**: T1547.001 (Registry Run Keys), T1053.005 (Scheduled Tasks), T1543.003 (Services)
- **Defense Evasion**: T1036.005 (Masquerading), T1055 (Process Injection), T1218 (Signed Binary Proxy)
- **Credential Access**: T1555.003 (Browser Credentials), T1539 (Steal Web Session)
- **Discovery**: T1016 (System Network Config), T1057 (Process Discovery)
- **Command & Control**: T1071.001 (Web Protocols), T1571 (Non-Standard Port), T1573 (Encrypted Channel)
- **Exfiltration**: T1041 (Exfil Over C2)

## Project Structure

```
detection-pipeline/
├── rules/
│   ├── yara/                    # File-based detection
│   │   ├── asyncrat_file_indicators.yar
│   │   ├── emotet_file_indicators.yar
│   │   ├── qakbot_file_indicators.yar
│   │   ├── remcos_file_indicators.yar
│   │   ├── lokibot_file_indicators.yar
│   │   └── chrysalis_lotus_blossom.yar
│   ├── sigma/                   # Behavioral detection
│   │   ├── asyncrat_*.yml
│   │   ├── emotet_behavior.yml
│   │   ├── qakbot_behavior.yml
│   │   ├── remcos_behavior.yml
│   │   ├── lokibot_behavior.yml
│   │   └── chrysalis_lotus_blossom.yml
│   └── wazuh/                   # SIEM correlation rules
│       ├── asyncrat_rules.xml
│       ├── emotet_rules.xml
│       ├── qakbot_rules.xml
│       ├── remcos_rules.xml
│       ├── lokibot_rules.xml
│       └── chrysalis_rules.xml
├── n8n-workflows/               # Alert enrichment automation
│   ├── wazuh_alert_enrichment_v2.json
│   └── README.md
├── reports/                     # Analysis reports
│   └── asyncrat_analysis.md
├── docs/
│   └── architecture.md
└── deployment/                  # Deployment logs
```

## Usage

### YARA Scanning

```bash
# Scan a file
yara rules/yara/asyncrat_file_indicators.yar /path/to/suspicious/file

# Scan a directory
yara -r rules/yara/*.yar /path/to/scan/
```

### Sigma Rule Conversion

```bash
# Convert to Wazuh format
sigma convert -t wazuh rules/sigma/asyncrat_persistence.yml

# Convert to Splunk
sigma convert -t splunk rules/sigma/asyncrat_persistence.yml
```

### Wazuh Deployment

```bash
# Copy rules to Wazuh server
scp rules/wazuh/*.xml root@wazuh-server:/var/ossec/etc/rules/

# Fix permissions and restart
ssh root@wazuh-server "chown wazuh:wazuh /var/ossec/etc/rules/*.xml && systemctl restart wazuh-manager"
```

### N8N Workflow Import

```bash
# Import workflow via CLI
n8n import:workflow --input=n8n-workflows/wazuh_alert_enrichment_v2.json
```

## Requirements

- **Wazuh Server** (4.x) - SIEM and detection engine
- **Sysmon** - Windows endpoint telemetry (Events 1, 3, 7, 11, 13)
- **N8N** - Workflow automation (optional, for enrichment)
- **VirusTotal API** - Threat intelligence enrichment (optional)

## Detection Rule Format

### YARA Example
```yara
rule asyncrat_config_strings {
    meta:
        description = "Detects AsyncRAT configuration strings"
        mitre_attack = "T1547.001"
    strings:
        $mutex = "AsyncMutex_" ascii wide
        $cfg = "Pastebin" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}
```

### Sigma Example
```yaml
title: AsyncRAT Scheduled Task Persistence
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - 'onlogon'
    condition: selection
```

### Wazuh Example
```xml
<rule id="100110" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/create</field>
    <mitre>
        <id>T1053.005</id>
    </mitre>
    <description>Scheduled task persistence detected</description>
</rule>
```

## Adding New Detections

1. **Analyze** - Extract IOCs and behavioral patterns from malware/threat intel
2. **Create Rules** - Write YARA (file), Sigma (behavior), and Wazuh (SIEM) rules
3. **Test** - Validate against known samples and benign files
4. **Deploy** - Push to Wazuh server and verify alerts
5. **Enrich** - Configure N8N workflow for threat intel enrichment

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [YARA Documentation](https://yara.readthedocs.io/)

## License

MIT

---

*Detection engineering portfolio demonstrating automated threat detection capabilities.*
