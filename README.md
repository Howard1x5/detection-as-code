# Detection-as-Code Pipeline

Automated malware analysis and detection rule generation pipeline for security operations.

## Overview

This project implements a detection-as-code approach to security monitoring, automating the flow from malware analysis to detection deployment and response.

## Architecture

```
                    ┌─────────────────┐
                    │ MalwareBazaar   │
                    │ Sample Source   │
                    └────────┬────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────┐
│           FLARE VM Analysis Environment         │
│  ┌─────────────┐  ┌─────────────┐              │
│  │   Static    │  │  Dynamic    │              │
│  │  Analysis   │  │  Analysis   │              │
│  └──────┬──────┘  └──────┬──────┘              │
│         │                │                      │
│         └────────┬───────┘                      │
│                  ▼                              │
│         ┌───────────────┐                       │
│         │ IOC Extraction│                       │
│         │ YARA/Sigma Gen│                       │
│         └───────┬───────┘                       │
└─────────────────┼───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│              Wazuh SIEM Server                  │
│  ┌─────────────────────────────────────┐        │
│  │  Detection Rules   │  Alerting      │        │
│  │  - YARA (file)     │  - Webhooks    │        │
│  │  - Sigma (behavior)│  - N8N         │        │
│  └─────────────────────────────────────┘        │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│           N8N Automation Platform               │
│  ┌─────────────────────────────────────┐        │
│  │  Alert Enrichment                   │        │
│  │  - VirusTotal lookup                │        │
│  │  - MalwareBazaar correlation        │        │
│  │  - Discord notifications            │        │
│  └─────────────────────────────────────┘        │
└─────────────────────────────────────────────────┘
```

## Components

| Component | Description | Status |
|-----------|-------------|--------|
| Wazuh Server | SIEM, detection engine, alerting | Deployed |
| N8N | Workflow automation, enrichment | Deployed |
| FLARE VM | Windows malware analysis | Active |
| REMnux | Linux malware analysis | Pending |

## Detection Rules

### YARA Rules (`rules/yara/`)

File-based detection rules for identifying malware by content patterns.

| Rule | Description |
|------|-------------|
| `eicar_test.yar` | EICAR antivirus test file detection |

### Sigma Rules (`rules/sigma/`)

Behavioral detection rules for identifying suspicious activities.

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `suspicious_powershell_download.yml` | PowerShell web downloads | T1059.001, T1105 |
| `suspicious_executable_in_temp.yml` | Executables in temp directories | T1204.002 |

## Usage

### Testing YARA Rules

```bash
yara rules/yara/eicar_test.yar /path/to/scan
```

### Converting Sigma Rules for Wazuh

```bash
sigma convert -t wazuh rules/sigma/*.yml
```

## Infrastructure

- **Wazuh Dashboard**: https://10.98.1.5:9443
- **N8N Automation**: http://10.98.1.5:5678

## Project Structure

```
detection-pipeline/
├── README.md
├── docs/
│   └── architecture.md
├── rules/
│   ├── yara/           # YARA detection rules
│   └── sigma/          # Sigma behavioral rules
├── samples/            # Analyzed samples metadata
└── infrastructure/     # Deployment configs
```

## Contributing

1. Analyze new malware samples in FLARE VM
2. Extract IOCs and behavioral patterns
3. Create YARA/Sigma rules
4. Test against known samples
5. Deploy to Wazuh

## License

MIT

---

*Built as part of detection engineering portfolio for security operations.*
