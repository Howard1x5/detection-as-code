# Detection Pipeline Architecture

## Overview

This detection-as-code pipeline automates the flow from malware analysis to detection deployment and automated response.

## System Diagram

```
Samples Downloaded from MalwareBazaar
    │
    ▼
FLARE VM Isolated
├─ Automated Analysis
│  - Static: strings, CAPA, DIE, sigcheck
│  - Dynamic: Detonation + monitoring
│  - IOC extraction + MITRE mapping
│
├─ Wazuh Agent (logs via gateway forwarding)
│  - File monitoring (YARA)
│  - Process monitoring (Sysmon)
│  - Forwards to gateway
│
└─ Analysis outputs → Detection rules
    │
    ▼
Hypervisor
├─ Forwards logs from isolated network → Wazuh Server
│
└─ Hosts:
   - Wazuh Server (container/VM)
   - N8N Automation (container/VM)
    │
    ▼
Wazuh Server
├─ Detection Rules
│  - YARA (file-based)
│  - Sigma (behavior-based)
│  - Custom rules (log correlation)
│
├─ Alert Generation
│  - Fires when rules match
│  - Webhook to N8N
│
└─ Response Playbooks
   - Via Wazuh active response API
    │
    ▼
N8N Automation
├─ Enrichment Workflow
│  1. Extract IOCs from alert
│  2. Query VirusTotal
│  3. Query MalwareBazaar
│  4. Calculate severity
│  5. Send to Discord/Slack
│
└─ If CRITICAL severity:
   - Trigger response playbook
   - Isolate host
   - Kill process
   - Remove persistence
```

## Components

### Analysis Infrastructure

| Component | Purpose |
|-----------|---------|
| FLARE VM (Isolated) | Malware detonation, static analysis |
| FLARE VM (Internet) | Analysis with controlled network access |
| REMnux | Linux malware analysis |

### Detection Infrastructure

| Component | Purpose |
|-----------|---------|
| Wazuh Server | SIEM, detection rules, alerts |
| N8N | Workflow automation, enrichment |
| Hypervisor | VM hosting, log forwarding |

## Data Flow

1. **Sample Acquisition**: Download from MalwareBazaar
2. **Static Analysis**: Run on FLARE VM
3. **Rule Generation**: Generate YARA/Sigma rules from IOCs and behaviors
4. **Rule Testing**: Validate against known samples
5. **Deployment**: Push rules to Wazuh
6. **Detection**: Wazuh monitors endpoints
7. **Enrichment**: N8N enriches alerts with threat intel
8. **Response**: Automated containment actions

## Network Segmentation

- **Infrastructure Network**: Internet-connected VMs and services
- **Isolated Network**: Air-gapped malware analysis environment

## Deployment

See individual component documentation for deployment instructions:
- [N8N Workflows](../n8n-workflows/README.md)
- [Wazuh Rules](../rules/wazuh/)
