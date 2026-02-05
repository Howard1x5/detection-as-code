# Detection Pipeline Architecture

## Overview

This detection-as-code pipeline automates the flow from malware analysis to detection deployment and automated response.

## System Diagram

```
Samples Downloaded from MalwareBazaar
    │
    ▼
FLARE VM Isolated (192.168.100.110)
├─ Claude Code Automated Analysis
│  - Static: strings, CAPA, DIE, sigcheck
│  - Dynamic: Detonation + monitoring
│  - IOC extraction + MITRE mapping
│
├─ Wazuh Agent (logs via Proxmox forwarding)
│  - File monitoring (YARA)
│  - Process monitoring (Sysmon)
│  - Forwards to 192.168.100.1 (Proxmox gateway)
│
└─ Analysis outputs → Detection rules
    │
    ▼
Proxmox (10.98.1.5)
├─ Forwards logs from 192.168.100.1 → Wazuh Server
│
└─ Hosts:
   - Wazuh Server (LXC 121 - 10.98.1.121)
   - N8N Automation (LXC 130 - 10.98.1.130)
    │
    ▼
Wazuh Server (10.98.1.121)
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
N8N (10.98.1.130:5678)
├─ Enrichment Workflow
│  1. Extract IOCs from alert
│  2. Query VirusTotal
│  3. Query MalwareBazaar
│  4. Calculate severity
│  5. Send to Discord
│
└─ If CRITICAL severity:
   - Trigger response playbook
   - Isolate host
   - Kill process
   - Remove persistence
```

## Components

### Analysis Infrastructure

| Component | IP Address | Purpose |
|-----------|------------|---------|
| FLARE VM (Isolated) | 192.168.100.110 | Malware detonation, static analysis |
| FLARE VM (Internet) | 10.98.1.112 | Analysis with network access |
| REMnux (Internet) | 10.98.1.102 | Linux malware analysis |

### Detection Infrastructure

| Component | IP Address | Purpose |
|-----------|------------|---------|
| Wazuh Server | 10.98.1.121 | SIEM, detection rules, alerts |
| N8N | 10.98.1.130 | Workflow automation, enrichment |
| Proxmox | 10.98.1.5 | Hypervisor, log forwarding |

## Data Flow

1. **Sample Acquisition**: Download from MalwareBazaar
2. **Static Analysis**: Run on FLARE VM via SSH
3. **Rule Generation**: Claude Code generates YARA/Sigma rules
4. **Rule Testing**: Validate against known samples
5. **Deployment**: Push rules to Wazuh
6. **Detection**: Wazuh monitors endpoints
7. **Enrichment**: N8N enriches alerts with threat intel
8. **Response**: Automated containment actions

## Network Segmentation

- **10.98.1.0/24 (vmbr0)**: Internet-connected VMs and infrastructure
- **192.168.100.0/24 (vmbr1)**: Isolated malware analysis network
