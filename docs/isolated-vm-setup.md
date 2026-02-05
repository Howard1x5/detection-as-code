# Isolated VM Configuration for Malware Detonation

## Overview

This document describes the configuration of the network-isolated FLARE VM for safe malware detonation with full detection telemetry.

## Network Architecture

```
Internet-Connected Network (10.98.1.0/24)
├── Wazuh Server (10.98.1.121)
├── N8N Automation (10.98.1.130)
└── FLARE-Internet VM (10.98.1.112)

Isolated Network (192.168.100.0/24)
├── FLARE-Isolated VM (192.168.100.110)
└── REMnux-Isolated VM (192.168.100.10)

Hypervisor bridges isolated network to Wazuh via port forwarding:
  192.168.100.1:1514 → 10.98.1.121:1514 (Wazuh agent communication)
```

## FLARE-Isolated VM Components

### Sysmon Configuration

Sysmon is installed to capture detailed Windows telemetry:

```powershell
# Install Sysmon with config
C:\Tools\sysinternals\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml
```

Key events captured:
- Event ID 1: Process Creation
- Event ID 3: Network Connection
- Event ID 7: Image Load (DLL)
- Event ID 11: File Create
- Event ID 13: Registry Value Set

### Wazuh Agent Configuration

The Wazuh agent forwards Sysmon logs to the server through the hypervisor bridge.

`C:\Program Files (x86)\ossec-agent\ossec.conf`:
```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.100.1</address>
      <port>1514</port>
    </server>
  </client>

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

## Snapshot Management

Always create a snapshot before malware detonation:

```bash
# Create snapshot
qm snapshot 110 pre-detonation-clean --description "Clean state before malware detonation"

# List snapshots
qm listsnapshot 110

# Restore to clean state after detonation
qm rollback 110 pre-detonation-clean
```

## Sample Transfer Workflow

Since the isolated VM has no internet, transfer samples via the hypervisor:

```bash
# From workstation to hypervisor
scp sample.exe root@<hypervisor>:/tmp/

# From hypervisor to isolated VM (via port forward)
scp -P 2224 /tmp/sample.exe analyst@<hypervisor>:C:/Samples/
```

## Detection Flow

```
1. Malware executes on FLARE-Isolated
2. Sysmon captures events (process, network, file, registry)
3. Wazuh agent reads Sysmon event log
4. Agent forwards to Wazuh server via hypervisor bridge
5. Wazuh matches detection rules (100xxx series)
6. Webhook fires to N8N
7. N8N enriches with VirusTotal
8. Alert sent to Discord
```

## Troubleshooting

### No alerts appearing
1. Check Sysmon service: `sc query Sysmon64`
2. Check Wazuh agent: `sc query WazuhSvc`
3. Verify network path: `Test-NetConnection 192.168.100.1 -Port 1514`

### Alerts missing data
See `n8n-workflow-troubleshooting.md` for N8N field extraction issues.
