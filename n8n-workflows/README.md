# N8N Workflows for Detection Pipeline

## Wazuh Alert Enrichment Workflow

**File:** `wazuh_alert_enrichment_v2.json`

### Overview

This workflow processes Wazuh security alerts, enriches them with VirusTotal threat intelligence, and sends notifications to Discord based on severity.

### Flow

```
Wazuh Alert (webhook)
    → Extract IOCs (hash, IP, process)
    → Check if SHA256 present
    → [Yes] Query VirusTotal
    → Calculate severity
    → Route by severity
    → Discord/Slack notification
```

### Required Credentials

1. **VirusTotal API**
   - Type: HTTP Header Auth
   - Header Name: `x-apikey`
   - Header Value: Your VT API key
   - Get free key: https://www.virustotal.com/gui/join-us

2. **Discord Webhook** (or Slack)
   - Create a webhook in your Discord server
   - Server Settings → Integrations → Webhooks → New Webhook
   - Copy webhook URL

### Import Instructions

1. Open N8N at `http://<your-n8n-server>:5678`
2. Go to Workflows → Import from File
3. Select `wazuh_alert_enrichment_v2.json`
4. Configure credentials:
   - Click on "VirusTotal File Lookup" node → Set credentials
   - Click on Discord nodes → Set webhook credentials
5. Activate the workflow

### Wazuh Integration

Add this integration block to your Wazuh config (`/var/ossec/etc/ossec.conf`):

```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://<n8n-server>:5678/webhook/wazuh-alerts</hook_url>
  <level>6</level>
  <alert_format>json</alert_format>
</integration>
```

Alerts with level >= 6 will be sent to N8N.

### Severity Levels

| Wazuh Level | Severity | Action |
|-------------|----------|--------|
| 14-15 | CRITICAL | Detailed Discord alert |
| 12-13 | HIGH | Standard Discord alert |
| 10-11 | MEDIUM | Standard Discord alert |
| < 10 | LOW | Standard Discord alert |

If VirusTotal returns >= 10 malicious detections, severity is upgraded to CRITICAL.

### Extracted Fields

From Sysmon events:
- `hash_sha256` - File hash for VT lookup
- `process_name` - Executable path
- `command_line` - Full command line
- `dest_ip` / `dest_port` - Network destination
- `source_ip` - Network source

From Wazuh:
- `rule_id` / `rule_level` / `rule_description`
- `mitre_ids` / `mitre_tactics`
- `agent_name` / `agent_ip`
- `groups` (malware family tags)

### CLI Import

```bash
# Import workflow via N8N CLI
n8n import:workflow --input=wazuh_alert_enrichment_v2.json

# Import credentials (create JSON first)
n8n import:credentials --input=credentials.json

# Activate workflow
n8n update:workflow --id=<workflow-id> --active=true
```

### Testing

Send a test alert to the webhook:

```bash
curl -X POST http://<n8n-server>:5678/webhook/wazuh-alerts \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-01-01T00:00:00Z",
    "rule": {
      "id": "100110",
      "level": 12,
      "description": "Test Alert",
      "mitre": {"id": ["T1053.005"], "tactic": ["Persistence"]},
      "groups": ["test"]
    },
    "agent": {"name": "test-agent", "ip": "10.0.0.1"}
  }'
```
