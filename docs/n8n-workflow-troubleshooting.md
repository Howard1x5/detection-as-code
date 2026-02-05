# N8N Workflow Troubleshooting Guide

## Issue: Discord Alerts Showing "unknown" for All Fields

### Symptoms
- Alerts arrive in Discord but show:
  - Rule: unknown - No description
  - Severity: LOW
  - Agent: unknown
  - MITRE: N/A

### Root Cause

The N8N webhook node wraps incoming POST data in a `body` object. Combined with Wazuh's shuffle integration which wraps alert data in `all_fields`, the correct data path is:

```
$json.body.all_fields.rule
$json.body.all_fields.agent
```

NOT:
```
$json.all_fields.rule  (wrong - missing body wrapper)
$json.rule             (wrong - direct format only)
```

### Data Flow

```
Wazuh Alert JSON
    ↓
Shuffle Integration wraps in: { all_fields: <alert>, severity: X, ... }
    ↓
N8N Webhook wraps in: { body: <shuffle_data>, headers: {...}, ... }
    ↓
Final path: $json.body.all_fields.rule.description
```

### Debugging Steps

1. **Create a debug workflow** to inspect raw input:

```javascript
// Debug Code node
const input = $input.first().json;
return {
  raw_keys: Object.keys(input),
  has_all_fields: !!input.all_fields,
  has_body: !!input.body,
  body_keys: input.body ? Object.keys(input.body) : [],
  input_preview: JSON.stringify(input).substring(0, 500)
};
```

2. **Send test webhook** and check Discord for debug output

3. **Verify the data structure** - look for:
   - `has_body=true` → data is in `$json.body`
   - `has_all_fields=false` at top level but present in body

### The Fix

In the "Extract IOCs" code node, change:

```javascript
// WRONG
const data = alert.all_fields || alert.body || alert;

// CORRECT
const body = alert.body || alert;
const data = body.all_fields || body;
```

### Full Extraction Code

```javascript
const alert = $input.first().json;

// Handle N8N webhook body wrapper + Wazuh shuffle format
const body = alert.body || alert;
const data = body.all_fields || body;

let extracted = {
  timestamp: data.timestamp || new Date().toISOString(),
  rule_id: data.rule?.id || 'unknown',
  rule_level: data.rule?.level || 0,
  rule_description: data.rule?.description || 'No description',
  mitre_ids: data.rule?.mitre?.id || [],
  mitre_tactics: data.rule?.mitre?.tactic || [],
  agent_name: data.agent?.name || 'unknown',
  agent_ip: data.agent?.ip || 'unknown',
  // ... rest of extraction
};
```

### Wazuh Shuffle Integration Format

The Wazuh shuffle integration (`/var/ossec/integrations/shuffle.py`) sends:

```json
{
  "severity": 1-3,
  "pretext": "WAZUH Alert",
  "title": "<rule description>",
  "text": "<full_log>",
  "rule_id": "<rule id>",
  "timestamp": "<timestamp>",
  "id": "<alert id>",
  "all_fields": {
    "timestamp": "...",
    "rule": { "id": "...", "level": X, "description": "...", "mitre": {...} },
    "agent": { "name": "...", "ip": "..." },
    "data": { "win": { "eventdata": {...} } }
  }
}
```

### Testing After Fix

```bash
# Send test in exact shuffle format
curl -X POST "http://<n8n-server>:5678/webhook/wazuh-alerts" \
  -H "Content-Type: application/json" \
  -d '{
    "severity": 3,
    "all_fields": {
      "rule": {"id": "100999", "level": 12, "description": "Test"},
      "agent": {"name": "TEST-AGENT", "ip": "10.0.0.1"}
    }
  }'
```

### Preventing Workflow Conflicts

When importing workflows, N8N creates new workflows rather than updating existing ones. Multiple workflows with the same webhook path can cause conflicts.

**Solution:** After importing, deactivate all old workflows and activate only the newest one:

```bash
# List workflows
n8n list:workflow

# Deactivate old
n8n update:workflow --id=<old-id> --active=false

# Activate new
n8n update:workflow --id=<new-id> --active=true

# Restart N8N to clear webhook cache
systemctl restart n8n
```
