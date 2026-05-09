# Claude Audit Monitor (CAM)

> Enterprise-grade activity monitoring for Claude Code and MCP servers. Real-time session telemetry, AI-powered intent analysis, policy enforcement, NHI detection, and SIEM integration.

---

## What it does

| Feature | Description |
|---|---|
| MCP tool call logging | Captures every tool call with full input/output |
| Pre/Post hook capture | Hooks into Claude Code's PreToolUse and PostToolUse events |
| Session correlation | Groups events by Claude Code session ID |
| NHI (credential) detection | Scans for exposed API keys, tokens, secrets |
| AI intent analysis | Full Claude API analysis of each tool call |
| Real-time blocking | Block tool calls before they execute |
| Configurable alert rules | 6 built-in rules + custom rule support |
| Policy engine | Block/Notify/Log actions per rule |
| SQLite local storage | No external dependency required |
| SIEM export | JSON and CSV export endpoints |
| WebSocket live stream | Real-time dashboard updates |
| REST API | Full programmatic access |

---

## Quick Start

### 1. Install dependencies and build

```bash
npm install
npm run build
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY
```

### 3. Start the server

```bash
npm start
# → Server running at http://localhost:7842
# → Dashboard: http://localhost:7842/dashboard
```

### 4. Install Claude Code hooks

```bash
mkdir -p ~/.claude/hooks
cp hooks/cam-pre-tool.mjs ~/.claude/hooks/
cp hooks/cam-post-tool.mjs ~/.claude/hooks/
chmod +x ~/.claude/hooks/cam-pre-tool.mjs
chmod +x ~/.claude/hooks/cam-post-tool.mjs
```

Then merge the hooks block from `config/claude-settings-snippet.json` into your `~/.claude/settings.json`.

### 5. Open the dashboard

Visit `http://localhost:7842/dashboard`

---

## Development

```bash
npm run dev   # tsx watch — hot reload
```

---

## Docker

```bash
docker build -t claude-audit-monitor .

docker run -d \
  -p 7842:7842 \
  -v ~/.claude-audit-monitor:/data \
  -e CAM_DB_PATH=/data/audit.db \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  claude-audit-monitor
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CAM_PORT` | `7842` | Server port |
| `CAM_DB_PATH` | `~/.claude-audit-monitor/audit.db` | SQLite database path |
| `CAM_URL` | `http://localhost:7842` | URL used by hook scripts |
| `ANTHROPIC_API_KEY` | _(required for AI analysis)_ | Anthropic API key |

If `ANTHROPIC_API_KEY` is not set, CAM falls back to rule-based analysis (fully offline).

---

## REST API

```
GET  /api/stats              → Aggregate statistics
GET  /api/events             → List events (filterable)
GET  /api/events/:id         → Single event detail
GET  /api/sessions           → All sessions
GET  /api/alerts             → Alert history
GET  /api/rules              → Alert rules
PATCH /api/rules/:id         → Toggle rule on/off
GET  /api/export?format=json → Export audit log (json or csv)
GET  /health                 → Health check

POST /hooks/pre              → PreToolUse hook endpoint
POST /hooks/post             → PostToolUse hook endpoint
```

### Event query filters

```
?session_id=sess_xxx
?tool_name=Bash
?flagged=true
?since=1700000000000   (unix ms)
?limit=50&offset=0
```

---

## Alert Rules

Six built-in rules (all configurable via dashboard or API):

| Rule | Action | Severity |
|---|---|---|
| Destructive shell command (`rm -rf`, etc.) | **Block** | Critical |
| Secret / API key exposure | Notify | Critical |
| Privilege escalation (`sudo`, `chmod 777`) | **Block** | Critical |
| High risk AI intent | Notify | Warning |
| Production data write | Notify | Warning |
| External data exfiltration | Notify | Warning |

---

## Non-Human Identity Detection

CAM automatically scans all tool inputs and outputs for:

- Anthropic API keys (`sk-ant-*`)
- OpenAI API keys (`sk-*`)
- GitHub tokens (`ghp_`, `gho_`, `github_pat_`)
- AWS access keys (`AKIA*`)
- Stripe live keys (`sk_live_*`)
- Slack tokens (`xox*`)
- JWT tokens (`eyJ*`)
- GCP service accounts

---

## SIEM Integration

### WebSocket (real-time)

```javascript
const ws = new WebSocket('ws://localhost:7842');
ws.onmessage = ({ data }) => {
  const msg = JSON.parse(data);
  // msg.type: 'event' | 'alert' | 'session_update' | 'stats'
  if (msg.type === 'alert' && msg.data.severity === 'critical') {
    pagerDuty.trigger(msg.data);
  }
};
```

### Splunk HEC

```bash
curl http://localhost:7842/api/export?format=json | \
  jq -c '.[] | {event: ., sourcetype: "claude_audit"}' | \
  curl -X POST https://splunk:8088/services/collector/event \
    -H "Authorization: Splunk $SPLUNK_TOKEN" \
    -H "Content-Type: application/json" --data-binary @-
```

### Elastic / OpenSearch

```bash
curl http://localhost:7842/api/export?format=json | \
  jq -c '.[] | {"index":{"_index":"claude-audit"}}, .' | \
  curl -X POST http://elasticsearch:9200/_bulk \
    -H "Content-Type: application/x-ndjson" --data-binary @-
```

---

## Security Note

CAM runs entirely locally. No data leaves your machine except:
- Anthropic API calls for intent analysis (tool inputs only, truncated to 1500 chars)
- Whatever SIEM exports you configure

To keep everything fully offline, omit `ANTHROPIC_API_KEY`. CAM will use rule-based analysis instead.
