# Claude Audit Monitor (CAM)

> Enterprise-grade activity monitoring for Claude Code and MCP servers.  
> Real-time session telemetry, AI-powered intent analysis, policy enforcement, NHI detection, and SIEM integration.

---

## Clone & Deploy (production)

```bash
git clone https://github.com/CIPH3R9ja/MCP-Project.git claude-audit-monitor
cd claude-audit-monitor

# Set your Anthropic API key
cp .env.example .env
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env

# Install hook scripts into Claude Code + start server
bash install.sh
npm start
```

Open **http://localhost:7842/dashboard**

> No build step needed — compiled JS is included in the repo.

---

## Docker (recommended for production)

```bash
git clone https://github.com/CIPH3R9ja/MCP-Project.git claude-audit-monitor
cd claude-audit-monitor

docker build -t claude-audit-monitor .

docker run -d \
  --name cam \
  --restart unless-stopped \
  -p 7842:7842 \
  -v "$HOME/.claude-audit-monitor:/data" \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  claude-audit-monitor
```

---

## Manual setup

### 1. Install npm dependencies (runtime only)

```bash
npm ci --omit=dev
```

### 2. Install Claude Code hooks

```bash
mkdir -p ~/.claude/hooks
cp hooks/cam-pre-tool.mjs  ~/.claude/hooks/
cp hooks/cam-post-tool.mjs ~/.claude/hooks/
chmod +x ~/.claude/hooks/cam-*.mjs
```

Merge `config/claude-settings-snippet.json` into `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse":  [{ "matcher": ".*", "hooks": [{ "type": "command", "command": "node ~/.claude/hooks/cam-pre-tool.mjs"  }] }],
    "PostToolUse": [{ "matcher": ".*", "hooks": [{ "type": "command", "command": "node ~/.claude/hooks/cam-post-tool.mjs" }] }]
  }
}
```

### 3. Start the server

```bash
npm start
# → http://localhost:7842
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `CAM_PORT` | `7842` | Server port |
| `CAM_DB_PATH` | `~/.claude-audit-monitor/audit.db` | SQLite database path |
| `CAM_URL` | `http://localhost:7842` | URL used by hook scripts |
| `ANTHROPIC_API_KEY` | _(optional)_ | For AI intent analysis. Falls back to rule-based if unset. |

---

## REST API

```
GET  /api/stats
GET  /api/events[?tool_name=&session_id=&flagged=true&since=<ms>&limit=50&offset=0]
GET  /api/events/:id
GET  /api/sessions
GET  /api/alerts
GET  /api/rules
PATCH /api/rules/:id        { "enabled": true|false }
GET  /api/export?format=json|csv
GET  /health
POST /hooks/pre             ← Claude Code PreToolUse
POST /hooks/post            ← Claude Code PostToolUse
```

---

## WebSocket (real-time SIEM)

```js
const ws = new WebSocket('ws://localhost:7842');
ws.onmessage = ({ data }) => {
  const msg = JSON.parse(data);
  // msg.type: 'event' | 'alert' | 'session_update' | 'stats'
  if (msg.type === 'alert' && msg.data.severity === 'critical') {
    pagerDuty.trigger(msg.data);
  }
};
```

---

## Alert rules (built-in)

| Rule | Action | Severity |
|---|---|---|
| `rm -rf` / destructive shell | **Block** | Critical |
| Privilege escalation (`sudo`, `chmod 777`) | **Block** | Critical |
| Secret / API key exposure | Notify | Critical |
| High-risk AI intent | Notify | Warning |
| Production data write | Notify | Warning |
| Potential data exfiltration | Notify | Warning |

Toggle rules via the dashboard or `PATCH /api/rules/:id`.

---

## Development

```bash
npm install
npm run dev     # tsx watch — hot reload
```

---

## Architecture

```
Claude Code (terminal)
    │
    ├── PreToolUse hook  → cam-pre-tool.mjs  → POST /hooks/pre
    │                                               │
    │                                         ┌────▼────┐
    │                                         │  CAM    │
    │                                         │ Server  │
    │                                         └────┬────┘
    ├── PostToolUse hook → cam-post-tool.mjs → POST /hooks/post
    │                                               │
    │                                   ┌───────────▼────────────┐
    │                                   │   SQLite Audit DB      │
    │                                   └───────────┬────────────┘
    │                                               │
    │                                   ┌───────────▼────────────┐
    │                                   │  Claude API            │
    │                                   │  Intent Analyzer       │
    │                                   └───────────┬────────────┘
    │                                               │
    │                                   ┌───────────▼────────────┐
    │                                   │  Policy Engine         │
    │                                   │  (block / notify)      │
    │                                   └───────────┬────────────┘
    │                                               │
    └─ WebSocket ───────────────────────── Dashboard / SIEM
```
