// ─────────────────────────────────────────────────────────────────────────────
// Claude Audit Monitor – Main Server
// REST API + WebSocket for real-time dashboard
// ─────────────────────────────────────────────────────────────────────────────
import express from "express";
import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import cors from "cors";
import { randomUUID } from "crypto";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { initDb, insertEvent, getEvents, getEvent, getSessions, upsertSession, getAlerts, getAlertRules, updateAlertRule, getStats, exportEvents, } from "./db.js";
import { detectNHIs, queueIntentAnalysis } from "./analyzer.js";
import { evaluateEvent, onAlert } from "./policy.js";
const PORT = parseInt(process.env.CAM_PORT ?? "7842");
const __dirname = dirname(fileURLToPath(import.meta.url));
// ── Init ────────────────────────────────────────────────────────────────────
initDb();
const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
const httpServer = createServer(app);
const wss = new WebSocketServer({ server: httpServer });
// ── WebSocket broadcast ─────────────────────────────────────────────────────
function broadcast(msg) {
    const data = JSON.stringify(msg);
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN)
            client.send(data);
    });
}
wss.on("connection", (ws) => {
    // Send current stats on connect
    ws.send(JSON.stringify({ type: "stats", data: getStats() }));
});
// Forward alerts to WebSocket
onAlert((alert) => {
    broadcast({ type: "alert", data: alert });
});
// ── Core event ingestion ────────────────────────────────────────────────────
async function ingestEvent(payload, phase) {
    const event = {
        id: randomUUID(),
        session_id: payload.session_id,
        timestamp: Date.now(),
        phase,
        tool_name: payload.tool_name,
        tool_input: payload.tool_input,
        tool_response: payload.tool_response,
        cwd: payload.cwd,
        model: payload.model,
        mcp_server: inferMcpServer(payload.tool_name),
    };
    // Detect non-human identities immediately (synchronous)
    event.identities = detectNHIs(event);
    // Quick policy check before async analysis (for blocking)
    const quickCheck = evaluateEvent(event);
    if (quickCheck.blocked) {
        event.flagged = true;
        event.flag_reason = quickCheck.flag_reason;
        insertEvent(event);
        upsertSession({
            id: event.session_id,
            cwd: event.cwd,
            flagged_events: 1,
        });
        broadcast({ type: "event", data: event });
        return { blocked: true, event_id: event.id, alerts: quickCheck.alerts };
    }
    // Async intent analysis (doesn't block the response)
    insertEvent(event);
    upsertSession({ id: event.session_id, cwd: event.cwd });
    broadcast({ type: "event", data: event });
    // Queue async analysis — updates the event once complete
    queueIntentAnalysis(event).then((intent) => {
        event.intent = intent;
        // Re-evaluate with full intent analysis
        const fullCheck = evaluateEvent(event);
        event.flagged = fullCheck.blocked || fullCheck.alerts.length > 0;
        event.flag_reason = fullCheck.flag_reason;
        // Update stored event with intent
        insertEvent(event);
        const riskScore = intent.risk_level === "critical" ? 1.0
            : intent.risk_level === "high" ? 0.7
                : intent.risk_level === "medium" ? 0.4
                    : 0.1;
        upsertSession({
            id: event.session_id,
            risk_score: riskScore,
            flagged_events: fullCheck.alerts.length > 0 ? 1 : 0,
            total_cost_usd: event.cost_usd ?? 0,
        });
        broadcast({ type: "event", data: event });
        broadcast({ type: "stats", data: getStats() });
    });
    return { blocked: false, event_id: event.id, alerts: quickCheck.alerts };
}
function inferMcpServer(toolName) {
    const mcpTools = {
        create_issue: "github-mcp",
        list_issues: "github-mcp",
        create_pull_request: "github-mcp",
        search_code: "github-mcp",
        create_task: "asana-mcp",
        list_tasks: "asana-mcp",
        search_files: "gdrive-mcp",
        create_file: "gdrive-mcp",
        send_email: "gmail-mcp",
        list_messages: "gmail-mcp",
        query_database: "database-mcp",
        execute_query: "database-mcp",
        slack_post_message: "slack-mcp",
        Bash: "claude-code-native",
        Read: "claude-code-native",
        Write: "claude-code-native",
        Edit: "claude-code-native",
        MultiEdit: "claude-code-native",
        Glob: "claude-code-native",
        Grep: "claude-code-native",
        LS: "claude-code-native",
        Task: "claude-code-native",
        WebFetch: "claude-code-native",
        WebSearch: "claude-code-native",
        TodoRead: "claude-code-native",
        TodoWrite: "claude-code-native",
        NotebookRead: "claude-code-native",
        NotebookEdit: "claude-code-native",
        computer: "claude-code-native",
    };
    return mcpTools[toolName];
}
// ── API Routes ──────────────────────────────────────────────────────────────
// Hook endpoints — called by Claude Code hooks
app.post("/hooks/pre", async (req, res) => {
    try {
        const payload = req.body;
        const result = await ingestEvent(payload, "pre");
        if (result.blocked) {
            res.status(200).json({
                action: "block",
                message: `[Claude Audit Monitor] Tool call BLOCKED by policy: ${payload.tool_name}`,
            });
        }
        else {
            res.status(200).json({ action: "continue" });
        }
    }
    catch (err) {
        console.error("Hook error:", err);
        res.status(200).json({ action: "continue" }); // Fail open
    }
});
app.post("/hooks/post", async (req, res) => {
    try {
        const payload = req.body;
        await ingestEvent(payload, "post");
        res.status(200).json({ ok: true });
    }
    catch (err) {
        console.error("Hook error:", err);
        res.status(200).json({ ok: true });
    }
});
// REST API
app.get("/api/stats", (_req, res) => res.json(getStats()));
app.get("/api/events", (req, res) => {
    const { limit, offset, session_id, tool_name, flagged, since } = req.query;
    res.json(getEvents({
        limit: limit ? parseInt(String(limit)) : 100,
        offset: offset ? parseInt(String(offset)) : 0,
        session_id: session_id,
        tool_name: tool_name,
        flagged: flagged === "true" ? true : flagged === "false" ? false : undefined,
        since: since ? parseInt(String(since)) : undefined,
    }));
});
app.get("/api/events/:id", (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        res.status(404).json({ error: "Not found" });
        return;
    }
    res.json(event);
});
app.get("/api/sessions", (_req, res) => res.json(getSessions()));
app.get("/api/alerts", (_req, res) => res.json(getAlerts()));
app.get("/api/rules", (_req, res) => res.json(getAlertRules()));
app.patch("/api/rules/:id", (req, res) => {
    updateAlertRule(req.params.id, req.body);
    res.json({ ok: true });
});
app.get("/api/export", (req, res) => {
    const format = req.query.format ?? "json";
    const since = req.query.since ? parseInt(String(req.query.since)) : undefined;
    const data = exportEvents(format, since);
    const mime = format === "csv" ? "text/csv" : "application/json";
    res.setHeader("Content-Type", mime);
    res.setHeader("Content-Disposition", `attachment; filename="audit-${Date.now()}.${format}"`);
    res.send(data);
});
// Dashboard — serve static HTML
app.get("/dashboard", (_req, res) => {
    res.sendFile(join(__dirname, "../public/dashboard.html"));
});
// Redirect root to dashboard
app.get("/", (_req, res) => {
    res.redirect("/dashboard");
});
// Health check
app.get("/health", (_req, res) => res.json({ ok: true, port: PORT }));
// ── Start ────────────────────────────────────────────────────────────────────
httpServer.listen(PORT, () => {
    console.log(`\n  Claude Audit Monitor running on http://localhost:${PORT}`);
    console.log(`  Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`  Hook URL:  http://localhost:${PORT}/hooks/{pre,post}`);
    console.log(`  WebSocket: ws://localhost:${PORT}\n`);
});
//# sourceMappingURL=server.js.map