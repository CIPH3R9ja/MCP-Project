// ─────────────────────────────────────────────────────────────────────────────
// Claude Audit Monitor – Database Layer (SQLite)
// ─────────────────────────────────────────────────────────────────────────────

import Database from "better-sqlite3";
import { mkdirSync } from "fs"; // synchronous — must exist before DB opens
import { join } from "path";
import { homedir } from "os";
import type {
  ToolEvent,
  Session,
  Alert,
  AlertRule,
  MonitorStats,
} from "./types.js";

const DB_DIR = join(homedir(), ".claude-audit-monitor");
const DB_PATH = process.env.CAM_DB_PATH || join(DB_DIR, "audit.db");

let db: Database.Database;

export function initDb(): void {
  // Ensure directory exists synchronously before opening the database
  mkdirSync(DB_DIR, { recursive: true });

  db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      user_id TEXT,
      timestamp INTEGER NOT NULL,
      phase TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      tool_input TEXT NOT NULL,
      tool_response TEXT,
      duration_ms INTEGER,
      mcp_server TEXT,
      cwd TEXT,
      model TEXT,
      tokens_used INTEGER,
      cost_usd REAL,
      flagged INTEGER DEFAULT 0,
      flag_reason TEXT,
      intent TEXT,
      identities TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool_name);
    CREATE INDEX IF NOT EXISTS idx_events_flagged ON events(flagged);

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      started_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL,
      user_id TEXT,
      cwd TEXT,
      event_count INTEGER DEFAULT 0,
      total_cost_usd REAL DEFAULT 0,
      risk_score REAL DEFAULT 0,
      flagged_events INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      rule_id TEXT NOT NULL,
      rule_name TEXT NOT NULL,
      event_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      resolved INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS alert_rules (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      enabled INTEGER DEFAULT 1,
      condition TEXT NOT NULL,
      action TEXT NOT NULL,
      severity TEXT NOT NULL
    );
  `);

  seedDefaultRules();
}

// ── Default alert rules ────────────────────────────────────────────────────

function seedDefaultRules(): void {
  const existing = db
    .prepare("SELECT COUNT(*) as c FROM alert_rules")
    .get() as { c: number };
  if (existing.c > 0) return;

  const rules: AlertRule[] = [
    {
      id: "rule-rm-rf",
      name: "Destructive Shell Command",
      description: "Detects rm -rf or similar destructive commands",
      enabled: true,
      condition: { type: "pattern_match", field: "tool_input", value: "rm -rf|rmdir /s|del /f" },
      action: "block",
      severity: "critical",
    },
    {
      id: "rule-secret-exposure",
      name: "Secret / API Key Exposure",
      description: "Detects API keys, tokens, or secrets in tool calls",
      enabled: true,
      condition: { type: "identity_exposed", value: "api_key|token|secret|password" },
      action: "notify",
      severity: "critical",
    },
    {
      id: "rule-high-risk",
      name: "High Risk Intent",
      description: "Flags events with high or critical risk analysis",
      enabled: true,
      condition: { type: "risk_level", value: "high" },
      action: "notify",
      severity: "warning",
    },
    {
      id: "rule-prod-write",
      name: "Production Data Write",
      description: "Detects writes to production databases or systems",
      enabled: true,
      condition: { type: "pattern_match", field: "tool_input", value: "production|prod_|_prod" },
      action: "notify",
      severity: "warning",
    },
    {
      id: "rule-exfil",
      name: "Potential Data Exfiltration",
      description: "Detects large outbound data transfers or curl/wget to external hosts",
      enabled: true,
      condition: { type: "pattern_match", field: "tool_input", value: "curl|wget|fetch.*http" },
      action: "notify",
      severity: "warning",
    },
    {
      id: "rule-sudo",
      name: "Privilege Escalation Attempt",
      description: "Detects sudo or privilege escalation commands",
      enabled: true,
      condition: { type: "pattern_match", field: "tool_input", value: "sudo |su -|chmod 777" },
      action: "block",
      severity: "critical",
    },
  ];

  const insert = db.prepare(`
    INSERT OR IGNORE INTO alert_rules (id, name, description, enabled, condition, action, severity)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  for (const rule of rules) {
    insert.run(
      rule.id,
      rule.name,
      rule.description,
      rule.enabled ? 1 : 0,
      JSON.stringify(rule.condition),
      rule.action,
      rule.severity
    );
  }
}

// ── Event operations ───────────────────────────────────────────────────────

export function insertEvent(event: ToolEvent): void {
  db.prepare(`
    INSERT OR REPLACE INTO events
    (id, session_id, user_id, timestamp, phase, tool_name, tool_input,
     tool_response, duration_ms, mcp_server, cwd, model, tokens_used,
     cost_usd, flagged, flag_reason, intent, identities)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    event.id,
    event.session_id,
    event.user_id ?? null,
    event.timestamp,
    event.phase,
    event.tool_name,
    JSON.stringify(event.tool_input),
    event.tool_response ? JSON.stringify(event.tool_response) : null,
    event.duration_ms ?? null,
    event.mcp_server ?? null,
    event.cwd ?? null,
    event.model ?? null,
    event.tokens_used ?? null,
    event.cost_usd ?? null,
    event.flagged ? 1 : 0,
    event.flag_reason ?? null,
    event.intent ? JSON.stringify(event.intent) : null,
    event.identities ? JSON.stringify(event.identities) : null
  );
}

export function getEvents(opts: {
  limit?: number;
  offset?: number;
  session_id?: string;
  tool_name?: string;
  flagged?: boolean;
  since?: number;
}): ToolEvent[] {
  const clauses: string[] = [];
  const params: unknown[] = [];

  if (opts.session_id) { clauses.push("session_id = ?"); params.push(opts.session_id); }
  if (opts.tool_name) { clauses.push("tool_name = ?"); params.push(opts.tool_name); }
  if (opts.flagged !== undefined) { clauses.push("flagged = ?"); params.push(opts.flagged ? 1 : 0); }
  if (opts.since) { clauses.push("timestamp >= ?"); params.push(opts.since); }

  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  params.push(opts.limit ?? 100);
  params.push(opts.offset ?? 0);

  const rows = db
    .prepare(`SELECT * FROM events ${where} ORDER BY timestamp DESC LIMIT ? OFFSET ?`)
    .all(...params) as Record<string, unknown>[];

  return rows.map(parseEventRow);
}

export function getEvent(id: string): ToolEvent | null {
  const row = db.prepare("SELECT * FROM events WHERE id = ?").get(id) as
    | Record<string, unknown>
    | undefined;
  return row ? parseEventRow(row) : null;
}

function parseEventRow(row: Record<string, unknown>): ToolEvent {
  return {
    ...row,
    tool_input: JSON.parse(row.tool_input as string),
    tool_response: row.tool_response
      ? JSON.parse(row.tool_response as string)
      : undefined,
    intent: row.intent ? JSON.parse(row.intent as string) : undefined,
    identities: row.identities ? JSON.parse(row.identities as string) : undefined,
    flagged: Boolean(row.flagged),
  } as ToolEvent;
}

// ── Session operations ─────────────────────────────────────────────────────

export function upsertSession(data: Partial<Session> & { id: string }): void {
  const existing = db
    .prepare("SELECT * FROM sessions WHERE id = ?")
    .get(data.id) as Session | undefined;

  if (!existing) {
    db.prepare(`
      INSERT INTO sessions (id, started_at, last_seen_at, user_id, cwd, event_count, total_cost_usd, risk_score, flagged_events)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      data.id,
      data.started_at ?? Date.now(),
      data.last_seen_at ?? Date.now(),
      data.user_id ?? null,
      data.cwd ?? null,
      data.event_count ?? 0,
      data.total_cost_usd ?? 0,
      data.risk_score ?? 0,
      data.flagged_events ?? 0
    );
  } else {
    db.prepare(`
      UPDATE sessions SET
        last_seen_at = ?,
        event_count = event_count + 1,
        total_cost_usd = total_cost_usd + ?,
        risk_score = ?,
        flagged_events = flagged_events + ?
      WHERE id = ?
    `).run(
      Date.now(),
      data.total_cost_usd ?? 0,
      data.risk_score ?? existing.risk_score,
      data.flagged_events ?? 0,
      data.id
    );
  }
}

export function getSessions(limit = 50): Session[] {
  return db
    .prepare("SELECT * FROM sessions ORDER BY last_seen_at DESC LIMIT ?")
    .all(limit) as Session[];
}

// ── Alert operations ───────────────────────────────────────────────────────

export function insertAlert(alert: Alert): void {
  db.prepare(`
    INSERT INTO alerts (id, rule_id, rule_name, event_id, session_id, timestamp, severity, message, resolved)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    alert.id,
    alert.rule_id,
    alert.rule_name,
    alert.event_id,
    alert.session_id,
    alert.timestamp,
    alert.severity,
    alert.message,
    alert.resolved ? 1 : 0
  );
}

export function getAlerts(limit = 100): Alert[] {
  return (
    db
      .prepare("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?")
      .all(limit) as Record<string, unknown>[]
  ).map((r) => ({ ...r, resolved: Boolean(r.resolved) } as Alert));
}

export function getAlertRules(): AlertRule[] {
  return (
    db.prepare("SELECT * FROM alert_rules").all() as Record<string, unknown>[]
  ).map((r) => ({
    ...r,
    enabled: Boolean(r.enabled),
    condition: JSON.parse(r.condition as string),
  } as AlertRule));
}

export function updateAlertRule(id: string, update: Partial<AlertRule>): void {
  if (update.enabled !== undefined) {
    db.prepare("UPDATE alert_rules SET enabled = ? WHERE id = ?").run(
      update.enabled ? 1 : 0,
      id
    );
  }
}

// ── Stats ──────────────────────────────────────────────────────────────────

export function getStats(): MonitorStats {
  const oneHourAgo = Date.now() - 3600_000;

  const totals = db
    .prepare("SELECT COUNT(*) as events, SUM(cost_usd) as cost, SUM(flagged) as flagged FROM events")
    .get() as { events: number; cost: number; flagged: number };

  const sessions = db
    .prepare("SELECT COUNT(*) as c FROM sessions")
    .get() as { c: number };

  const alertCount = db
    .prepare("SELECT COUNT(*) as c FROM alerts")
    .get() as { c: number };

  const eventsLastHour = db
    .prepare("SELECT COUNT(*) as c FROM events WHERE timestamp >= ?")
    .get(oneHourAgo) as { c: number };

  const topTools = db
    .prepare(
      "SELECT tool_name as tool, COUNT(*) as count FROM events GROUP BY tool_name ORDER BY count DESC LIMIT 8"
    )
    .all() as Array<{ tool: string; count: number }>;

  const risks = db
    .prepare(`
      SELECT
        SUM(CASE WHEN json_extract(intent, '$.risk_level') = 'low' THEN 1 ELSE 0 END) as low,
        SUM(CASE WHEN json_extract(intent, '$.risk_level') = 'medium' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN json_extract(intent, '$.risk_level') = 'high' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN json_extract(intent, '$.risk_level') = 'critical' THEN 1 ELSE 0 END) as critical
      FROM events WHERE intent IS NOT NULL
    `)
    .get() as { low: number; medium: number; high: number; critical: number };

  return {
    total_events: totals.events ?? 0,
    total_sessions: sessions.c ?? 0,
    total_alerts: alertCount.c ?? 0,
    flagged_events: totals.flagged ?? 0,
    total_cost_usd: totals.cost ?? 0,
    events_last_hour: eventsLastHour.c ?? 0,
    top_tools: topTools,
    risk_breakdown: risks ?? { low: 0, medium: 0, high: 0, critical: 0 },
  };
}

export function exportEvents(format: "json" | "csv", since?: number): string {
  const events = getEvents({ limit: 10_000, since });

  if (format === "json") {
    return JSON.stringify(events, null, 2);
  }

  const headers = [
    "id", "session_id", "timestamp", "phase", "tool_name",
    "mcp_server", "flagged", "risk_level", "cost_usd", "duration_ms",
  ];
  const rows = events.map((e) =>
    [
      e.id, e.session_id, new Date(e.timestamp).toISOString(),
      e.phase, e.tool_name, e.mcp_server ?? "",
      e.flagged, e.intent?.risk_level ?? "", e.cost_usd ?? 0, e.duration_ms ?? 0,
    ].join(",")
  );
  return [headers.join(","), ...rows].join("\n");
}
