// ─────────────────────────────────────────────────────────────────────────────
// Claude Audit Monitor – Core Types
// ─────────────────────────────────────────────────────────────────────────────

export interface ToolEvent {
  id: string;
  session_id: string;
  user_id?: string;
  timestamp: number;
  phase: "pre" | "post";
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response?: Record<string, unknown>;
  duration_ms?: number;
  mcp_server?: string;
  cwd?: string;
  model?: string;
  tokens_used?: number;
  cost_usd?: number;
  flagged?: boolean;
  flag_reason?: string;
  intent?: IntentAnalysis;
  identities?: NonHumanIdentity[];
}

export interface IntentAnalysis {
  summary: string;
  category:
    | "code_generation"
    | "file_access"
    | "network_request"
    | "data_read"
    | "data_write"
    | "system_command"
    | "authentication"
    | "other";
  risk_level: "low" | "medium" | "high" | "critical";
  risk_reasons: string[];
  actions: string[];
  affected_resources: string[];
}

export interface NonHumanIdentity {
  type: "api_key" | "token" | "service_account" | "webhook" | "oauth";
  name: string;
  service?: string;
  masked_value?: string;
}

export interface Session {
  id: string;
  started_at: number;
  last_seen_at: number;
  user_id?: string;
  cwd?: string;
  event_count: number;
  total_cost_usd: number;
  risk_score: number;
  flagged_events: number;
}

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  condition: AlertCondition;
  action: "log" | "block" | "notify";
  severity: "info" | "warning" | "critical";
}

export interface AlertCondition {
  type:
    | "tool_match"
    | "risk_level"
    | "pattern_match"
    | "rate_limit"
    | "identity_exposed";
  value: string | number;
  field?: string;
}

export interface Alert {
  id: string;
  rule_id: string;
  rule_name: string;
  event_id: string;
  session_id: string;
  timestamp: number;
  severity: "info" | "warning" | "critical";
  message: string;
  resolved: boolean;
}

export interface MonitorStats {
  total_events: number;
  total_sessions: number;
  total_alerts: number;
  flagged_events: number;
  total_cost_usd: number;
  events_last_hour: number;
  top_tools: Array<{ tool: string; count: number }>;
  risk_breakdown: { low: number; medium: number; high: number; critical: number };
}

export interface HookPayload {
  session_id: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_response?: Record<string, unknown>;
  cwd?: string;
  model?: string;
}

// WebSocket message types
export type WSMessage =
  | { type: "event"; data: ToolEvent }
  | { type: "alert"; data: Alert }
  | { type: "session_update"; data: Session }
  | { type: "stats"; data: MonitorStats };
