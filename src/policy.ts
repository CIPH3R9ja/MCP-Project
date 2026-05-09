// ─────────────────────────────────────────────────────────────────────────────
// Claude Audit Monitor – Policy Engine
// Evaluates alert rules against events, can block tool calls
// ─────────────────────────────────────────────────────────────────────────────

import { randomUUID } from "crypto";
import { getAlertRules, insertAlert } from "./db.js";
import type { Alert, AlertRule, ToolEvent } from "./types.js";

type AlertCallback = (alert: Alert) => void;

const callbacks: AlertCallback[] = [];

export function onAlert(cb: AlertCallback): void {
  callbacks.push(cb);
}

function emit(alert: Alert): void {
  insertAlert(alert);
  for (const cb of callbacks) cb(alert);
}

export function evaluateEvent(event: ToolEvent): {
  blocked: boolean;
  alerts: Alert[];
  flag_reason?: string;
} {
  const rules = getAlertRules().filter((r) => r.enabled);
  const triggeredAlerts: Alert[] = [];
  let blocked = false;
  let flag_reason: string | undefined;

  for (const rule of rules) {
    const matched = testRule(rule, event);
    if (!matched) continue;

    const alert: Alert = {
      id: randomUUID(),
      rule_id: rule.id,
      rule_name: rule.name,
      event_id: event.id,
      session_id: event.session_id,
      timestamp: Date.now(),
      severity: rule.severity,
      message: buildMessage(rule, event),
      resolved: false,
    };

    triggeredAlerts.push(alert);
    emit(alert);

    if (rule.action === "block") {
      blocked = true;
      flag_reason = rule.name;
    }

    if (!flag_reason && rule.action === "notify") {
      flag_reason = rule.name;
    }
  }

  // Also flag based on intent analysis result
  if (event.intent?.risk_level === "critical" || event.intent?.risk_level === "high") {
    if (!triggeredAlerts.length) {
      const alert: Alert = {
        id: randomUUID(),
        rule_id: "auto-risk",
        rule_name: "Elevated Risk Intent",
        event_id: event.id,
        session_id: event.session_id,
        timestamp: Date.now(),
        severity: event.intent.risk_level === "critical" ? "critical" : "warning",
        message: `AI intent analysis flagged ${event.intent.risk_level} risk: ${event.intent.risk_reasons.join("; ")}`,
        resolved: false,
      };
      triggeredAlerts.push(alert);
      emit(alert);
      flag_reason = flag_reason ?? "Elevated risk intent";
    }
  }

  // Flag if NHIs detected
  if (event.identities && event.identities.length > 0) {
    const services = event.identities.map((i) => i.service).join(", ");
    const alert: Alert = {
      id: randomUUID(),
      rule_id: "auto-nhi",
      rule_name: "Non-Human Identity Detected",
      event_id: event.id,
      session_id: event.session_id,
      timestamp: Date.now(),
      severity: "critical",
      message: `Credentials detected in tool call: ${services}. Possible secret exposure.`,
      resolved: false,
    };
    triggeredAlerts.push(alert);
    emit(alert);
    flag_reason = flag_reason ?? `Credentials exposed (${services})`;
  }

  return { blocked, alerts: triggeredAlerts, flag_reason };
}

function testRule(rule: AlertRule, event: ToolEvent): boolean {
  const { condition } = rule;
  const inputStr = JSON.stringify(event.tool_input).toLowerCase();
  const responseStr = JSON.stringify(event.tool_response ?? {}).toLowerCase();
  const fullText = inputStr + " " + responseStr;

  switch (condition.type) {
    case "tool_match":
      return event.tool_name.toLowerCase() === String(condition.value).toLowerCase();

    case "pattern_match": {
      const patterns = String(condition.value).split("|");
      const searchIn = condition.field === "tool_input" ? inputStr : fullText;
      return patterns.some((p) => searchIn.includes(p.toLowerCase()));
    }

    case "risk_level": {
      const levels = ["low", "medium", "high", "critical"];
      const threshold = levels.indexOf(String(condition.value));
      const actual = levels.indexOf(event.intent?.risk_level ?? "low");
      return actual >= threshold;
    }

    case "identity_exposed":
      return Boolean(event.identities && event.identities.length > 0);

    case "rate_limit":
      return false;

    default:
      return false;
  }
}

function buildMessage(rule: AlertRule, event: ToolEvent): string {
  return `[${rule.name}] Tool "${event.tool_name}" in session ${event.session_id.slice(0, 8)} triggered rule "${rule.description ?? rule.name}"`;
}
