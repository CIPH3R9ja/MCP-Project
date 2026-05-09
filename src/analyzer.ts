// ─────────────────────────────────────────────────────────────────────────────
// Claude Audit Monitor – Intent Analyzer
// Uses Claude API to analyze tool calls for intent, risk, and NHI detection
// ─────────────────────────────────────────────────────────────────────────────

import Anthropic from "@anthropic-ai/sdk";
import type { IntentAnalysis, NonHumanIdentity, ToolEvent } from "./types.js";

const client = new Anthropic();

// Regex patterns for detecting non-human identities inline
const NHI_PATTERNS: Array<{
  type: NonHumanIdentity["type"];
  service: string;
  pattern: RegExp;
}> = [
  { type: "api_key", service: "Anthropic", pattern: /sk-ant-[a-zA-Z0-9\-_]{20,}/g },
  { type: "api_key", service: "OpenAI", pattern: /sk-[a-zA-Z0-9]{48}/g },
  { type: "token", service: "GitHub", pattern: /gh[pousr]_[a-zA-Z0-9]{36}/g },
  { type: "token", service: "GitHub", pattern: /github_pat_[a-zA-Z0-9_]{82}/g },
  { type: "api_key", service: "AWS", pattern: /AKIA[0-9A-Z]{16}/g },
  { type: "api_key", service: "Stripe", pattern: /sk_live_[a-zA-Z0-9]{24}/g },
  { type: "api_key", service: "Slack", pattern: /xox[baprs]-[a-zA-Z0-9\-]+/g },
  // Generic high-entropy strings — only checked when no specific pattern matched
  { type: "api_key", service: "Generic", pattern: /[a-zA-Z0-9]{32,64}/g },
  { type: "token", service: "JWT", pattern: /eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/g },
  { type: "service_account", service: "GCP", pattern: /"type":\s*"service_account"/g },
];

export function detectNHIs(event: ToolEvent): NonHumanIdentity[] {
  const text = JSON.stringify(event.tool_input) + JSON.stringify(event.tool_response ?? {});
  const found: NonHumanIdentity[] = [];
  const seen = new Set<string>();

  for (const { type, service, pattern } of NHI_PATTERNS) {
    // Skip generic patterns if specific ones already matched
    if (service === "Generic" && found.length > 0) continue;

    const matches = text.matchAll(pattern);
    for (const match of matches) {
      const val = match[0];
      if (val.length < 16) continue;
      const key = `${type}:${service}:${val.slice(0, 8)}`;
      if (!seen.has(key)) {
        seen.add(key);
        found.push({
          type,
          service,
          name: `${service} ${type}`,
          masked_value: val.slice(0, 6) + "..." + val.slice(-4),
        });
      }
    }
  }

  return found;
}

// Intent analysis cache to avoid re-analyzing identical calls
const intentCache = new Map<string, IntentAnalysis>();

export async function analyzeIntent(event: ToolEvent): Promise<IntentAnalysis> {
  const cacheKey = `${event.tool_name}:${JSON.stringify(event.tool_input).slice(0, 200)}`;
  if (intentCache.has(cacheKey)) return intentCache.get(cacheKey)!;

  const prompt = `You are a security analyst reviewing Claude AI agent tool calls for an enterprise audit system.

Analyze this tool call and return a JSON object (no markdown, no backticks):

Tool: ${event.tool_name}
MCP Server: ${event.mcp_server ?? "Claude Code native"}
Input: ${JSON.stringify(event.tool_input, null, 2).slice(0, 1500)}
Response preview: ${JSON.stringify(event.tool_response ?? {}).slice(0, 500)}

Return ONLY this JSON structure:
{
  "summary": "1-2 sentence plain English description of what the agent is doing",
  "category": one of ["code_generation","file_access","network_request","data_read","data_write","system_command","authentication","other"],
  "risk_level": one of ["low","medium","high","critical"],
  "risk_reasons": ["reason1", "reason2"],
  "actions": ["specific action 1", "specific action 2"],
  "affected_resources": ["resource paths, URLs, DB tables, etc"]
}

Risk guidelines:
- low: reading files, generating code, non-destructive queries
- medium: modifying files, calling external APIs, accessing credentials stores
- high: deleting data, executing system commands, accessing production systems, secrets handling
- critical: privilege escalation, mass deletion, exfiltration patterns, disabling security controls`;

  try {
    const response = await client.messages.create({
      model: "claude-sonnet-4-6", // Fixed: was claude-sonnet-4-20250514
      max_tokens: 600,
      messages: [{ role: "user", content: prompt }],
    });

    const text = response.content
      .filter((b) => b.type === "text")
      .map((b) => (b as { type: "text"; text: string }).text)
      .join("");

    const analysis = JSON.parse(text.trim()) as IntentAnalysis;
    intentCache.set(cacheKey, analysis);
    // Keep cache bounded
    if (intentCache.size > 500) {
      const firstKey = intentCache.keys().next().value;
      if (firstKey) intentCache.delete(firstKey);
    }
    return analysis;
  } catch {
    // Fallback: rule-based analysis when API is unavailable
    return fallbackAnalysis(event);
  }
}

function fallbackAnalysis(event: ToolEvent): IntentAnalysis {
  const input = JSON.stringify(event.tool_input).toLowerCase();
  const tool = event.tool_name.toLowerCase();

  let risk_level: IntentAnalysis["risk_level"] = "low";
  const risk_reasons: string[] = [];

  if (/rm\s+-rf|rmdir|del\s+\/f/.test(input)) {
    risk_level = "critical";
    risk_reasons.push("Destructive delete command detected");
  } else if (/sudo|chmod\s+777|su\s+-/.test(input)) {
    risk_level = "critical";
    risk_reasons.push("Privilege escalation detected");
  } else if (/password|secret|api_key|token/.test(input)) {
    risk_level = "high";
    risk_reasons.push("Sensitive credential handling");
  } else if (/curl|wget|http/.test(input)) {
    risk_level = "medium";
    risk_reasons.push("External network request");
  } else if (/write|create|update|insert|delete/.test(tool)) {
    risk_level = "medium";
    risk_reasons.push("Data modification operation");
  }

  const categoryMap: Record<string, IntentAnalysis["category"]> = {
    bash: "system_command",
    read_file: "file_access",
    write_file: "data_write",
    create_file: "data_write",
    list_directory: "file_access",
    web_search: "network_request",
    web_fetch: "network_request",
  };

  return {
    summary: `${event.tool_name} tool call (auto-classified)`,
    category: categoryMap[tool] ?? "other",
    risk_level,
    risk_reasons: risk_reasons.length ? risk_reasons : ["No specific risks identified"],
    actions: [event.tool_name],
    affected_resources: [],
  };
}

// Async batch processor — doesn't block the event pipeline
const analysisQueue: Array<{
  event: ToolEvent;
  resolve: (v: IntentAnalysis) => void;
}> = [];
let processingQueue = false;

export function queueIntentAnalysis(event: ToolEvent): Promise<IntentAnalysis> {
  return new Promise((resolve) => {
    analysisQueue.push({ event, resolve });
    if (!processingQueue) processQueue();
  });
}

async function processQueue() {
  processingQueue = true;
  while (analysisQueue.length > 0) {
    const item = analysisQueue.shift()!;
    const result = await analyzeIntent(item.event);
    item.resolve(result);
    // Small delay to avoid rate limiting
    await new Promise((r) => setTimeout(r, 100));
  }
  processingQueue = false;
}
