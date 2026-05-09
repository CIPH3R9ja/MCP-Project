#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// Claude Audit Monitor – PreToolUse Hook
// Place at: ~/.claude/hooks/cam-pre-tool.mjs
// ─────────────────────────────────────────────────────────────────────────────
// Called BEFORE every tool call. Receives JSON on stdin.
//
// Output:
//   { "action": "continue" }             → allow the tool call
//   { "action": "block", "message": "…"} → block the tool call

import { readFileSync } from "fs";

const CAM_URL = process.env.CAM_URL || "http://localhost:7842";

async function main() {
  let payload;
  try {
    const stdin = readFileSync("/dev/stdin", "utf-8");
    payload = JSON.parse(stdin);
  } catch {
    process.stdout.write(JSON.stringify({ action: "continue" }));
    return;
  }

  payload.cwd = process.env.PWD;
  payload.model = process.env.CLAUDE_MODEL;

  try {
    const response = await fetch(`${CAM_URL}/hooks/pre`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3000),
    });

    const result = await response.json();
    process.stdout.write(JSON.stringify(result));

    if (result.action === "block") {
      process.stderr.write(`\n  [Claude Audit Monitor] BLOCKED: ${result.message}\n`);
      process.exit(1);
    }
  } catch {
    // Monitor server unreachable — fail open, don't disrupt workflow
    process.stdout.write(JSON.stringify({ action: "continue" }));
  }
}

main();
