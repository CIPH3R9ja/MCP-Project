#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// Claude Audit Monitor – PostToolUse Hook
// Place at: ~/.claude/hooks/cam-post-tool.mjs
// ─────────────────────────────────────────────────────────────────────────────
// Called AFTER every tool execution. Captures tool response for full
// request/response audit logging and async intent analysis.

import { readFileSync } from "fs";

const CAM_URL = process.env.CAM_URL || "http://localhost:7842";

async function main() {
  let payload;
  try {
    const stdin = readFileSync("/dev/stdin", "utf-8");
    payload = JSON.parse(stdin);
  } catch {
    return;
  }

  payload.cwd = process.env.PWD;
  payload.model = process.env.CLAUDE_MODEL;

  try {
    await fetch(`${CAM_URL}/hooks/post`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3000),
    });
  } catch {
    // Fail silently — monitor being down should never break Claude Code
  }
}

main();
