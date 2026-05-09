#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Claude Audit Monitor – Quick Install
# Usage: bash install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

HOOKS_DIR="${HOME}/.claude/hooks"
SETTINGS="${HOME}/.claude/settings.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "  Claude Audit Monitor – Installer"
echo ""

# 1. Install hooks
echo "[1/3] Installing Claude Code hooks..."
mkdir -p "$HOOKS_DIR"
cp "$SCRIPT_DIR/hooks/cam-pre-tool.mjs"  "$HOOKS_DIR/"
cp "$SCRIPT_DIR/hooks/cam-post-tool.mjs" "$HOOKS_DIR/"
chmod +x "$HOOKS_DIR/cam-pre-tool.mjs" "$HOOKS_DIR/cam-post-tool.mjs"
echo "      Hooks installed to $HOOKS_DIR"

# 2. Merge settings.json
echo "[2/3] Configuring Claude Code settings..."
if [ ! -f "$SETTINGS" ]; then
  echo '{}' > "$SETTINGS"
fi

# Check if hooks already present
if grep -q "cam-pre-tool" "$SETTINGS" 2>/dev/null; then
  echo "      Hooks already present in settings.json — skipping."
else
  # Use node to safely merge JSON
  node - <<'EOF'
const fs = require('fs');
const path = require('path');
const settingsPath = process.env.HOME + '/.claude/settings.json';
const snippetPath = path.join(process.cwd(), 'config/claude-settings-snippet.json');

const existing = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
const snippet  = JSON.parse(fs.readFileSync(snippetPath, 'utf8'));

existing.hooks = { ...(existing.hooks || {}), ...snippet.hooks };
fs.writeFileSync(settingsPath, JSON.stringify(existing, null, 2));
console.log('      Merged hooks into', settingsPath);
EOF
fi

# 3. Copy env example if .env missing
echo "[3/3] Checking environment..."
if [ ! -f "$SCRIPT_DIR/.env" ]; then
  cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
  echo ""
  echo "  Created .env from .env.example"
  echo "  ACTION REQUIRED: set ANTHROPIC_API_KEY in $SCRIPT_DIR/.env"
else
  echo "      .env already exists — skipping."
fi

echo ""
echo "  Done! Start the monitor with:"
echo ""
echo "    cd $SCRIPT_DIR"
echo "    npm start"
echo ""
echo "  Dashboard: http://localhost:7842/dashboard"
echo ""
