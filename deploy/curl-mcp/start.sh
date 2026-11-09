#!/usr/bin/env bash
# Start the calibress/curl-mcp server on port 7458 with streamable HTTP transport.
set -euo pipefail

PORT="${MCP_CURL_PORT:-7458}"
echo "[*] Starting curl-mcp HTTP server on port $PORT..."

# Search for the cached cli.js to avoid any network lookup
CLI_PATH="$(find "$HOME/.npm/_npx" -name "cli.js" -path "*/@calibress/curl-mcp/*" 2>/dev/null | head -n 1 || true)"

if [[ -n "$CLI_PATH" && -f "$CLI_PATH" ]]; then
    exec env PORT="$PORT" node "$CLI_PATH" --http
else
    exec env PORT="$PORT" npx --no-install @calibress/curl-mcp --http
fi
