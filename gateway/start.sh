#!/usr/bin/env bash
# ==============================================================================
# AIPENT — Docker MCP Gateway Runner
# Starts the single Docker MCP Gateway that the AIPENT backend connects to.
# ==============================================================================
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Resolve environment file with fallback priority
if [[ -f "$root/gateway/.env" ]]; then
  env_file="$root/gateway/.env"
elif [[ -f "$root/.env" ]]; then
  env_file="$root/.env"
else
  echo "[!] Missing environment file. Copy gateway/.env.example to gateway/.env and fill in MCP_API_KEY." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$env_file"
set +a
: "${MCP_API_KEY:?MCP_API_KEY is missing from $env_file}"

# Ensure MCP backing services are running
COMPOSE_FILE="$root/mcp/compose.yaml"

if ! docker compose -f "$COMPOSE_FILE" ps --status running --services 2>/dev/null | grep -qx "mcp-server"; then
  echo "[!] ZAP MCP server is not running. Please start the backing services first:" >&2
  echo "    docker compose -f $COMPOSE_FILE up -d" >&2
  exit 1
fi

# Ensure catalogue is installed
mkdir -p "$HOME/.docker/mcp/catalogs"
install -m 0644 "$root/gateway/aipent.yaml" "$HOME/.docker/mcp/catalogs/aipent.yaml"

# Write isolated secrets for remote MCP headers
umask 077
printf 'MCP_API_KEY=%s\n' "$MCP_API_KEY" > "$HOME/.docker/mcp/aipent-secrets.env"

# Docker MCP in-container flags
export DOCKER_MCP_IN_CONTAINER=1
export DOCKER_MCP_ALLOW_INSECURE_REMOTE_URLS=1

# Verify curl-mcp is reachable
if ! nc -z 127.0.0.1 7458 2>/dev/null; then
  echo "[*] Waiting for curl-mcp on port 7458..."
  for _ in {1..10}; do
    if nc -z 127.0.0.1 7458 2>/dev/null; then break; fi
    sleep 1
  done
fi

# Tools catalog for AIPENT
tools="${AIPENT_MCP_TOOLS:-nmap_scan,nikto_scan,sqlmap_scan,dirb_scan,whatweb_scan,hashcat_crack,curl_request,zap_crawl_start,zap_crawl_status,zap_crawl_stop,zap_passive_scan_wait,zap_report_generate,zap_report_read_chunk}"

echo "[*] Launching Docker MCP Gateway on 127.0.0.1:${AIPENT_MCP_PORT:-8812}..."
exec docker mcp gateway run \
  --catalog=aipent.yaml \
  --servers="${AIPENT_MCP_SERVERS:-kali,zap,curl}" \
  --secrets="$HOME/.docker/mcp/aipent-secrets.env" \
  --transport=sse \
  --host=127.0.0.1 \
  --port="${AIPENT_MCP_PORT:-8812}" \
  --allow-unauthenticated \
  --verify-signatures=false \
  --long-lived \
  --tools="$tools" \
  --log-calls \
  --verbose
