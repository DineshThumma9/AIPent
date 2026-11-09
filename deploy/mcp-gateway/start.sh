#!/usr/bin/env bash
# Start the one Docker MCP Gateway that the backend talks to.
#
# The catalog is installed into ~/.docker/mcp/catalogs because `docker mcp
# gateway run --catalog=<name>` resolves names there. The ZAP API key is copied
# into a dedicated 0600 file so the gateway can inject it into the remote MCP
# headers without putting the secret in this repo or in the process argv.
#
# Run deploy/mcp-zap/compose.yaml first, then this script in the foreground.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
env_file="$root/deploy/mcp-zap/.env"

if [[ ! -f "$env_file" ]]; then
  echo "missing $env_file; copy deploy/mcp-zap/.env.example and fill it" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$env_file"
set +a
: "${MCP_API_KEY:?MCP_API_KEY is missing from $env_file}"

if ! docker compose -f "$root/deploy/mcp-zap/compose.yaml" ps --status running \
  --services 2>/dev/null | grep -qx "mcp-server"; then
  echo "ZAP MCP server is not running; start deploy/mcp-zap/compose.yaml first" >&2
  exit 1
fi

mkdir -p "$HOME/.docker/mcp/catalogs"
install -m 0644 "$root/deploy/mcp-gateway/aipent.yaml" \
  "$HOME/.docker/mcp/catalogs/aipent.yaml"

umask 077
printf 'MCP_API_KEY=%s\n' "$MCP_API_KEY" > "$HOME/.docker/mcp/aipent-secrets.env"

# The gateway itself runs in a container and must be allowed to reach the
# loopback-only ZAP MCP endpoint. Both flags are scoped to this process.
export DOCKER_MCP_IN_CONTAINER=1
export DOCKER_MCP_ALLOW_INSECURE_REMOTE_URLS=1

# Start curl-mcp daemon on port 7458 if not already running
if ! nc -z 127.0.0.1 7458 2>/dev/null; then
  echo "[*] Launching local curl-mcp daemon on port 7458..."
  "$root/deploy/curl-mcp/start.sh" >/dev/null 2>&1 &
  sleep 1
fi

# Only the tools the guided workflow needs. The LLM never sees these
# names; the backend maps semantic actions onto them.
tools="${AIPENT_MCP_TOOLS:-nmap_scan,nikto_scan,sqlmap_scan,dirb_scan,whatweb_scan,hashcat_crack,curl_request,zap_crawl_start,zap_crawl_status,zap_crawl_stop,zap_passive_scan_wait,zap_report_generate,zap_report_read_chunk}"

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
