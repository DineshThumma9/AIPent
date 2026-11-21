# Docker MCP Gateway

The backend is an MCP client. It connects to **one** endpoint, the gateway, and
never starts nmap, Nikto or ZAP itself. The gateway starts/manages the Kali
stdio container and holds the remote connection to the ZAP MCP server.

```
backend -> http://127.0.0.1:8812/sse -> kali (stdio container)
                                      -> zap  (remote :7456) -> zaproxy :8090
```

## Prerequisites: Installing `docker-mcp` Plugin

The Docker MCP Gateway requires the **`docker-mcp`** CLI plugin (from [`docker/mcp-gateway`](https://github.com/docker/mcp-gateway)).

> **Note for Linux / Docker Engine Users:** Unlike Docker Desktop on macOS/Windows, standard Docker Engine on Linux **does not pre-bundle** the `docker mcp` CLI plugin. It must be installed into your Docker CLI plugins directory.

### Linux / WSL2 / macOS (x86_64 / amd64)
```bash
# 1. Create the Docker CLI plugins directory
mkdir -p ~/.docker/cli-plugins

# 2. Download and extract the latest docker-mcp binary
curl -fsSL https://github.com/docker/mcp-gateway/releases/latest/download/docker-mcp-linux-amd64.tar.gz | tar -xz -C ~/.docker/cli-plugins/

# 3. Ensure executable permissions
chmod +x ~/.docker/cli-plugins/docker-mcp

# 4. Verify installation
docker mcp version
```

*(For ARM64 Linux / Apple Silicon, replace `linux-amd64` with `linux-arm64` or `darwin-arm64` as appropriate).*

### Building from Source (Go required)
```bash
git clone https://github.com/docker/mcp-gateway.git
cd mcp-gateway
mkdir -p "$HOME/.docker/cli-plugins/"
make docker-mcp
```

## Start order

### Recommended: One-command launcher
```bash
./start.sh --with-lab
```

### Manual start sequence:
```bash
# 1. Lab target (optional)
docker compose -f labs/lab.lvl1.yml up -d

# 2. Start MCP backing services (ZAP, Vulnify, Curl, Typst)
docker compose -f mcp/compose.yaml up -d

# 3. Gateway (foreground; Ctrl-C stops it)
./gateway/start.sh

# 4. Backend
cd backend && uv run uvicorn app.main:app --host 127.0.0.1 --port 8010
```

`start.sh` copies `aipent.yaml` into `~/.docker/mcp/catalogs/` and writes the
ZAP key to `~/.docker/mcp/aipent-secrets.env` with mode 0600. Neither file is
in this repo, and neither is the key.

## Why the flags matter

| Flag | Reason |
|---|---|
| `--servers=kali,zap` | only these two servers; no dynamic catalog |
| `--tools=...` | expose only the eight tools the guided workflow calls |
| `--long-lived` | keep the Kali stdio container alive across calls |
| `--transport=sse` | `GatewayClient` selects SSE from the `/sse` URL |
| `--host=127.0.0.1` | gateway is local-only; never expose it |
| `--allow-unauthenticated` | safe only with the loopback bind above |
| `--verify-signatures=false` | the Kali image is unsigned; accepted local risk |

The ZAP stack sets `ZAP_MAX_SPIDER_SCAN_DURATION` in **minutes**. Keep it at 2
for the demo; the old value `120` meant 120 minutes, not seconds.

## Sanity check

With the gateway running:

```bash
cd backend
uv run python - <<'PY'
import asyncio
from app.mcp_client import GatewayClient

async def main():
    async with GatewayClient() as gateway:
        print(await gateway.list_tools())

asyncio.run(main())
PY
```

Expect exactly:

```
['nikto_scan', 'nmap_scan', 'zap_crawl_start', 'zap_crawl_status',
 'zap_crawl_stop', 'zap_passive_scan_wait', 'zap_report_generate',
 'zap_report_read_chunk']
```
