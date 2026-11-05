# Docker MCP Gateway

The backend is an MCP client. It connects to **one** endpoint, the gateway, and
never starts nmap, Nikto or ZAP itself. The gateway starts/manages the Kali
stdio container and holds the remote connection to the ZAP MCP server.

```
backend -> http://127.0.0.1:8812/sse -> kali (stdio container)
                                      -> zap  (remote :7456) -> zaproxy :8090
```

## Start order

```bash
# 1. Lab target
docker compose -f lab.lvl1.yml up -d

# 2. ZAP + its MCP server
docker compose -f deploy/mcp-zap/compose.yaml up -d

# 3. Gateway (foreground; Ctrl-C stops it)
./deploy/mcp-gateway/start.sh

# 4. Backend, with gateway transport in backend/.env
cd backend
uv run uvicorn app.main:app --host 127.0.0.1 --port 8010
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
