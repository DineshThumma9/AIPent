import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MCP_CMD = ["uv", "run", "--directory", "/opt/vulnify", "vulnify-mcp"]


class MCPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/health", "/ping"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","server":"vulnify-mcp"}\n')
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"

        try:
            proc = subprocess.run(
                MCP_CMD,
                input=body,
                capture_output=True,
                timeout=30,
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(proc.stdout)
        except Exception as exc:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(exc)}).encode())

    def log_message(self, format, *args):
        sys.stderr.write(f"[vulnify-bridge] {format % args}\n")


if __name__ == "__main__":
    port = int(os.environ.get("VULNIFY_PORT", 7457))
    server = ThreadingHTTPServer(("0.0.0.0", port), MCPHandler)
    sys.stderr.write(f"[vulnify-bridge] Serving Vulnify MCP bridge on 0.0.0.0:{port}\n")
    server.serve_forever()
