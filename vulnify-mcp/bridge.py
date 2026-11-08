import asyncio 
import subprocess 
import sys 
from  http.server import BaseHTTPRequestHandler,ThreadingHTTPServer 
import json 

MCP_CMD = ["uv","run","--directory","/opt/vulnify","vulnify-mcp"]



class MCPHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        length = int(self.headers.get("Content-Length",0))
        body = self.rfile.read(length) if length else b'{}'

        proc = subprocess.run(
            MCP_CMD,
            input=body,
            capture_output=True,
            timeout=30
        )

        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.end_headers()
        self.wfile.write(proc.stdout)



if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0",7457),MCPHandler).serve_forever()

