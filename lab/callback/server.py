import json
import re
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


EVENT_LOG = Path("/tmp/callback-events.jsonl")
CALLBACK_TOKEN = os.environ.get("CALLBACK_TOKEN", "")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        match = re.search(r"/astro-callback-([A-Za-z0-9._~-]+)\.svg$", self.path)
        if match is not None:
            token = match.group(1)
        elif self.path in {"/404.html", "/500.html"} and CALLBACK_TOKEN:
            token = CALLBACK_TOKEN
        else:
            self.send_error(404)
            return
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": self.client_address[0],
            "method": self.command,
            "path": self.path,
        }
        with EVENT_LOG.open("a", encoding="utf-8") as log:
            log.write(json.dumps(event) + "\n")
        body = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">'
            f"<!-- astro-scan-callback:{token} -->"
            f"<astro-scan-callback>{token}</astro-scan-callback></svg>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


ThreadingHTTPServer(("0.0.0.0", 9999), Handler).serve_forever()
