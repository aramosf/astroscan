#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        marker = (
            b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">'
            b"<astro-scan-remote-patterns>OK</astro-scan-remote-patterns></svg>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(marker)

    def log_message(self, format, *args):
        return


ThreadingHTTPServer(("0.0.0.0", 9999), Handler).serve_forever()
