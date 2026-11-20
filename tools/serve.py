"""Local no-cache static server: python tools/serve.py [port]

Also forwards /splunk-api/<path> to a Splunk REST API (the page's "Run in Splunk"), since
Splunk's management port sends no CORS headers. The Splunk URL comes in the X-Splunk-Base
header; X-Splunk-Insecure: 1 accepts a self-signed certificate. Only requests from this
page are forwarded: the custom header makes a browser ask first (OPTIONS), which this
server never allows, and a foreign Origin is refused.
"""
import http.server
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PREFIX = "/splunk-api"
BASE_RE = re.compile(r"^https?://[^/\s]+$")


class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        if self.path.startswith(PREFIX + "/") or self.path == PREFIX:
            return self.forward()
        return super().do_GET()

    def do_POST(self):
        if self.path.startswith(PREFIX + "/"):
            return self.forward()
        self.reply(405, "POST is only for " + PREFIX + "/")

    def reply(self, status, text, ctype="text/plain; charset=utf-8"):
        data = text.encode("utf-8") if isinstance(text, str) else text
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def forward(self):
        rest = self.path[len(PREFIX):] or "/"
        if rest == "/ping":
            return self.reply(200, "ok")
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}"):
            return self.reply(403, "Only this page may use the Splunk forwarding.")
        base = (self.headers.get("X-Splunk-Base") or "").strip().rstrip("/")
        if not BASE_RE.match(base):
            return self.reply(400, "X-Splunk-Base must be like https://splunk-host:8089")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: self.headers[k] for k in ("Authorization", "Content-Type") if self.headers.get(k)}
        request = urllib.request.Request(base + rest, data=body, headers=headers, method=self.command)
        context = ssl._create_unverified_context() if self.headers.get("X-Splunk-Insecure") == "1" else None
        try:
            with urllib.request.urlopen(request, context=context, timeout=120) as res:
                self.reply(res.status, res.read(), res.headers.get("Content-Type", "text/plain"))
        except urllib.error.HTTPError as err:
            self.reply(err.code, err.read(), err.headers.get("Content-Type", "text/plain"))
        except Exception as err:  # unreachable host, TLS error, timeout
            self.reply(502, f"Could not reach {base}: {err}")

    def log_message(self, fmt, *args):
        # request lines only (never bodies, so no password); query strings are kept short
        super().log_message(fmt, *[str(a)[:160] for a in args])


if __name__ == "__main__":
    with http.server.ThreadingHTTPServer(("127.0.0.1", PORT), NoCacheHandler) as httpd:
        print(f"Serving {ROOT} at http://localhost:{PORT}/")
        httpd.serve_forever()
