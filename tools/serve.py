"""Local no-cache static server: python tools/serve.py [port]

Also forwards /splunk-api/<path> to Splunk (the page's "Run in Splunk"), since neither
Splunk's REST API (management port) nor Splunk Web sends CORS headers.
  X-Splunk-Base      the Splunk URL (scheme, host, port, optional root path)
  X-Splunk-Insecure  1: accept a self-signed certificate
  X-Splunk-Cookie    cookies to send (Splunk Web session); the answer's cookies come back in
                     X-Splunk-Set-Cookie (JSON list of "name=value"), so the browser never
                     stores Splunk's cookies for this page
A redirect is not followed: it is answered with 200 and X-Splunk-Status / X-Splunk-Location
(Splunk Web's login answers with a redirect that carries the session cookies).
Only requests from this page are forwarded: the custom headers make a browser ask first
(OPTIONS), which this server never allows, and a foreign Origin is refused.
"""
import http.server
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PREFIX = "/splunk-api"
BASE_RE = re.compile(r"^https?://[^/\s]+(/[^\s?#]*)?$")
FORWARD_HEADERS = ("Authorization", "Content-Type", "X-Splunk-Form-Key", "X-Requested-With")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # report the 3xx (and its cookies) instead of following it


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

    def reply(self, status, text, ctype="text/plain; charset=utf-8", extra=None):
        data = text.encode("utf-8") if isinstance(text, str) else text
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
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
        headers = {k: self.headers[k] for k in FORWARD_HEADERS if self.headers.get(k)}
        if self.headers.get("X-Splunk-Cookie"):
            headers["Cookie"] = self.headers["X-Splunk-Cookie"]
        request = urllib.request.Request(base + rest, data=body, headers=headers, method=self.command)
        handlers = [NoRedirect()]
        if self.headers.get("X-Splunk-Insecure") == "1":
            handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(request, timeout=120) as res:
                self.answer(res.status, res.headers, res.read())
        except urllib.error.HTTPError as err:
            self.answer(err.code, err.headers, err.read())
        except Exception as err:  # unreachable host, TLS error, timeout
            self.reply(502, f"Could not reach {base}: {err}")

    def answer(self, status, headers, data):
        cookies = [c.split(";", 1)[0].strip() for c in headers.get_all("Set-Cookie") or []]
        extra = {"X-Splunk-Set-Cookie": json.dumps(cookies)}
        if 300 <= status < 400:
            extra["X-Splunk-Status"] = str(status)
            extra["X-Splunk-Location"] = headers.get("Location", "")
            status = 200
        self.reply(status, data, headers.get("Content-Type", "text/plain"), extra)

    def log_message(self, fmt, *args):
        # request lines only (never bodies, so no password); query strings are kept short
        super().log_message(fmt, *[str(a)[:160] for a in args])


if __name__ == "__main__":
    with http.server.ThreadingHTTPServer(("127.0.0.1", PORT), NoCacheHandler) as httpd:
        print(f"Serving {ROOT} at http://localhost:{PORT}/")
        httpd.serve_forever()
