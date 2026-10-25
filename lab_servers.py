"""Small local web servers with deliberately different security configurations.

They give the scanner known answers to be tested against. Never expose them to a network.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TRUSTED_ORIGIN = "https://app.example.com"

class LabHandler(BaseHTTPRequestHandler):
    profile = {}
    def version_string(self):            # value of the Server header
        return self.profile["server"]
    def log_message(self, *args):        # keep the notebook output clean
        pass
    def _respond(self, body):
        p = self.profile
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in p["headers"].items():
            self.send_header(k, v)
        for c in p["cookies"]:
            self.send_header("Set-Cookie", c)
        for k, v in p["cors"](self.headers.get("Origin")).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
    def do_GET(self):     self._respond(b"<html><body>lab page</body></html>")
    def do_HEAD(self):    self._respond(b"")
    def do_OPTIONS(self): self._respond(b"")

PROFILES = {
    "insecure-lab": {
        "server": "Apache/2.2.15 (CentOS)",
        "headers": {"X-Powered-By": "PHP/5.3.3"},
        "cookies": ["PHPSESSID=abc123; Path=/"],
        "cors": lambda o: ({"Access-Control-Allow-Origin": o, "Access-Control-Allow-Credentials": "true",
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE"} if o else {}),
    },
    "partial-lab": {
        "server": "nginx",
        "headers": {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN"},
        "cookies": ["session=abc123; Path=/; HttpOnly"],
        "cors": lambda o: {"Access-Control-Allow-Origin": "*"},
    },
    "hardened-lab": {
        "server": "webserver",
        "headers": {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        },
        "cookies": ["session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"],
        "cors": lambda o: ({"Access-Control-Allow-Origin": o, "Access-Control-Allow-Methods": "GET",
                            "Vary": "Origin"} if o == TRUSTED_ORIGIN else {"Vary": "Origin"}),
    },
}


def start_lab_servers():
    """Start the three lab servers on free local ports.

    Returns (servers, targets) where targets maps a name to its URL.
    Call server.shutdown() on each server when finished.
    """
    servers, targets = [], {}
    for name, prof in PROFILES.items():
        handler = type(name.replace("-", "_"), (LabHandler,), {"profile": prof})
        srv = HTTPServer(("127.0.0.1", 0), handler)          # port 0 = any free port
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        targets[name] = f"http://127.0.0.1:{srv.server_address[1]}/"
    return servers, targets
