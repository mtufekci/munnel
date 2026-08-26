# Minimal Caddy on-demand TLS "ask" permission endpoint.
#
# Caddy calls GET /check?domain=<host> before issuing an on-demand TLS
# certificate; we approve only our own apex and its subdomains and refuse
# everything else. This satisfies Caddy's anti-abuse requirement for
# on-demand TLS (a permission module is mandatory in Caddy v2.8+) while
# keeping self-service subdomains working: any *.tunnels.example.com a
# client claims with -s gets a cert on first request.
#
# Run via docker compose (see the `ask` service in docker-compose.yml).
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import urllib.parse

# The apex tunnel domain. Override with MUNNEL_DOMAIN so the same image works
# for any deployment without rebuilding.
DOMAIN = os.environ.get("MUNNEL_DOMAIN", "tunnels.example.com").lower()


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if q.path != "/check":
            self.send_response(404)
            self.end_headers()
            return
        domain = urllib.parse.parse_qs(q.query).get("domain", [""])[0].lower()
        ok = domain == DOMAIN or domain.endswith("." + DOMAIN)
        self.send_response(200 if ok else 403)
        self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()