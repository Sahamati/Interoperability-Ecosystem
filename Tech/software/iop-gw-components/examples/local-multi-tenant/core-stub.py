# A stand-in core for the example: answers every call 200 with a small JSON body
# and echoes Correlation-Id, as a real core must. It logs Core-Entity-Id, which a
# multi-tenant gateway sends on every request to the core. Testing only.
import json, os, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ.get("CORE_NAME", "core")

class Core(BaseHTTPRequestHandler):
    def answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        body = json.dumps({"ver": "2.0.0", "txnid": str(uuid.uuid4()), "status": "ok", "core": NAME, "path": self.path}).encode()
        self.send_response(200)
        if self.headers.get("Correlation-Id"):
            self.send_header("Correlation-Id", self.headers["Correlation-Id"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"{NAME}: {self.command} {self.path} Core-Entity-Id={self.headers.get('Core-Entity-Id')} "
              f"Initiator-Entity={self.headers.get('Initiator-Entity')} Forwarding-Hop={self.headers.get('Forwarding-Hop')}", flush=True)

    do_GET = do_POST = answer

    def log_message(self, *args):
        pass

ThreadingHTTPServer(("0.0.0.0", 8090), Core).serve_forever()
