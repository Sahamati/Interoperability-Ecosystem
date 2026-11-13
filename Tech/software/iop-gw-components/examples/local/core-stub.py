# A stand-in core for the local example: answers every call 200 with a small
# JSON body and echoes Correlation-Id, as a real core must. Testing only.
import json, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Core(BaseHTTPRequestHandler):
    def answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        body = json.dumps({"ver": "2.0.0", "txnid": str(uuid.uuid4()), "status": "ok", "path": self.path}).encode()
        self.send_response(200)
        if self.headers.get("Correlation-Id"):
            self.send_header("Correlation-Id", self.headers["Correlation-Id"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"core-stub: {self.command} {self.path} Initiator-Entity={self.headers.get('Initiator-Entity')} "
              f"Forwarding-Hop={self.headers.get('Forwarding-Hop')}", flush=True)

    do_GET = do_POST = answer

    def log_message(self, *args):
        pass

ThreadingHTTPServer(("0.0.0.0", 8090), Core).serve_forever()
