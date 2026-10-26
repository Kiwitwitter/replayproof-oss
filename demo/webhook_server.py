"""Demo receiver with safe and deliberately broken modes. Localhost only!"""
import argparse
import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DemoState:
    def __init__(self, safe: bool):
        self.safe = safe
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with getattr(self, "lock", threading.Lock()):
            self.seen = set()
            self.attempts = set()
            self.side_effects = 0
            self.subscription_status = "unknown"
            self.subscription_version = -1

    def handle_event(self, event: dict) -> int:
        event_id = event.get("id")
        with self.lock:
            if self.safe and event_id in self.seen:
                return 200
            if self.safe:
                self.seen.add(event_id)
            event_type = event.get("type")
            if event_type == "invoice.paid":
                self.side_effects += 1
            if event_type in ("customer.subscription.created", "customer.subscription.deleted"):
                timestamp = int(event.get("created", 0))
                if not self.safe or timestamp >= self.subscription_version:
                    self.subscription_version = timestamp
                    self.subscription_status = "active" if event_type.endswith("created") else "canceled"
            if str(event_id).endswith("failonce") and event_id not in self.attempts:
                self.attempts.add(event_id)
                return 500  # simulate committed work followed by a failed acknowledgement
            return 200


def make_handler(state: DemoState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, code: int, value: dict):
            data = json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/_test/state":
                with state.lock:
                    obj = {"side_effects": state.side_effects,
                           "subscription_status": state.subscription_status}
                self._send(200, obj)
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16384:
                self._send(413, {"error": "payload too large"})
                return
            raw = self.rfile.read(length)
            if self.path == "/_test/reset":
                state.reset()
                self._send(200, {"reset": True})
                return
            if self.path != "/webhook":
                self._send(404, {"error": "not found"})
                return
            secret = os.environ.get("REPLAYPROOF_DEMO_SECRET")
            if secret:
                try:
                    kv = dict(x.split("=", 1) for x in self.headers.get("Stripe-Signature", "").split(","))
                    signed = (kv["t"] + ".").encode() + raw
                    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
                    if abs(time.time() - int(kv["t"])) > 300 or not hmac.compare_digest(digest, kv["v1"]):
                        raise ValueError("invalid signature")
                except (ValueError, KeyError):
                    self._send(400, {"error": "signature check failed"})
                    return
            try:
                event = json.loads(raw)
                code = state.handle_event(event)
            except (ValueError, TypeError):
                self._send(400, {"error": "invalid JSON"})
                return
            self._send(code, {"ok": code == 200})
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("safe", "vulnerable"), default="vulnerable")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(DemoState(args.mode == "safe")))
    print(f"Demo server: {args.mode}, http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
