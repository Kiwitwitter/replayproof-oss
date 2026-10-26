import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path

from demo.webhook_server import DemoState, make_handler
from replayproof.engine import ConfigurationError, check_destinations, execute, validate_manifest
from replayproof.cli import markdown_report


@contextmanager
def staging_server(safe=True):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(DemoState(safe)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def scenario(port: int):
    spec = json.loads((Path(__file__).parents[1] / "examples" / "staging.json").read_text())
    for path in ("target", "probe", "reset"):
        spec[path] = spec[path].replace("8765", str(port))
    return spec


class ReplayProofTests(unittest.TestCase):
    def test_vulnerable_server_fails_all_four_invariants(self):
        with staging_server(safe=False) as port:
            result = execute(scenario(port))
        self.assertEqual(result["summary"]["fail"], 4, result)
        self.assertEqual(result["summary"]["pass"], 0)
        self.assertEqual(result["cases"][0]["side_effect_delta"], 3)
        self.assertEqual(result["cases"][1]["side_effect_delta"], 8)
        self.assertEqual(result["cases"][2]["side_effect_delta"], 2)
        self.assertEqual(result["cases"][3]["observed_state"]["subscription_status"], "active")

    def test_safe_server_passes_all_four_invariants(self):
        with staging_server(safe=True) as port:
            result = execute(scenario(port))
        self.assertEqual(result["summary"]["pass"], 4, result)
        self.assertEqual(result["summary"]["fail"], 0)
        self.assertEqual(result["cases"][0]["side_effect_delta"], 1)
        self.assertEqual(result["cases"][1]["side_effect_delta"], 1)
        self.assertEqual(result["cases"][2]["side_effect_delta"], 1)
        self.assertEqual(result["cases"][3]["observed_state"]["subscription_status"], "canceled")
        self.assertIn("PASS 4", markdown_report(result))

    def test_no_probe_means_no_idempotency_proof(self):
        with staging_server(safe=False) as port:
            config = {"target": f"http://127.0.0.1:{port}/webhook",
                      "cases": [{"kind": "duplicate", "event": {"id": "evt1"}, "repeat": 2}]}
            result = execute(config)
        self.assertEqual(result["summary"]["inconclusive"], 1)

    def test_fails_closed_remote(self):
        manifest = {"target": "https://example.com/webhook", "cases": [{"kind": "duplicate", "event": {}, "repeat": 2}]}
        with self.assertRaises(ConfigurationError):
            check_destinations(manifest, False, False)
        with self.assertRaises(ConfigurationError):
            check_destinations({**manifest, "probe": "http://127.0.0.1:8765/state"}, True, True)

    def test_request_ceiling(self):
        manifest = {"target": "http://localhost:8765/webhook", "cases": [{"kind": "duplicate", "event": {}, "repeat": 10} for _ in range(6)]}
        with self.assertRaises(ConfigurationError):
            validate_manifest(manifest)

    def test_rejects_missing_side_effect_probe(self):
        manifest = {"target": "http://localhost:8765/webhook", "cases": [{"kind": "duplicate", "event": {}, "max_side_effect_delta": 1}]}
        with self.assertRaises(ConfigurationError):
            validate_manifest(manifest)

    def test_cli_writes_reports_and_exit_status(self):
        with staging_server(safe=True) as port, tempfile.TemporaryDirectory() as work:
            manifest = Path(work) / "manifest.json"
            manifest.write_text(json.dumps(scenario(port)))
            completed = subprocess.run([sys.executable, "-m", "replayproof.cli", str(manifest),
                                        "--out", str(Path(work) / "audit")], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((Path(work) / "audit.md").exists())
            self.assertTrue((Path(work) / "audit.json").exists())

    def test_stripe_signing_hmac(self):
        os.environ["REPLAYPROOF_DEMO_SECRET"] = "whsec_test_fixture"
        try:
            with staging_server(safe=True) as port:
                result = execute(scenario(port), secret="whsec_test_fixture")
            self.assertEqual(result["summary"]["pass"], 4, result)
        finally:
            del os.environ["REPLAYPROOF_DEMO_SECRET"]


if __name__ == "__main__":
    unittest.main()
