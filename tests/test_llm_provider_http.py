"""OllamaProvider HTTP behaviour against a SIMULATED local endpoint (not a real model).
Real Ollama integration remains IMPLEMENTED_NOT_VERIFIED."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from argos.llm.explain import LLMRejected, OllamaProvider, explain

ALERT = {"rule_id": "ARG-X", "rule_title": "t", "what": "w", "why": "y", "threat": {}, "automation": {}, "llm": {}, "framework": {},
         "purpose": {}, "confidence": "low", "alternatives": [], "missing_visibility": [], "resolving_data": [], "evidence_refs": ["ev:abc:1", "ev:abc:2"]}


def serve(behaviour):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert body["stream"] is False and body["format"] == "json" and "<alert>" in body["prompt"]
            kind, payload = behaviour
            if kind == "sleep":
                time.sleep(payload)
                return
            if kind == "status":
                self.send_response(payload)
                self.end_headers()
                return
            data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def provider(srv, timeout=5):
    return OllamaProvider(f"http://127.0.0.1:{srv.server_address[1]}", "simulated-model", timeout, allow_remote=False)


def test_valid_response_accepted():
    good = {"summary": "s", "cited_evidence_refs": ["ev:abc:1"], "suggested_checks": [{"check": "look at host logs", "evidence_refs": ["ev:abc:2"]}]}
    srv = serve(("json", {"response": json.dumps(good)}))
    try:
        assert explain(ALERT, provider(srv))["explanation"]["cited_evidence_refs"] == ["ev:abc:1"]
    finally:
        srv.shutdown()


@pytest.mark.parametrize("behaviour,exc", [
    (("sleep", 3), Exception),                  # timeout -> urllib raises (TimeoutError/URLError)
    (("status", 500), Exception),               # HTTP error
    (("json", "not json at all"), Exception),   # malformed transport body
])
def test_transport_errors_raise(behaviour, exc):
    srv = serve(behaviour)
    try:
        with pytest.raises(exc):
            explain(ALERT, provider(srv, timeout=1))
    finally:
        srv.shutdown()


def test_invented_reference_rejected():
    bad = {"summary": "s", "cited_evidence_refs": ["ev:zzz:9"], "suggested_checks": []}
    srv = serve(("json", {"response": json.dumps(bad)}))
    try:
        with pytest.raises(LLMRejected, match="non-existent"):
            explain(ALERT, provider(srv))
    finally:
        srv.shutdown()
