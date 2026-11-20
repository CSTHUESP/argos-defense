"""Acceptance 16: import -> analyze -> open alert -> inspect evidence -> export, through the
real HTTP server (uvicorn) and the real HTML/API routes. Also checks auth, Host, Origin
and CSRF enforcement, and persistence across a server restart."""
import http.client
import json
import re
import socket
import threading
import time
import uuid

import pytest
import uvicorn

from argos.api.app import create_app
from conftest import ROOT

DEMO = ROOT / "fixtures" / "demo"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Server:
    def __init__(self, settings, token):
        self.port = free_port()
        self.app = create_app(settings, token, self.port)
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error"))
        self.t = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.t.start()
        for _ in range(100):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("server did not start")

    def __exit__(self, *a):
        self.server.should_exit = True
        self.t.join(5)
        self.app.state.argos.store.close()


class Client:
    def __init__(self, port, token=None):
        self.port, self.token, self.cookie = port, token, None
        self.origin = f"http://127.0.0.1:{port}"

    def req(self, method, path, body=None, headers=None, bearer=False, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if self.cookie:
            h["Cookie"] = self.cookie
        if bearer:
            h["Authorization"] = f"Bearer {self.token}"
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        sc = r.getheader("set-cookie")
        if sc and "argos_session=" in sc:
            self.cookie = sc.split(";")[0]
        return r.status, dict(r.getheaders()), data.decode("utf-8", "replace")

    def form(self, path, fields, origin=True):
        from urllib.parse import urlencode
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        if origin:
            h["Origin"] = self.origin
        return self.req("POST", path, urlencode(fields), h)

    def multipart(self, path, fields, file_field, filename, content, origin=True, bearer=False):
        b = uuid.uuid4().hex
        parts = []
        for k, v in fields.items():
            parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
                     f"Content-Type: application/octet-stream\r\n\r\n".encode() + content + b"\r\n")
        parts.append(f"--{b}--\r\n".encode())
        h = {"Content-Type": f"multipart/form-data; boundary={b}"}
        if origin:
            h["Origin"] = self.origin
        return self.req("POST", path, b"".join(parts), h, bearer=bearer)


def csrf_of(html):
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def test_16_full_workflow_browser_and_api(env):
    token = "test-token-" + uuid.uuid4().hex
    with Server(env.settings, token) as srv:
        cl = Client(srv.port, token)
        # --- access control
        assert cl.req("GET", "/")[0] == 303
        assert cl.req("GET", "/api/cases")[0] == 401
        assert cl.req("GET", "/api/cases", bearer=True, host="evil.example:80")[0] == 400  # DNS-rebinding guard
        assert cl.req("GET", "/login?token=wrong")[0] == 403
        st, hdr, _ = cl.req("GET", f"/login?token={token}")
        assert st == 303 and "httponly" in hdr["set-cookie"].lower() and "samesite=strict" in hdr["set-cookie"].lower()
        st, hdr, html = cl.req("GET", "/")
        assert st == 200 and "script-src 'self'" in hdr["content-security-policy"]
        # regression: 'no-referrer' made real browsers send "Origin: null" on form posts (found in Chrome check)
        assert hdr["referrer-policy"] == "same-origin"
        assert cl.req("POST", "/cases", "name=x0", {"Content-Type": "application/x-www-form-urlencoded", "Origin": "null"})[0] == 403
        csrf = csrf_of(html)
        # --- CSRF / origin enforcement
        assert cl.form("/cases", {"name": "x1"})[0] == 403                                 # no csrf
        assert cl.form("/cases", {"name": "x1", "csrf": "nope"})[0] == 403                 # wrong csrf
        assert cl.req("POST", "/cases", "name=x1&csrf=" + csrf, {"Content-Type": "application/x-www-form-urlencoded",
                                                                   "Origin": "http://evil.example"})[0] == 403
        assert cl.form("/cases", {"name": "x1", "csrf": csrf}, origin=False)[0] == 403     # origin required
        # --- create case and import through the UI
        st, hdr, _ = cl.form("/cases", {"name": "ui-demo", "synthetic": "on", "csrf": csrf})
        assert st == 303
        cid = hdr["location"].rsplit("/", 1)[1]
        manifest = json.loads((DEMO / "import_manifest.json").read_text())
        for f in manifest:
            fields = {"csrf": csrf, "case": cid, "format": f["format"], **f["options"]}
            if f.get("coverage"):
                fields.update(coverage_start=f["coverage"]["start"], coverage_end=f["coverage"]["end"],
                              coverage_scope=f["coverage"]["scope"], coverage_note=f["coverage"]["note"])
            st, _, page = cl.multipart("/import", fields, "file", f["file"], (DEMO / f["file"]).read_bytes())
            assert st == 200 and ("<b>imported</b>" in page), page[:500]
        # hostile filename and XXE rejected with actual error text
        st, _, page = cl.multipart("/import", {"csrf": csrf, "case": cid, "format": "native_jsonl"}, "file", "../../etc/passwd.jsonl", b"{}")
        assert st == 400 and "unsafe file name" in page
        st, _, page = cl.multipart("/import", {"csrf": csrf, "case": cid, "format": "sysmon_xml"}, "file", "x.xml",
                                   b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><Events/>')
        assert st == 200 and "rejected" in page and "not accepted" in page
        # --- analyze
        st, hdr, _ = cl.form(f"/cases/{cid}/analyze", {"csrf": csrf})
        assert st == 303 and hdr["location"].startswith("/jobs/job-")
        job_path = hdr["location"]
        for _ in range(300):  # background job: poll its page (it auto-refreshes in a browser)
            st, _, page = cl.req("GET", job_path)
            if "status <b>succeeded</b>" in page or "status <b>failed</b>" in page:
                break
            time.sleep(0.1)
        assert st == 200 and "status <b>succeeded</b>" in page and "analyzed=run-" in page, page[-800:]
        st, _, page = cl.req("GET", f"/cases/{cid}")
        assert "DEMO/SYNTHETIC CASE" in page and "corroborated_presence" in page and "unavailable" not in page.split("Coverage by")[1][:200]
        # --- alert queue with filters
        st, _, page = cl.req("GET", f"/alerts?case={cid}&min_severity=high")
        assert st == 200 and "ARG-AUTH-002" in page and "ARG-LLM-001" not in page
        aid = re.search(r'href="/alerts/(al-[0-9a-f]+)">Failures, then success', page).group(1)
        st, _, page = cl.req("GET", f"/alerts?case={cid}&llm=directly_observed")
        assert "ARG-LLM-002" in page and "ARG-AUTH-002" not in page
        # --- open alert, inspect evidence
        st, _, page = cl.req("GET", f"/alerts/{aid}")
        assert st == 200 and "C · LLM involvement" in page and "Matched predicates" in page and "failed_signins" in page
        eid = re.search(r'href="/events/([0-9a-f]{32})"', page).group(1)
        st, _, page = cl.req("GET", f"/events/{eid}")
        assert st == 200 and "Original record" in page and "identity_native.jsonl" in page
        # hostile content escaped in UI
        st, _, page = cl.req("GET", f"/alerts?case={cid}&show_authorized=1")
        wid = re.search(r'href="/alerts/(al-[0-9a-f]+)">\[WEAK\]', page).group(1)
        st, _, page = cl.req("GET", f"/alerts/{wid}")
        assert "<script>alert(" not in page and "&lt;script&gt;" in page
        # --- notes + status (persist)
        assert cl.form(f"/alerts/{aid}/notes", {"csrf": csrf, "text": "checked with IdP team"})[0] == 303
        assert cl.form(f"/alerts/{aid}/status", {"csrf": csrf, "status": "escalated"})[0] == 303
        # --- export
        st, hdr, body = cl.req("GET", f"/cases/{cid}/export.json")
        exp = json.loads(body)
        assert st == 200 and exp["banner"].startswith("DEMO/SYNTHETIC") and exp["timeline"] and exp["versions"]["rules_hash"]
        assert any(n["text"] == "checked with IdP team" for n in exp["notes"])
        st, hdr, body = cl.req("GET", f"/cases/{cid}/export.html")
        assert st == 200 and "DEMO/SYNTHETIC" in body and "<script" not in body.lower()
        st, hdr, body = cl.req("GET", f"/cases/{cid}/export.csv")
        assert st == 200 and body.startswith("alert_id,")
        # --- other pages render
        for p in ("/entities?case=" + cid, "/rules", "/import"):
            assert cl.req("GET", p)[0] == 200
        # --- pure API path with bearer token (no cookie)
        api = Client(srv.port, token)
        st, _, body = api.req("POST", "/api/cases", json.dumps({"name": "api-case", "synthetic": True}), {"Content-Type": "application/json"}, bearer=True)
        assert st == 201
        acid = json.loads(body)["case_id"]
        st, _, body = api.multipart(f"/api/cases/{acid}/import", {"format": "native_jsonl"}, "file", "identity_native.jsonl",
                                    (DEMO / "identity_native.jsonl").read_bytes(), origin=False, bearer=True)
        assert st == 200 and json.loads(body)["accepted"] == 33
        st, _, body = api.req("POST", f"/api/cases/{acid}/analyze", bearer=True)
        assert st == 200
        st, _, body = api.req("GET", f"/api/alerts?case={acid}", bearer=True)
        al = json.loads(body)["alerts"]
        assert al and all(a["case_id"] == acid for a in al)
        st, _, body = api.req("GET", f"/api/alerts/{al[0]['alert_id']}", bearer=True)
        assert st == 200 and json.loads(body)["events"]
        assert api.req("POST", f"/api/alerts/{al[0]['alert_id']}/explain", "{}", {"Content-Type": "application/json"}, bearer=True)[0] == 422
    # --- restart: notes and status persist, no duplicates after re-analysis
    with Server(env.settings, token) as srv2:
        cl2 = Client(srv2.port, token)
        cl2.req("GET", f"/login?token={token}")
        st, _, body = cl2.req("GET", f"/api/alerts/{aid}", bearer=True)
        d = json.loads(body)
        assert d["alert"]["analyst_status"] == "escalated" and d["notes"][0]["text"] == "checked with IdP team"
        before = len(json.loads(cl2.req("GET", f"/api/alerts?case={cid}&show_authorized=1", bearer=True)[2])["alerts"])
        cl2.req("POST", f"/api/cases/{cid}/analyze", bearer=True)
        after = len(json.loads(cl2.req("GET", f"/api/alerts?case={cid}&show_authorized=1", bearer=True)[2])["alerts"])
        assert before == after


def test_bearer_requests_from_foreign_origin_rejected(env):
    token = "t-" + uuid.uuid4().hex
    with Server(env.settings, token) as srv:
        cl = Client(srv.port, token)
        st, _, _ = cl.req("POST", "/api/cases", json.dumps({"name": "zz"}), {"Content-Type": "application/json", "Origin": "http://evil.example"}, bearer=True)
        assert st == 403


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.1"])
def test_cli_refuses_non_loopback(host, env):
    from argos.cli import main
    assert main(["--home", str(env.settings.home), "serve", "--host", host, "--port", "1"]) == 2
