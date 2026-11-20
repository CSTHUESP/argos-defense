"""Local web interface and JSON API (Starlette).

Security model (local single-analyst tool):
- binds to 127.0.0.1 by default; Host header must be a loopback name (DNS-rebinding guard)
- access requires the local session token (printed at startup, stored 0600 in ARGOS_HOME)
- browser sessions use an HttpOnly SameSite=Strict cookie; every state-changing browser
  request needs a matching Origin/Referer AND a per-session CSRF token
- API clients may use 'Authorization: Bearer <token>' instead of the cookie
- strict CSP: only locally served JS/CSS; all imported content is HTML-escaped
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import tempfile
import threading
from datetime import datetime
from pathlib import Path

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from argos import __version__
from argos.analysis import AnalysisError, load_context, run_analysis
from argos.config import Settings
from argos.resources import static_dir
from argos.ingest.adapters import FORMAT_HELP
from argos.ingest.pipeline import ImportError_, ingest_file, safe_join, safe_original_name
from argos.llm.explain import LLMRejected, explain, provider_from_settings
from argos.models import CONF_ORDER, SEVERITY_ORDER
from argos.normalize.mappers import BUILTIN_PROFILES, MappingError
from argos.reporting.export import alerts_csv, build_case_export, jinja_env, render_html
from argos.store import Store

STATIC = static_dir()
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
PUBLIC_PATHS = ("/login", "/static/", "/health")


class AppState:
    def __init__(self, settings: Settings, token: str, port: int):
        self.settings = settings
        self.token = token
        self.port = port
        self.store = Store(settings.db_path)
        self.lock = threading.RLock()
        self.sessions: dict[str, str] = {}  # session id -> csrf token
        self.env = jinja_env()
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        self.allowed_origins = {f"http://{h}" for h in self.allowed_hosts}
        self.server = None  # set by the CLI launcher; enables /api/shutdown


def ensure_token(settings: Settings, rotate: bool = False) -> str:
    settings.ensure()
    p = settings.home / ".session_token"
    if p.exists() and not rotate:
        return p.read_text().strip()
    tok = secrets.token_urlsafe(32)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(tok)
    return tok


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        st: AppState = request.app.state.argos
        host = request.headers.get("host", "")
        if host not in st.allowed_hosts:
            return PlainTextResponse("Host not allowed", status_code=400)
        path = request.url.path
        auth = None
        bearer = request.headers.get("authorization", "")
        if bearer.lower().startswith("bearer ") and hmac.compare_digest(bearer[7:].strip(), st.token):
            auth = "bearer"
        sid = request.cookies.get("argos_session")
        if auth is None and sid and sid in st.sessions:
            auth = "cookie"
        request.state.auth = auth
        request.state.csrf = st.sessions.get(sid) if auth == "cookie" else None
        if not path.startswith(PUBLIC_PATHS) and auth is None:
            if path.startswith("/api/"):
                return JSONResponse({"error": "authentication required"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
        request.state.need_form_csrf = False
        if request.method in UNSAFE:
            origin = request.headers.get("origin")
            if origin is None and request.headers.get("referer"):
                origin = "/".join(request.headers["referer"].split("/")[:3])
            if origin is not None and origin not in st.allowed_origins:
                return PlainTextResponse("Cross-origin request rejected", status_code=403)
            if auth == "cookie":
                if origin is None:
                    return PlainTextResponse("Origin header required", status_code=403)
                sent = request.headers.get("x-csrf-token")
                ctype = request.headers.get("content-type", "")
                if sent is not None:
                    if not hmac.compare_digest(sent, request.state.csrf or ""):
                        return PlainTextResponse("CSRF token invalid", status_code=403)
                elif ctype.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
                    request.state.need_form_csrf = True  # verified by get_form() in the handler
                else:
                    return PlainTextResponse("CSRF token missing", status_code=403)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                                   "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"  # "no-referrer" makes browsers send Origin: null on form POSTs
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        return resp


class CSRFError(Exception):
    pass


async def get_form(request: Request):
    """Read a form and enforce the per-session CSRF token for cookie sessions."""
    form = await request.form(max_part_size=_st(request).settings.max_file_bytes)
    if getattr(request.state, "need_form_csrf", False):
        sent = form.get("csrf")
        if not sent or not hmac.compare_digest(str(sent), request.state.csrf or ""):
            raise CSRFError()
    return form


async def csrf_error(request: Request, exc):
    return PlainTextResponse("CSRF token missing or invalid", status_code=403)


def _st(request) -> AppState:
    return request.app.state.argos


def render(request, name, status=200, **ctx):
    st = _st(request)
    tpl = st.env.get_template(name)
    ctx.update(request=request, csrf=request.state.csrf or "", version=__version__,
               llm_enabled=st.settings.llm_provider != "disabled")
    return HTMLResponse(tpl.render(**ctx), status_code=status)


def _case_or_404(st, ref):
    c = st.store.get_case(ref)
    if not c:
        raise LookupError("case not found")
    return c


# ------------------------------------------------------------------ auth pages
async def login(request: Request):
    st = _st(request)
    tok = request.query_params.get("token")
    if request.method == "POST":
        form = await request.form()
        tok = form.get("token")
        if request.headers.get("origin") is None:
            return PlainTextResponse("Origin header required", status_code=403)
    if tok:
        if hmac.compare_digest(str(tok), st.token):
            sid = secrets.token_urlsafe(32)
            st.sessions[sid] = secrets.token_urlsafe(32)
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie("argos_session", sid, httponly=True, samesite="strict", path="/")
            return resp
        return HTMLResponse(st.env.get_template("login.html").render(error="Invalid token", request=request, csrf="", version=__version__), status_code=403)
    return HTMLResponse(st.env.get_template("login.html").render(error=None, request=request, csrf="", version=__version__))


async def health(request: Request):
    return JSONResponse({"status": "ok", "version": __version__})


# ------------------------------------------------------------------ HTML pages
async def overview(request: Request):
    st = _st(request)
    with st.lock:
        cases = st.store.list_cases()
        for c in cases:
            a = st.store.latest_assessment(c["case_id"])
            c["assessment"] = a
    return render(request, "overview.html", cases=cases)


async def create_case(request: Request):
    st = _st(request)
    form = await get_form(request)
    try:
        with st.lock:
            c = st.store.create_case(str(form.get("name", "")).strip(), form.get("synthetic") == "on", str(form.get("description", ""))[:2000])
    except ValueError as exc:
        return render(request, "error.html", status=400, message=str(exc))
    return RedirectResponse(f"/cases/{c['case_id']}", status_code=303)


async def case_page(request: Request):
    st = _st(request)
    with st.lock:
        try:
            c = _case_or_404(st, request.path_params["cid"])
        except LookupError:
            return render(request, "error.html", status=404, message="Case not found")
        ctx = dict(case=c, inputs=st.store.list_inputs(c["case_id"]), runs=st.store.list_runs(c["case_id"]),
                   assessment=st.store.latest_assessment(c["case_id"]), notes=st.store.list_notes(c["case_id"]),
                   rejects=st.store.list_rejects(c["case_id"], limit=200), event_count=st.store.count_events(c["case_id"]))
    return render(request, "case.html", **ctx)


async def case_analyze(request: Request):
    st = _st(request)
    cid = request.path_params["cid"]
    if request.headers.get("content-type", "").startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
        await get_form(request)

    def work():
        with st.lock:
            return run_analysis(st.store, st.settings, cid)
    try:
        res = await run_in_threadpool(work)
    except AnalysisError as exc:
        return _err(request, str(exc), 400)
    if request.url.path.startswith("/api/"):
        return JSONResponse(res)
    return RedirectResponse(f"/cases/{res['case_id']}?analyzed={res['run_id']}", status_code=303)


async def case_status(request: Request):
    st = _st(request)
    form = await get_form(request)
    try:
        with st.lock:
            c = _case_or_404(st, request.path_params["cid"])
            st.store.set_case_status(c["case_id"], str(form.get("status")))
    except (LookupError, ValueError) as exc:
        return render(request, "error.html", status=400, message=str(exc))
    return RedirectResponse(f"/cases/{c['case_id']}", status_code=303)


async def add_note(request: Request):
    st = _st(request)
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
    else:
        body = dict(await get_form(request))
    aid = request.path_params.get("aid")
    try:
        with st.lock:
            if aid:
                a = st.store.get_alert(aid)
                if not a:
                    raise LookupError("alert not found")
                cid = a["case_id"]
            else:
                cid = _case_or_404(st, request.path_params["cid"])["case_id"]
            nid = st.store.add_note(cid, str(body.get("text", "")), alert_id=aid)
    except (LookupError, ValueError) as exc:
        return _err(request, str(exc), 400)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"note_id": nid})
    return RedirectResponse(f"/alerts/{aid}" if aid else f"/cases/{cid}", status_code=303)


async def alert_status(request: Request):
    st = _st(request)
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
    else:
        body = dict(await get_form(request))
    aid = request.path_params["aid"]
    try:
        with st.lock:
            if not st.store.get_alert(aid):
                raise LookupError("alert not found")
            st.store.set_alert_status(aid, str(body.get("status")))
    except (LookupError, ValueError) as exc:
        return _err(request, str(exc), 400)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"ok": True})
    return RedirectResponse(f"/alerts/{aid}", status_code=303)


async def attest_input(request: Request):
    st = _st(request)
    form = await get_form(request)
    note = str(form.get("note", "")).strip()
    if len(note) < 10:
        return render(request, "error.html", status=400, message="Attestation requires a note (>=10 chars) explaining how provenance was verified outside the file.")
    with st.lock:
        row = st.store.conn.execute("SELECT case_id FROM inputs WHERE input_id=?", (request.path_params["iid"],)).fetchone()
        if not row:
            return render(request, "error.html", status=404, message="Input not found")
        trust = "analyst_attested" if form.get("trust") == "analyst_attested" else "unverified"
        st.store.set_input_trust(request.path_params["iid"], trust, "analyst: " + note[:1000])
    return RedirectResponse(f"/cases/{row[0]}", status_code=303)


def _err(request, msg, code):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": msg}, status_code=code)
    return render(request, "error.html", status=code, message=msg)


async def import_page(request: Request):
    st = _st(request)
    with st.lock:
        cases = st.store.list_cases()
    return render(request, "import.html", cases=cases, formats=FORMAT_HELP, profiles=BUILTIN_PROFILES,
                  preselect=request.query_params.get("case"), result=None)


async def _do_import(request: Request, case_ref: str | None):
    st = _st(request)
    form = await get_form(request)
    upload = form.get("file")
    case_ref = case_ref or str(form.get("case", ""))
    fmt = str(form.get("format", ""))
    if upload is None or not hasattr(upload, "filename"):
        raise ImportError_("no file uploaded")
    name = safe_original_name(upload.filename or "")
    options = {}
    if form.get("profile"):
        options["profile"] = str(form.get("profile"))
    if form.get("assume_tz"):
        options["assume_tz"] = str(form.get("assume_tz")).strip()
    if form.get("zeek_log"):
        options["zeek_log"] = str(form.get("zeek_log"))
    with st.lock:
        case = st.store.get_case(case_ref)
    if not case:
        raise ImportError_("unknown case")
    staging = safe_join(st.settings.cases_dir, case["case_id"], "staging")
    staging.mkdir(parents=True, exist_ok=True)
    mapping_text = str(form.get("mapping_yaml", "") or "").strip()
    tmp_map = None
    if mapping_text:
        if len(mapping_text) > 64 * 1024:
            raise ImportError_("mapping too large")
        fd, tmp_map = tempfile.mkstemp(suffix=".yaml", dir=str(staging))
        with os.fdopen(fd, "w") as fh:
            fh.write(mapping_text)
        options["mapping"] = tmp_map
        options.pop("profile", None)
    fd, tmp = tempfile.mkstemp(suffix=Path(name).suffix, dir=str(staging))
    size = 0
    try:
        with os.fdopen(fd, "wb") as fh:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > st.settings.max_file_bytes:
                    raise ImportError_("upload exceeds size limit")
                fh.write(chunk)

        def work():
            with st.lock:
                return ingest_file(st.store, st.settings, case, tmp, fmt, options, original_name=name)
        res = await run_in_threadpool(work)
    finally:
        Path(tmp).unlink(missing_ok=True)
        if tmp_map:
            Path(tmp_map).unlink(missing_ok=True)
    res["case_id"] = case["case_id"]
    with st.lock:
        res["rejects_sample"] = [r for r in st.store.list_rejects(case["case_id"], limit=500) if r["input_id"] == res["input_id"]][:50]
    return res


async def import_post(request: Request):
    st = _st(request)
    try:
        res = await _do_import(request, None)
    except (ImportError_, MappingError, ValueError) as exc:
        with st.lock:
            cases = st.store.list_cases()
        return render(request, "import.html", status=400, cases=cases, formats=FORMAT_HELP, profiles=BUILTIN_PROFILES,
                      preselect=None, result={"status": "error", "error": str(exc)})
    with st.lock:
        cases = st.store.list_cases()
    return render(request, "import.html", cases=cases, formats=FORMAT_HELP, profiles=BUILTIN_PROFILES,
                  preselect=res["case_id"], result=res)


def _filter_alerts(alerts, q):
    def ok(a):
        if q.get("severity") and a["threat"]["severity"] != q["severity"]:
            return False
        if q.get("min_severity") and SEVERITY_ORDER.index(a["threat"]["severity"]) < SEVERITY_ORDER.index(q["min_severity"]):
            return False
        if q.get("confidence") and a["confidence"] != q["confidence"]:
            return False
        if q.get("automation") and a["automation"]["level"] != q["automation"]:
            return False
        if q.get("llm") and a["llm"]["level"] != q["llm"]:
            return False
        if q.get("framework") and a["framework"]["level"] != q["framework"]:
            return False
        if q.get("activity") and q["activity"].lower() not in (a["what"] + " " + a["rule_title"]).lower():
            return False
        if q.get("since") and a["last_time"] < q["since"]:
            return False
        if q.get("until") and a["first_time"] > q["until"] + "T99":
            return False
        if q.get("status") and a["analyst_status"] != q["status"]:
            return False
        if not q.get("show_authorized") and a["disposition"] == "authorized_automation":
            return False
        return True
    return [a for a in alerts if ok(a)]


async def alerts_page(request: Request):
    st = _st(request)
    q = dict(request.query_params)
    with st.lock:
        cases = {c["case_id"]: c for c in st.store.list_cases()}
        case = st.store.get_case(q["case"]) if q.get("case") else None
        alerts = st.store.list_alerts(case["case_id"] if case else None)
    alerts = _filter_alerts(alerts, q)
    alerts.sort(key=lambda a: (-SEVERITY_ORDER.index(a["threat"]["severity"]), -CONF_ORDER.index(a["confidence"]), a["first_time"]))
    if request.url.path.startswith("/api/"):
        return JSONResponse({"alerts": alerts, "count": len(alerts)})
    return render(request, "alerts.html", alerts=alerts, cases=cases, q=q, severities=SEVERITY_ORDER, confs=CONF_ORDER)


async def alert_page(request: Request):
    st = _st(request)
    aid = request.path_params["aid"]
    with st.lock:
        a = st.store.get_alert(aid)
        if not a:
            return _err(request, "alert not found", 404)
        case = st.store.get_case(a["case_id"])
        evs = st.store.get_events(a["event_ids"])
        notes = st.store.list_notes(a["case_id"], aid)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"alert": a, "events": evs, "notes": notes})
    return render(request, "alert.html", a=a, case=case, events=evs, notes=notes)


async def alert_explain(request: Request):
    st = _st(request)
    with st.lock:
        a = st.store.get_alert(request.path_params["aid"])
    if not a:
        return _err(request, "alert not found", 404)
    try:
        prov = provider_from_settings(st.settings)
        res = await run_in_threadpool(explain, a, prov)
    except LLMRejected as exc:
        return JSONResponse({"error": str(exc)}, status_code=422)
    except Exception as exc:  # noqa: BLE001 - network/timeouts of optional layer
        return JSONResponse({"error": f"LLM provider error: {type(exc).__name__}"}, status_code=502)
    return JSONResponse(res)


def _original_record(st: AppState, ev: dict):
    row = st.store.conn.execute("SELECT stored_path, format, original_name, sha256, provenance_trust FROM inputs WHERE input_id=?",
                                (ev["input_id"],)).fetchone()
    if not row:
        return None
    info = dict(row)
    path = Path(row["stored_path"])
    text = None
    if row["format"] in ("native_jsonl", "splunk_json", "zeek_jsonl", "splunk_csv") and path.is_file():
        with open(path, "rb") as fh:
            for no, line in enumerate(fh, start=1):
                if no == ev["record_no"]:
                    text = line[:8192].decode("utf-8", "replace")
                    break
    elif row["format"] == "sysmon_xml":
        text = f"(XML <Event> element #{ev['record_no']} in the retained file)"
    info["record_text"] = text
    info["location"] = f"{'line' if row['format'] != 'sysmon_xml' else 'Event element'} {ev['record_no']}"
    return info


async def event_page(request: Request):
    st = _st(request)
    with st.lock:
        evs = st.store.get_events([request.path_params["eid"]])
        if not evs:
            return _err(request, "event not found", 404)
        ev = evs[0]
        case = st.store.get_case(ev["case_id"])
        orig = _original_record(st, ev)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"event": ev, "original": orig})
    return render(request, "event.html", ev=ev, orig=orig, case=case)


async def entities_page(request: Request):
    st = _st(request)
    q = dict(request.query_params)
    with st.lock:
        cases = st.store.list_cases()
        case = st.store.get_case(q.get("case") or (cases[0]["case_id"] if cases else ""))
        ents = st.store.list_entities(case["case_id"], q.get("type") or None) if case else []
    if request.url.path.startswith("/api/"):
        return JSONResponse({"entities": ents})
    return render(request, "entities.html", ents=ents[:1000], case=case, cases=cases, q=q)


async def entity_page(request: Request):
    st = _st(request)
    with st.lock:
        e = st.store.get_entity(request.path_params["eid"])
        if not e:
            return _err(request, "entity not found", 404)
        rels = st.store.entity_relationships(e["entity_id"])
        evs = st.store.get_events(st.store.entity_event_ids(e["entity_id"], 100))
        case = st.store.get_case(e["case_id"])
    return render(request, "entity.html", e=e, rels=rels, events=evs, case=case)


async def rules_page(request: Request):
    st = _st(request)
    rules, rules_hash, errors, registry, iocs = load_context(st.settings)
    data = [r.model_dump(by_alias=True) for r in rules]
    if request.url.path.startswith("/api/"):
        return JSONResponse({"rules": data, "rules_hash": rules_hash, "errors": errors})
    return render(request, "rules.html", rules=data, rules_hash=rules_hash, errors=errors,
                  registry=[e.model_dump() for e in registry.entries], iocs=sum(len(v) for v in iocs.items.values()))


async def export(request: Request):
    st = _st(request)
    fmt = request.path_params.get("fmt") or request.query_params.get("format", "json")
    with st.lock:
        try:
            exp = build_case_export(st.store, st.settings, request.path_params["cid"])
        except ValueError as exc:
            return _err(request, str(exc), 404)
    name = f"argos-{exp['case']['name']}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    if fmt == "json":
        return Response(json.dumps(exp, indent=2, sort_keys=True, default=str), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
    if fmt == "html":
        return HTMLResponse(render_html(exp), headers={"Content-Disposition": f'attachment; filename="{name}.html"'})
    if fmt == "csv":
        return Response(alerts_csv([a for a in exp["alerts"] if a["current"]]), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{name}-alerts.csv"'})
    return _err(request, "format must be json, html or csv", 400)


# ------------------------------------------------------------------ JSON API
async def api_cases(request: Request):
    st = _st(request)
    if request.method == "POST":
        body = await request.json()
        try:
            with st.lock:
                c = st.store.create_case(str(body.get("name", "")), bool(body.get("synthetic", False)), str(body.get("description", ""))[:2000])
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return JSONResponse(c, status_code=201)
    with st.lock:
        return JSONResponse({"cases": st.store.list_cases()})


async def api_import(request: Request):
    try:
        res = await _do_import(request, request.path_params["cid"])
    except (ImportError_, MappingError, ValueError) as exc:
        return JSONResponse({"status": "error", "error": str(exc)}, status_code=400)
    return JSONResponse(res, status_code=200 if res["status"] != "rejected" else 422)


async def api_assessment(request: Request):
    st = _st(request)
    with st.lock:
        c = st.store.get_case(request.path_params["cid"])
        if not c:
            return JSONResponse({"error": "case not found"}, status_code=404)
        return JSONResponse({"case": c, "assessment": st.store.latest_assessment(c["case_id"]), "runs": st.store.list_runs(c["case_id"])})


async def api_shutdown(request: Request):
    """Clean shutdown for the local launcher (authenticated; CSRF/Origin rules apply)."""
    st = _st(request)
    if st.server is None:
        return JSONResponse({"error": "shutdown not available in this mode"}, status_code=409)
    st.server.should_exit = True
    return JSONResponse({"ok": True, "message": "ARGOS Defense is shutting down"})


def create_app(settings: Settings | None = None, token: str | None = None, port: int = 8789) -> Starlette:
    settings = settings or Settings()
    settings.ensure()
    token = token or ensure_token(settings)
    routes = [
        Route("/login", login, methods=["GET", "POST"]),
        Route("/health", health),
        Route("/", overview),
        Route("/cases", create_case, methods=["POST"]),
        Route("/cases/{cid}", case_page),
        Route("/cases/{cid}/analyze", case_analyze, methods=["POST"]),
        Route("/cases/{cid}/status", case_status, methods=["POST"]),
        Route("/cases/{cid}/notes", add_note, methods=["POST"]),
        Route("/cases/{cid}/export.{fmt}", export),
        Route("/inputs/{iid}/attest", attest_input, methods=["POST"]),
        Route("/import", import_page),
        Route("/import", import_post, methods=["POST"]),
        Route("/alerts", alerts_page),
        Route("/alerts/{aid}", alert_page),
        Route("/alerts/{aid}/notes", add_note, methods=["POST"]),
        Route("/alerts/{aid}/status", alert_status, methods=["POST"]),
        Route("/events/{eid}", event_page),
        Route("/entities", entities_page),
        Route("/entities/{eid}", entity_page),
        Route("/rules", rules_page),
        Route("/api/cases", api_cases, methods=["GET", "POST"]),
        Route("/api/cases/{cid}/import", api_import, methods=["POST"]),
        Route("/api/cases/{cid}/analyze", case_analyze, methods=["POST"]),
        Route("/api/cases/{cid}/assessment", api_assessment),
        Route("/api/cases/{cid}/notes", add_note, methods=["POST"]),
        Route("/api/cases/{cid}/export", export),
        Route("/api/alerts", alerts_page),
        Route("/api/alerts/{aid}", alert_page),
        Route("/api/alerts/{aid}/notes", add_note, methods=["POST"]),
        Route("/api/alerts/{aid}/status", alert_status, methods=["POST"]),
        Route("/api/alerts/{aid}/explain", alert_explain, methods=["POST"]),
        Route("/api/events/{eid}", event_page),
        Route("/api/entities", entities_page),
        Route("/api/rules", rules_page),
        Route("/api/shutdown", api_shutdown, methods=["POST"]),
        Mount("/static", StaticFiles(directory=str(STATIC)), name="static"),
    ]
    app = Starlette(routes=routes, middleware=[Middleware(SecurityMiddleware)], exception_handlers={CSRFError: csrf_error})
    app.state.argos = AppState(settings, token, port)
    return app
