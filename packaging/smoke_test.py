"""Native packaged-application smoke test.

    python packaging/smoke_test.py --archive dist-native/ARGOS-Defense-<v>-<target>.zip --out smoke-results

The application under test is the EXTRACTED NATIVE EXECUTABLE (never `python -m argos`).
This harness (and the Playwright browser driving the UI) runs in the runner's Python;
the executable is launched with PYTHONPATH/PYTHONHOME/VIRTUAL_ENV removed, from a
working directory outside the source checkout, with a data directory whose path
contains spaces and non-ASCII characters.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import urllib.request
import zipfile
from pathlib import Path

RESULTS: list[dict] = []
SERVERS: list = []
LOG: list[str] = []
SECRETS: list[str] = []


def redact(s: str) -> str:
    for sec in SECRETS:
        if sec:
            s = s.replace(sec, "[REDACTED-TOKEN]")
    return s


def record(name, ok, detail=""):
    RESULTS.append({"check": name, "pass": bool(ok), "detail": redact(str(detail))[:2000]})
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {redact(str(detail))[:300]}", flush=True)
    return ok


def clean_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "VIRTUAL_ENV", "ARGOS_", "CONDA"))}
    venv_bin = str(Path(sys.executable).parent)
    env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep) if p and Path(p) != Path(venv_bin))
    return env


def run(exe: Path, args: list[str], cwd: Path, timeout=300) -> subprocess.CompletedProcess:
    r = subprocess.run([str(exe), *args], cwd=cwd, env=clean_env(), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    LOG.append(f"$ argos-defense {' '.join(args)}\n[exit {r.returncode}]\n{r.stdout}\n{r.stderr}")
    return r


def extract(archive: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive) as tf:
            tf.extractall(dest, filter="tar")
    elif sys.platform == "darwin":
        subprocess.run(["ditto", "-x", "-k", str(archive), str(dest)], check=True)
    else:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    tops = [p for p in dest.iterdir() if p.is_dir()]
    assert len(tops) == 1, tops
    return tops[0]


def tree_fingerprint(root: Path) -> str:
    """Content fingerprint of a directory tree (F13): relative path, entry type, permission bits,
    symlink target and SHA-256 of every regular file. Same-length edits, mode changes, added/removed
    files and retargeted symlinks all change the result. Symlinks are not followed."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*"), key=lambda x: x.relative_to(root).as_posix()):
        rel = p.relative_to(root).as_posix()
        st = p.lstat()
        mode = oct(st.st_mode & 0o7777) if os.name != "nt" else "-"
        if p.is_symlink():
            h.update(f"L|{rel}|{os.readlink(p)}\n".encode())
        elif p.is_dir():
            h.update(f"D|{rel}|{mode}\n".encode())
        elif p.is_file():
            fh = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    fh.update(chunk)
            h.update(f"F|{rel}|{mode}|{st.st_size}|{fh.hexdigest()}\n".encode())
        else:
            h.update(f"O|{rel}\n".encode())
    return h.hexdigest()


def http(url, method="GET", token=None, data=None):
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, r.read().decode("utf-8", "replace")


class Server:
    def __init__(self, exe, data, cwd):
        self.exe, self.data, self.cwd = exe, data, cwd
        self.proc = None

    def start(self):
        (self.data / "server.json").unlink(missing_ok=True)
        kw = {}
        if sys.platform.startswith("win"):
            kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        self.out = open(self.cwd / f"server-{int(time.time() * 1000)}.log", "w+", encoding="utf-8")
        SERVERS.append(self)
        self.proc = subprocess.Popen([str(self.exe), "--data-dir", str(self.data), "start", "--no-browser", "--port", "0"],
                                     cwd=self.cwd, env=clean_env(), stdout=self.out, stderr=subprocess.STDOUT, **kw)
        for _ in range(600):
            if (self.data / "server.json").exists():
                break
            if self.proc.poll() is not None:
                raise RuntimeError("server exited early")
            time.sleep(0.1)
        info = json.loads((self.data / "server.json").read_text())
        self.port = info["port"]
        self.base = f"http://127.0.0.1:{self.port}"
        for _ in range(300):
            try:
                http(self.base + "/health")
                break
            except OSError:
                time.sleep(0.1)
        self.token = (self.data / ".session_token").read_text().strip()
        SECRETS.append(self.token)
        return self

    def stop(self) -> int:
        try:
            http(self.base + "/api/shutdown", "POST", self.token, b"{}")
            code = self.proc.wait(60)
        except Exception:  # noqa: BLE001
            self.proc.kill()
            code = -999
        self.out.seek(0)
        LOG.append("[server output]\n" + self.out.read())
        self.out.close()
        return code


def browser_flow_full(srv: Server, upload: Path, shots: Path) -> None:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        br = p.chromium.launch(headless=True, args=["--no-proxy-server"])
        ctx = br.new_context(viewport={"width": 1366, "height": 900}, accept_downloads=True)
        pg = ctx.new_page()
        errors = []
        pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        pg.goto(srv.base + "/")
        record("browser: unauthenticated redirect to login", pg.url.endswith("/login"), pg.url)
        pg.fill("input[name=token]", srv.token)
        pg.click("button[type=submit]")
        record("browser: login form submission", pg.inner_text("h1") == "Overview", pg.url)
        pg.fill("input[name=name]", "smoke-ui")
        pg.check("input[name=synthetic]")
        pg.click("form[action='/cases'] button[type=submit]")
        record("browser: create case form (CSRF)", "smoke-ui" in pg.inner_text("h1"), pg.url)
        pg.click("a:has-text('Import file')")
        pg.select_option("#fmt", "sysmon_xml")
        pg.set_input_files("input[name=file]", str(upload))
        pg.click("button:has-text('Import')")
        body = pg.inner_text("body")
        record("browser: multipart import form", "imported" in body and "accepted 2" in body, body[:300])
        pg.click("a:has-text('Open case')")
        pg.click("button:has-text('Analyze / re-analyze')")
        ok = "/jobs/" in pg.url
        try:
            pg.wait_for_selector("text=Analysis run", timeout=120000)  # job page auto-refreshes
            pg.click("a.button:has-text('Open case')")
        except Exception as exc:  # noqa: BLE001
            ok = False
            LOG.append(f"analyze job page: {exc}")
        record("browser: analyze button (background job with progress page)", ok and pg.is_visible("text=Analysis run"), pg.url)
        pg.screenshot(path=str(shots / "case.png"), full_page=True)
        pg.click("a.button:has-text('Alert queue')")
        pg.click("a:has-text('Server or office process spawned a command shell')")
        dims = all(pg.is_visible(f"text={t}") for t in ["A · Activity & threat", "C · LLM involvement", "D · Framework", "F · Entities"])
        record("browser: alert detail with separate dimensions", dims, pg.url)
        pg.fill("textarea[name=text]", "smoke note persists")
        pg.click("button:has-text('Add note')")
        record("browser: note form", "smoke note persists" in pg.inner_text("body"), "")
        pg.screenshot(path=str(shots / "alert.png"), full_page=True)
        pg.locator("a[href^='/events/']").first.click()
        body = pg.inner_text("body")
        record("browser: evidence page with original record", pg.is_visible("text=Original record") and "Lookup: located" in body
               and "&lt;Event" not in body and "EventData" in body, pg.url)
        pg.go_back()
        pg.goto(srv.base + "/")
        pg.click("a:has-text('smoke-ui')")
        with pg.expect_download() as d:
            pg.click("a.button:has-text('Export HTML')")
        dl = Path(d.value.path()).read_text("utf-8")
        record("browser: HTML export download", "DEMO/SYNTHETIC" in dl and "ARGOS Defense case report" in dl, d.value.suggested_filename)
        css = ctx.request.get(srv.base + "/static/app.css")
        record("browser: bundled static assets served", css.status == 200 and "synthbanner" in css.text(), css.status)
        record("browser: no console errors", not errors, errors)
        br.close()


def make_upload(dir_: Path) -> Path:
    xml = """<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Computer>web-77</Computer></System><EventData><Data Name="UtcTime">2026-11-03 10:00:00.000</Data><Data Name="ProcessGuid">{S-1}</Data><Data Name="ProcessId">10</Data><Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c whoami</Data><Data Name="ParentProcessGuid">{S-0}</Data><Data Name="ParentProcessId">9</Data><Data Name="ParentImage">C:\\Windows\\System32\\inetsrv\\w3wp.exe</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><Computer>web-77</Computer></System><EventData><Data Name="UtcTime">2026-11-03 10:00:05.000</Data><Data Name="ProcessGuid">{S-1}</Data><Data Name="ProcessId">10</Data><Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data><Data Name="Protocol">tcp</Data><Data Name="Initiated">true</Data><Data Name="SourceIp">10.0.0.9</Data><Data Name="SourcePort">5555</Data><Data Name="DestinationIp">203.0.113.5</Data><Data Name="DestinationPort">443</Data></EventData></Event>
</Events>
"""
    p = dir_ / "sysmon export é.xml"
    p.write_text(xml, encoding="utf-8")
    return p


def _wait_server(data: Path, proc, seconds=60):
    for _ in range(seconds * 10):
        if (data / "server.json").exists():
            return json.loads((data / "server.json").read_text())
        if proc.poll() is not None:
            return None
        time.sleep(0.1)
    return None


def launcher_checks(top: Path, base: Path, work: Path):
    """Start the app through the DISTRIBUTED launcher (.cmd / .command / .sh), with ARGOS_HOME pointing at a
    non-ASCII data directory. 1) --no-browser: server comes up and shuts down cleanly. 2) default (browser
    opening): BROWSER points at a recorder script; the login URL must reach it and target loopback."""
    if sys.platform.startswith("win"):
        launcher = top / "Start ARGOS Defense.cmd"
        argv = ["cmd.exe", "/d", "/c", str(launcher)]
    elif sys.platform == "darwin":
        launcher = top / "Start ARGOS Defense.command"
        argv = ["/bin/bash", str(launcher)]
    else:
        launcher = top / "start-argos-defense.sh"
        argv = [str(launcher)]
    record(f"launcher: {launcher.name} present", launcher.is_file(), launcher.name)
    if not sys.platform.startswith("win"):
        record("launcher: executable bit preserved", os.access(launcher, os.X_OK), oct(launcher.stat().st_mode))
    for mode in ("no-browser", "browser"):
        data = base / f"launcher data {mode} ü"
        env = clean_env()
        env["ARGOS_HOME"] = str(data)
        rec = base / f"browser-url-{mode}.txt"
        if mode == "browser":
            if sys.platform.startswith("win"):
                script = base / "record-browser.cmd"
                script.write_text(f'@echo off\r\n>"{rec}" echo %~1\r\n', encoding="utf-8")
            else:
                script = base / "record-browser.sh"
                script.write_text(f'#!/bin/sh\nprintf "%s" "$1" > "{rec}"\n', encoding="utf-8")
                os.chmod(script, 0o700)
            env["BROWSER"] = str(script)
            extra = ["--port", "0"]
        else:
            extra = ["--no-browser", "--port", "0"]
        out = open(work / f"launcher-{mode}.log", "w+", encoding="utf-8")
        kw = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform.startswith("win") else {}
        # cmd.exe quoting: /s + one outer pair of quotes keeps a launcher path with spaces intact
        cmdline = (f'cmd.exe /d /s /c ""{launcher}" {" ".join(extra)}"' if sys.platform.startswith("win") else [*argv, *extra])
        proc = subprocess.Popen(cmdline, cwd=work, env=env, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, **kw)
        info = _wait_server(data, proc)
        ok = info is not None
        srv_tok = (data / ".session_token").read_text().strip() if (data / ".session_token").exists() else ""
        SECRETS.append(srv_tok)
        if ok:  # server.json is written before the socket accepts connections: poll like Server.start
            ok = False
            for _ in range(300):
                try:
                    st, _ = http(f"http://127.0.0.1:{info['port']}/api/cases", token=srv_tok)
                    ok = st == 200
                    break
                except Exception:  # noqa: BLE001
                    time.sleep(0.1)
        record(f"launcher: {launcher.name} starts the native app ({mode}, ARGOS_HOME non-ASCII)", ok, info and info.get("port"))
        if mode == "browser":
            url = ""
            for _ in range(100):
                if rec.exists() and rec.read_text(errors="replace").strip():
                    url = rec.read_text(errors="replace").strip()
                    break
                time.sleep(0.1)
            record("launcher: default start opens the browser via BROWSER (login URL on loopback)",
                   url.startswith(f"http://127.0.0.1:{info['port'] if info else ''}/login"), redact(url)[:80])
            rec.unlink(missing_ok=True)
        else:
            record("launcher: --no-browser does not open a browser", not rec.exists(), "")
        code = -1
        if info:
            try:
                http(f"http://127.0.0.1:{info['port']}/api/shutdown", "POST", srv_tok, b"{}")
                code = proc.wait(60)
            except Exception:  # noqa: BLE001
                proc.kill()
        else:
            proc.kill()
        out.seek(0)
        LOG.append(f"[launcher {mode}]\n" + out.read())
        out.close()
        record(f"launcher: clean shutdown ({mode})", code == 0, code)


def update_backup_restore_checks(exe: Path, base: Path, work: Path, out: Path):
    """Update path: a v0.2.0 data directory (synthetic demo DB fixture) is migrated by the new executable with a
    verified pre-migration backup; then backup -> verify -> restore into a new directory -> data present."""
    import gzip
    import sqlite3
    fixture = Path(__file__).resolve().parent / "fixtures" / "legacy-v0.2.0-demo.sql.gz"
    old = base / "legacy data v0.2 ö"
    old.mkdir()
    con = sqlite3.connect(old / "argos.sqlite3")
    con.executescript(gzip.decompress(fixture.read_bytes()).decode())
    con.commit()
    con.close()
    r = run(exe, ["--data-dir", str(old), "cases"], work)
    backups = list(old.glob("argos.v2-backup.sqlite3"))
    record("update: v0.2.0 database migrated by the native app", r.returncode == 0 and "demo-synthetic" in r.stdout, r.stdout[-200:])
    ok = False
    if backups:
        b = sqlite3.connect(backups[0])
        ok = b.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and b.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 425
        b.close()
    record("update: verified pre-migration backup retained", ok, [p.name for p in backups])
    r = run(exe, ["--data-dir", str(old), "runs", "--case", "demo-synthetic"], work)
    record("update: legacy run labelled (no invented snapshot)", r.returncode == 0 and "legacy-none" in r.stdout, r.stdout[-200:])
    r = run(exe, ["--data-dir", str(old), "analyze", "--case", "demo-synthetic", "--quiet"], work)
    record("update: re-analysis after migration", r.returncode == 0 and '"run_id"' in r.stdout, r.stdout[-200:] + r.stderr[-200:])
    bk = base / "backup ü.zip"
    r = run(exe, ["--data-dir", str(old), "backup", "--output", str(bk)], work)
    record("backup: created", r.returncode == 0 and bk.is_file(), r.stdout[-200:])
    r = run(exe, ["verify-backup", str(bk)], work)
    record("backup: verified", r.returncode == 0 and r.stdout.startswith("OK"), r.stdout[-200:] + r.stderr[-200:])
    new = base / "restored data é"
    r = run(exe, ["--data-dir", str(new), "restore", str(bk)], work)
    record("restore: into new directory", r.returncode == 0 and '"schema_version": 3' in r.stdout, r.stdout[-300:] + r.stderr[-300:])
    r = run(exe, ["--data-dir", str(new), "alerts", "--case", "demo-synthetic"], work)
    record("restore: restored case and alerts readable", r.returncode == 0 and "ARG-" in r.stdout, r.stdout[-200:])
    r = run(exe, ["--data-dir", str(new), "restore", str(bk)], work)
    record("restore: refuses non-empty target", r.returncode == 2, r.stderr[-200:])


def kill_leftovers():
    for s in SERVERS:
        if s.proc is not None and s.proc.poll() is None:
            s.proc.kill()
            try:
                s.proc.wait(30)
            except subprocess.TimeoutExpired:
                pass


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", required=True)
    ap.add_argument("--out", default="smoke-results")
    ap.add_argument("--no-browser", action="store_true", help="skip the Playwright part (NOT valid for a release gate)")
    a = ap.parse_args(argv)
    archive = Path(a.archive).resolve()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "screenshots").mkdir(exist_ok=True)
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    base = Path(tempfile.mkdtemp(prefix="argos smoke ")) / "Prüfung ARGOS 测试"
    meta = {"archive": archive.name, "archive_sha256": sha, "archive_size": archive.stat().st_size,
            "os": {"platform": platform.platform(), "system": platform.system(), "release": platform.release(),
                   "version": platform.version(), "machine": platform.machine(), "mac_ver": platform.mac_ver()[0],
                   "win32_ver": " ".join(platform.win32_ver()), "runner_image": os.environ.get("ImageOS", ""),
                   "runner_image_version": os.environ.get("ImageVersion", "")},
            "harness_python": platform.python_version(), "extract_dir_has_space_and_non_ascii": True}
    try:
        top = extract(archive, base / "extracted app")
        exe = top / "argos-defense" / ("argos-defense.exe" if sys.platform.startswith("win") else "argos-defense")
        record("archive: executable present", exe.is_file(), exe.relative_to(base))
        if not sys.platform.startswith("win"):
            record("archive: executable permission preserved", os.access(exe, os.X_OK), oct(exe.stat().st_mode))
        bundle_before = tree_fingerprint(top)
        work = base / "work dir ñ"
        work.mkdir()
        data = base / "datos de prueba é"
        r = run(exe, ["--version"], work)
        record("exe: --version runs as frozen executable", r.returncode == 0 and "frozen=True" in r.stdout, r.stdout.strip())
        r = run(exe, ["--data-dir", str(data), "doctor"], work)
        record("exe: doctor (bundled templates/static/rules/notices)", r.returncode == 0 and "RESULT: OK" in r.stdout, r.stdout[-400:])
        r = run(exe, ["--data-dir", str(data), "demo"], work)
        record("exe: demo generation + analysis", r.returncode == 0 and "DEMO/SYNTHETIC case 'demo-synthetic'" in r.stdout, r.stdout[-300:])
        up = make_upload(work)
        r = run(exe, ["--data-dir", str(data), "ingest", str(up), "--format", "sysmon_xml", "--case", "smoke-cli", "--synthetic"], work)
        record("exe: ingest sysmon XML", r.returncode == 0 and '"accepted": 2' in r.stdout, r.stdout[-200:])
        r = run(exe, ["--data-dir", str(data), "analyze", "--case", "smoke-cli"], work)
        record("exe: analyze", r.returncode == 0 and '"alerts"' in r.stdout, r.stdout[-200:])
        r = run(exe, ["--data-dir", str(data), "alerts", "--case", "smoke-cli"], work)
        record("exe: alerts include EP-001/EP-002", "ARG-EP-001" in r.stdout and "ARG-EP-002" in r.stdout, r.stdout[-400:])
        tzf = work / "naive times.jsonl"
        tzf.write_text('{"event_time": "2026-11-03 10:00:00", "event_kind": "dns", "dns_query": "a.example"}\n', encoding="utf-8")
        r = run(exe, ["--data-dir", str(data), "ingest", str(tzf), "--format", "native_jsonl", "--case", "smoke-tz", "--synthetic",
                      "--assume-tz", "Europe/Budapest"], work)
        record("exe: IANA time zone resolves (bundled tz database)", r.returncode == 0 and '"accepted": 1' in r.stdout, r.stdout[-200:] + r.stderr[-300:])
        rep = out / "report-smoke-demo.html"
        r = run(exe, ["--data-dir", str(data), "report", "--case", "demo-synthetic", "--format", "html", "--output", str(rep)], work)
        record("exe: HTML report export", r.returncode == 0 and "DEMO/SYNTHETIC" in rep.read_text("utf-8"), rep.name)
        repj = out / "report-smoke-demo.json"
        r = run(exe, ["--data-dir", str(data), "report", "--case", "demo-synthetic", "--format", "json", "--output", str(repj)], work)
        record("exe: JSON report export", r.returncode == 0 and json.loads(repj.read_text("utf-8"))["case"]["synthetic"], repj.name)
        # occupied port handling
        srv = Server(exe, data, work).start()
        r = run(exe, ["--data-dir", str(data), "start", "--no-browser", "--port", str(srv.port)], work, timeout=60)
        record("exe: occupied port reported clearly", r.returncode == 3 and "already in use" in r.stderr, r.stderr.strip())
        st, body = http(srv.base + "/api/cases", token=srv.token)
        record("http: authenticated API", st == 200 and "demo-synthetic" in body, st)
        try:
            http(srv.base + "/api/cases")
            record("http: unauthenticated API rejected", False, "200")
        except urllib.error.HTTPError as e:
            record("http: unauthenticated API rejected", e.code == 401, e.code)
        if a.no_browser:
            record("browser: SKIPPED (not valid as release gate)", False, "--no-browser")
        else:
            browser_flow_full(srv, up, out / "screenshots")
        code = srv.stop()
        record("exe: clean shutdown via authenticated API", code == 0, code)
        record("exe: runtime file removed on shutdown", not (data / "server.json").exists(), "")
        srv2 = Server(exe, data, work).start()
        st, body = http(srv2.base + "/api/cases", token=srv2.token)
        cases = json.loads(body)["cases"]
        sid = next((c["case_id"] for c in cases if c["name"] == "smoke-ui"), None)
        ok = False
        if sid or a.no_browser:
            _, alerts = http(srv2.base + f"/api/alerts?case={sid or 'smoke-cli'}", token=srv2.token)
            al = json.loads(alerts)["alerts"]
            notes = []
            for x in al:
                _, d = http(srv2.base + f"/api/alerts/{x['alert_id']}", token=srv2.token)
                notes += [n["text"] for n in json.loads(d)["notes"]]
            ok = a.no_browser or "smoke note persists" in notes
        record("exe: persistence across restart (cases, alerts, notes)", ok, f"cases={len(cases)}")
        record("exe: second clean shutdown", srv2.stop() == 0, "")
        launcher_checks(top, base, work)
        update_backup_restore_checks(exe, base, work, out)
        record("bundle: no files written inside the application bundle", tree_fingerprint(top) == bundle_before, "")
        logs = "\n".join(LOG)
        record("logs: session token never printed", all(s not in logs for s in SECRETS), "")
    except Exception as exc:  # noqa: BLE001
        record("harness: unexpected error", False, f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1500:]}")
    finally:
        kill_leftovers()
    passed = all(r["pass"] for r in RESULTS) and bool(RESULTS)
    res = {"schema": "argos-smoke/2", "overall_pass": passed, "checks_total": len(RESULTS), "checks_passed": sum(r["pass"] for r in RESULTS),
           "browser_part": not a.no_browser, **meta,
           "results": RESULTS, "note": "the application under test is the extracted native executable; Playwright/harness run in the runner's Python"}
    target = re.sub(r"^ARGOS-Defense-[^-]+-|\.(zip|tar\.gz)$", "", archive.name)
    (out / f"smoke-{target}.json").write_text(json.dumps(res, indent=2))
    (out / f"smoke-{target}.log").write_text(redact("\n".join(LOG)), encoding="utf-8")
    shutil.rmtree(base.parent, ignore_errors=True)
    print(f"OVERALL: {'PASS' if passed else 'FAIL'} ({res['checks_passed']}/{res['checks_total']})")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
