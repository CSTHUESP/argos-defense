"""Launcher, data-dir, resource discovery, migration and shutdown behaviour (source install).
The same behaviours are re-checked against the frozen executables by packaging/smoke_test.py."""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from argos.cli import main
from argos.resources import check
from argos.store import SCHEMA, Store
from conftest import ROOT

ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}


def test_all_bundled_resources_present():
    assert all(check().values()), check()


def test_platform_data_dir_not_inside_package(tmp_path, monkeypatch):
    from argos.config import Settings, platform_data_dir
    monkeypatch.delenv("ARGOS_HOME", raising=False)
    d = platform_data_dir()
    assert "argos" in str(d).lower() and "site-packages" not in str(d) and "/home/claude/argos-defense" not in str(d)
    s = Settings()
    s.home = tmp_path / "Datos ARGOS é ü"
    s.ensure()
    assert (s.config_dir / "authorized_automation.yaml").exists()  # editable copy, not the bundled file
    (s.config_dir / "rule_overrides.yaml").write_text("{}  # user edit\n")
    s.ensure()
    assert "user edit" in (s.config_dir / "rule_overrides.yaml").read_text()  # never overwritten


def test_cli_workflow_in_path_with_spaces_and_non_ascii(tmp_path, capsys):
    home = tmp_path / "carpeta con espacios ñ" / "数据"
    assert main(["--data-dir", str(home), "demo"]) == 0
    assert main(["--data-dir", str(home), "report", "--case", "demo-synthetic", "--format", "html"]) == 0
    out = home / "reports" / "demo-synthetic.html"
    assert out.exists() and "DEMO/SYNTHETIC" in out.read_text("utf-8")
    assert main(["--version"]) == 0
    from argos import __version__
    assert __version__ in capsys.readouterr().out


def test_v01_database_migrates_with_backup(tmp_path):
    db = tmp_path / "argos.sqlite3"
    c = sqlite3.connect(db)
    c.executescript(SCHEMA)  # v0.1 schema had no meta table
    c.execute("INSERT INTO cases VALUES('case-x','old',0,'',  'open','2026-11-01T00:00:00Z')")
    c.commit()
    c.close()
    st = Store(db)
    assert st.schema_version() == 4 and st.get_case("old")["case_id"] == "case-x"
    assert (tmp_path / "argos.v1-backup.sqlite3").exists()
    st.close()
    assert Store(db).schema_version() == 4  # idempotent


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_occupied_port_reports_clear_error(tmp_path):
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    port = busy.getsockname()[1]
    try:
        r = subprocess.run([sys.executable, "-m", "argos", "--data-dir", str(tmp_path / "h"), "start", "--no-browser", "--port", str(port)],
                           capture_output=True, text=True, timeout=60, env=ENV)
        assert r.returncode == 3 and "already in use" in r.stderr
    finally:
        busy.close()


def test_start_no_browser_token_hygiene_and_api_shutdown(tmp_path):
    home = tmp_path / "home ü"
    p = subprocess.Popen([sys.executable, "-m", "argos", "--data-dir", str(home), "start", "--no-browser", "--port", "0"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=ENV)
    try:
        for _ in range(200):
            if (home / "server.json").exists():
                break
            time.sleep(0.05)
        info = json.loads((home / "server.json").read_text())
        token = (home / ".session_token").read_text().strip()
        url = f"http://127.0.0.1:{info['port']}"
        for _ in range(100):
            try:
                urllib.request.urlopen(url + "/health", timeout=2)
                break
            except OSError:
                time.sleep(0.1)
        req = urllib.request.Request(url + "/api/shutdown", data=b"{}", method="POST",
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        assert json.loads(urllib.request.urlopen(req, timeout=5).read())["ok"]
        out, _ = p.communicate(timeout=30)
        assert p.returncode == 0
        assert token not in out, "session token must not be printed by default"
        assert "Session token file" in out and "ARGOS Defense stopped." in out
        assert not (home / "server.json").exists()
    finally:
        if p.poll() is None:
            p.kill()


def test_shutdown_requires_auth(tmp_path):
    home = tmp_path / "h2"
    p = subprocess.Popen([sys.executable, "-m", "argos", "--data-dir", str(home), "serve", "--port", "0"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
    try:
        for _ in range(200):
            if (home / "server.json").exists():
                break
            time.sleep(0.05)
        port = json.loads((home / "server.json").read_text())["port"]
        time.sleep(0.5)
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/shutdown", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("unauthenticated shutdown must fail")
        except urllib.error.HTTPError as e:
            assert e.code == 401
        assert p.poll() is None
    finally:
        p.terminate()
        p.wait(10)


def test_frozen_entry_defaults_to_start(monkeypatch):
    import argos.cli as cli
    called = {}
    monkeypatch.setattr(cli, "is_frozen", lambda: True)
    monkeypatch.setattr(cli, "cmd_start", lambda a, s: called.setdefault("start", a.no_browser) or 0)
    assert cli.main([]) == 0 and called["start"] is False


def test_redirected_output_is_utf8_even_with_legacy_codepage(tmp_path):
    # Simulates Windows: a redirected stream with a legacy code page must not crash on non-ASCII paths.
    env = {**ENV, "PYTHONIOENCODING": "cp1252"}
    home = tmp_path / "Prüfung 测试"
    r = subprocess.run([sys.executable, "-m", "argos", "--data-dir", str(home), "doctor"], capture_output=True, env=env, timeout=120)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    out = r.stdout.decode("utf-8")
    assert "测试" in out and "RESULT: OK" in out
