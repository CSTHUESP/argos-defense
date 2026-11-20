"""Regenerate documentation screenshots and sample reports from a fresh SYNTHETIC demo.
Never captures the login page or the token. Usage: python scripts/capture_docs_media.py"""
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
SAMPLES = ROOT / "docs" / "samples"


def main():
    home = Path(tempfile.mkdtemp(prefix="argos-docs-"))
    cli = [sys.executable, "-m", "argos", "--data-dir", str(home)]
    env = {**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")}
    subprocess.run(cli + ["demo"], check=True, env=env, capture_output=True)
    SAMPLES.mkdir(parents=True, exist_ok=True)
    for fmt in ("html", "json", "csv"):
        subprocess.run(cli + ["report", "--case", "demo-synthetic", "--format", fmt, "--output", str(SAMPLES / f"demo-synthetic-report.{fmt}")],
                       check=True, env=env, capture_output=True)
    p = subprocess.Popen(cli + ["serve", "--port", "0"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(200):
            if (home / "server.json").exists():
                break
            time.sleep(0.05)
        base = json.loads((home / "server.json").read_text())["url"].rstrip("/")
        token = (home / ".session_token").read_text().strip()
        time.sleep(1)
        from playwright.sync_api import sync_playwright
        OUT.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as pw:
            br = pw.chromium.launch(headless=True, args=["--no-proxy-server"])
            pg = br.new_page(viewport={"width": 1440, "height": 1000})
            pg.goto(f"{base}/login?token={token}")  # URL is never captured; screenshots start after redirect
            shots = [("01-overview.png", "/"), ("03-alert-queue.png", "/alerts?show_authorized=1"), ("06-rules.png", "/rules")]
            for name, path in shots:
                pg.goto(base + path)
                pg.screenshot(path=str(OUT / name), full_page=name != "06-rules.png")
            pg.goto(base + "/")
            pg.click("a:has-text('demo-synthetic')")
            pg.screenshot(path=str(OUT / "02-case-assessment.png"), full_page=True)
            pg.goto(base + "/alerts")
            pg.click("a:has-text('Failures, then success, then sensitive action')")
            pg.screenshot(path=str(OUT / "04-alert-detail.png"), full_page=True)
            pg.goto(base + "/alerts?llm=directly_observed")
            pg.click("a:has-text('Model tool-call linked to an endpoint process')")
            pg.screenshot(path=str(OUT / "05-alert-llm-linkage.png"), full_page=True)
            pg.goto(base + "/entities?type=account")
            pg.screenshot(path=str(OUT / "07-entities.png"), full_page=True)
            br.close()
    finally:
        p.terminate()
        p.wait(10)
    for f in list(OUT.glob("*.png")) + list(SAMPLES.glob("*")):
        data = f.read_bytes()
        assert token.encode() not in data, f"token found in {f}"
    shutil.rmtree(home, ignore_errors=True)
    print("docs media regenerated:", sorted(x.name for x in OUT.glob("*.png")), sorted(x.name for x in SAMPLES.glob("*")))


if __name__ == "__main__":
    main()
