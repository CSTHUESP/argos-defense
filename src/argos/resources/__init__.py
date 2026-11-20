"""Locate bundled read-only resources (rules, default config, templates, static files).

Works for a source checkout, an installed wheel and a PyInstaller onedir bundle: all of
them keep these files next to the package modules, so paths are resolved relative to
this file - never relative to the current working directory or a source checkout.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]  # .../argos


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def package_dir() -> Path:
    return PACKAGE_DIR


def resources_dir() -> Path:
    return PACKAGE_DIR / "resources"


def rules_dir() -> Path:
    env = os.environ.get("ARGOS_RULES")
    return Path(env).resolve() if env else resources_dir() / "rules"


def default_config_dir() -> Path:
    return resources_dir() / "config"


def templates_dir() -> Path:
    return PACKAGE_DIR / "templates"


def static_dir() -> Path:
    return PACKAGE_DIR / "static"


def notices_dir() -> Path:
    return resources_dir() / "notices"


def check() -> dict:
    """Return a map of required resource -> exists (used by `doctor` and packaged smoke tests)."""
    items = {
        "rules": rules_dir() / "detections",
        "iocs": rules_dir() / "iocs",
        "default_config": default_config_dir() / "authorized_automation.yaml",
        "templates": templates_dir() / "base.html",
        "report_template": templates_dir() / "report.html",
        "static_css": static_dir() / "app.css",
        "static_js": static_dir() / "app.js",
        "license": notices_dir() / "LICENSE",
        "third_party_notices": notices_dir() / "THIRD_PARTY_NOTICES.md",
    }
    return {k: v.exists() for k, v in items.items()}
