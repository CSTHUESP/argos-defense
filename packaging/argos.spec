# PyInstaller spec for ARGOS Defense (onedir). Build: pyinstaller packaging/argos.spec --noconfirm
# Resources are added at the same relative locations they have inside the `argos` package, so
# argos.resources resolves them identically in source, wheel and frozen layouts.
import os
from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
SRC = os.path.join(ROOT, "src", "argos")

datas = [
    (os.path.join(SRC, "templates"), "argos/templates"),
    (os.path.join(SRC, "static"), "argos/static"),
    (os.path.join(SRC, "resources", "rules"), "argos/resources/rules"),
    (os.path.join(SRC, "resources", "config"), "argos/resources/config"),
    (os.path.join(SRC, "resources", "notices"), "argos/resources/notices"),
]
hiddenimports = (
    collect_submodules("uvicorn")
    + collect_submodules("argos")
    + ["python_multipart", "multipart", "yaml", "defusedxml.ElementTree", "zoneinfo"]
)
if os.name == "nt":
    from PyInstaller.utils.hooks import collect_data_files
    hiddenimports += ["tzdata"] + collect_submodules("tzdata")
    datas += collect_data_files("tzdata")  # (src, dest) pairs belong in Analysis(datas=...)

a = Analysis(
    [os.path.join(SPECPATH, "argos_entry.py")],
    pathex=[os.path.join(ROOT, "src")],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "playwright", "IPython", "numpy"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="argos-defense",
    console=True,            # visible logs and errors; the launcher scripts open a terminal window
    debug=False,
    strip=False,
    upx=False,
    codesign_identity=None,  # no Developer ID available; PyInstaller applies ad-hoc signatures on macOS
    entitlements_file=None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="argos-defense")
