# PyInstaller spec for the TrustWatch desktop app (macOS and Windows).
#
# Build with packaging/build.py, which runs:
#   python -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging/trustwatch.spec
# Output: dist/TrustWatch.app on macOS, dist/TrustWatch/TrustWatch.exe on Windows (one folder, no console).
#
# pywebview ships its own PyInstaller hook (webview/__pyinstaller/hook-webview.py; pyinstaller-hooks-contrib has one
# too) that adds its JavaScript and, on Windows, the WebView2 DLLs in webview/lib. pyinstaller-hooks-contrib's
# hook-clr.py / hook-clr_loader.py add pythonnet's Python.Runtime.dll and clr_loader's DLLs. This spec only picks the
# right GUI backend for each OS (Cocoa on macOS; WinForms + EdgeChromium/WebView2 on Windows) and leaves the others
# (the other OS's, Qt, GTK, CEF, Android) out.

import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

import trustwatch

IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform == "win32"

ENTRY = os.path.join(SPECPATH, "entry.py")  # noqa: F821 (SPECPATH is set by PyInstaller)

# Bundled reference data (trustwatch/data/**) and the dashboard (trustwatch/ui/index.html).
datas = collect_data_files("trustwatch")
# The MIT notice travels inside the app (added here, before the bundle is signed, so the seal stays valid).
datas.append((os.path.join(SPECPATH, "..", "LICENSE"), "."))  # noqa: F821

# The CLI imports trustwatch.server lazily; take every module so nothing is missed.
hiddenimports = collect_submodules("trustwatch")

# pywebview: its core modules plus only this OS's backend.
ALL_BACKENDS = ("cocoa", "winforms", "edgechromium", "mshtml", "win32", "qt", "gtk", "cef", "android")
if IS_MAC:
    keep_backends = ("cocoa",)
elif IS_WIN:
    keep_backends = ("winforms", "edgechromium", "mshtml", "win32")
else:
    keep_backends = ()


def _wanted(name):
    parts = name.split(".")
    if len(parts) >= 3 and parts[1] == "platforms":
        return parts[2] in keep_backends
    return True


hiddenimports += collect_submodules("webview", filter=_wanted)
if IS_WIN:
    # pythonnet: winforms.py does `import clr`; the hooks then collect Python.Runtime.dll.
    hiddenimports += ["clr", "clr_loader"]

excludes = [f"webview.platforms.{b}" for b in ALL_BACKENDS if b not in keep_backends] + [
    "PyQt5", "PyQt6", "PySide2", "PySide6", "qtpy", "gi", "cefpython3", "jnius",
]

a = Analysis(  # noqa: F821
    [ENTRY],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # onedir: libraries go next to the executable
    name="TrustWatch",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX-packed executables trip antivirus heuristics on Windows
    console=False,  # windowed: no terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,  # the build machine's own architecture (CI builds arm64 and x86_64 separately)
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="TrustWatch",
)

if IS_MAC:
    app = BUNDLE(  # noqa: F821
        coll,
        name="TrustWatch.app",
        icon=None,
        bundle_identifier="io.github.naveen-sai-ganadi.trustwatch",
        version=trustwatch.__version__,
        info_plist={
            "CFBundleName": "TrustWatch",
            "CFBundleDisplayName": "TrustWatch",
            "CFBundleShortVersionString": trustwatch.__version__,
            "CFBundleVersion": trustwatch.__version__,
            "NSHighResolutionCapable": True,
        },
    )
