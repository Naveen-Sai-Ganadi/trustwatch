"""Build the TrustWatch desktop app for this OS and package it for a release.

    uv run --group build --extra desktop python packaging/build.py

macOS:   dist/TrustWatch.app and dist/TrustWatch-<version>-mac-<arm64|x86_64>.dmg
Windows: dist/TrustWatch/ and dist/TrustWatch-<version>-windows-x64.zip (a TrustWatch folder inside)

Prints the path of the .dmg or .zip. Exits non-zero on any failure.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

import trustwatch

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "packaging" / "trustwatch.spec"
DIST = ROOT / "dist"
WORK = ROOT / "build"
VERSION = trustwatch.__version__


def run(cmd: list[str]) -> None:
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def mac_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "arm64"
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    raise SystemExit(f"unsupported macOS architecture: {platform.machine()}")


def pyinstaller() -> None:
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
         "--distpath", str(DIST), "--workpath", str(WORK), str(SPEC)])


def package_mac() -> Path:
    app = DIST / "TrustWatch.app"
    if not app.is_dir():
        raise SystemExit(f"PyInstaller did not produce {app}")
    dmg = DIST / f"TrustWatch-{VERSION}-mac-{mac_arch()}.dmg"
    cmd = ["hdiutil", "create", "-volname", "TrustWatch", "-srcfolder", str(app), "-ov", "-format", "UDZO", str(dmg)]
    # hdiutil sometimes fails with "Resource busy" on CI runners; a retry usually clears it.
    for attempt in range(1, 4):
        try:
            run(cmd)
            break
        except subprocess.CalledProcessError:
            if attempt == 3:
                raise
            print(f"hdiutil failed, retrying ({attempt}/3)", flush=True)
            time.sleep(5)
    return dmg


def package_windows() -> Path:
    folder = DIST / "TrustWatch"
    if not (folder / "TrustWatch.exe").is_file():
        raise SystemExit(f"PyInstaller did not produce {folder / 'TrustWatch.exe'}")
    base = DIST / f"TrustWatch-{VERSION}-windows-x64"
    return Path(shutil.make_archive(str(base), "zip", root_dir=DIST, base_dir="TrustWatch"))


def main() -> int:
    if sys.platform == "darwin":
        package = package_mac
    elif sys.platform == "win32":
        package = package_windows
    else:
        print(f"TrustWatch desktop builds are made on macOS and Windows, not {sys.platform}", file=sys.stderr)
        return 2
    try:
        pyinstaller()
        artifact = package()
    except subprocess.CalledProcessError as e:
        print(f"build failed: {e}", file=sys.stderr)
        return 1
    print(artifact)
    return 0


if __name__ == "__main__":
    sys.exit(main())
