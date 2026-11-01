#!/usr/bin/env python3
"""Rebuild the bundled eMudhra event (src/trustwatch/data/events/emudhra-2026-10) from
https://emudhra.we-have-a-problem.com/.

  uv run python scripts/import_emudhra.py             # download the tracker's files
  uv run python scripts/import_emudhra.py DOWNLOAD_DIR  # or use saved copies

DOWNLOAD_DIR must hold impacted-intermediates.json, roots.json, chains.zip and emudhra.html (the index page).
`trustwatch update-feed` runs the same import into the user's cache.
"""
import shutil
import sys
from pathlib import Path

from trustwatch import emudhra

OUT = Path(__file__).resolve().parents[1] / "src/trustwatch/data/events" / emudhra.ID


def main(src: Path | None) -> None:
    if src:
        files = emudhra.build((src / "emudhra.html").read_text(), *((src / f).read_bytes() for f in emudhra.FILES))
    else:
        files = emudhra.fetch()
    shutil.rmtree(OUT / "chains", ignore_errors=True)
    for rel, data in files.items():
        (OUT / rel).parent.mkdir(parents=True, exist_ok=True)
        (OUT / rel).write_bytes(data)
    print(f"wrote {OUT}: {sum(k.startswith('chains/') for k in files)} chains")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
