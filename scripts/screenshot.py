"""Capture README screenshots with headless Chrome. Start the server first: make stack.

Usage: uv run python scripts/screenshot.py --port 8861
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

CHROME_PATHS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome",
    "chromium",
]
DOCS = Path(__file__).resolve().parents[1] / "docs"


def chrome() -> str:
    for c in CHROME_PATHS:
        if Path(c).exists() or shutil.which(c):
            return c
    raise SystemExit("Chrome not found")


def shoot(url: str, out: Path, width: int, height: int) -> None:
    args = [
        chrome(),
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        f"--window-size={width},{height}",
        "--virtual-time-budget=15000",
        f"--screenshot={out}",
        url,
    ]
    subprocess.run(args, check=True, capture_output=True, timeout=60)
    print(f"wrote {out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8861)
    a = ap.parse_args()
    base = f"http://127.0.0.1:{a.port}"
    DOCS.mkdir(exist_ok=True)
    shoot(f"{base}/#/analytics", DOCS / "screenshot.png", 1400, 1700)
    shoot(f"{base}/#/decisions?planted=P3", DOCS / "decision-trace.png", 1400, 1000)
    shoot(f"{base}/#/simulate", DOCS / "simulator.png", 1400, 1100)
    shoot(f"{base}/#/diff", DOCS / "policy-diff.png", 1400, 1100)
    shoot(f"{base}/#/sessions?status=revoked", DOCS / "sessions.png", 1400, 800)

if __name__ == "__main__":
    main()
