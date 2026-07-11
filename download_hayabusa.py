"""Download the latest Hayabusa release for this platform and extract it to ./hayabusa/.

Usage:
    python download_hayabusa.py
"""

import json
import platform
import shutil
import stat
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

API_URL = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
DEST_DIR = Path(__file__).parent / "hayabusa"


def platform_patterns() -> list[str]:
    """Return candidate substrings (in priority order) that identify the
    release asset matching this OS/architecture, per Hayabusa's naming
    convention (e.g. hayabusa-3.4.0-win-x64.zip)."""
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Windows":
        return ["win-x86"] if machine in ("x86", "i686") else ["win-x64"]
    if system == "Linux":
        return ["lin-x64-gnu", "lin-x64-musl"]
    if system == "Darwin":
        return ["mac-arm"] if machine in ("arm64", "aarch64") else ["mac-intel"]

    raise RuntimeError(f"Unsupported platform: {system} ({machine})")


def fetch_latest_release() -> dict:
    request = urllib.request.Request(
        API_URL, headers={"User-Agent": "mcp-hayabusa-downloader"}
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def pick_asset(release: dict, patterns: list[str]) -> dict:
    assets = release.get("assets", [])
    for pattern in patterns:
        for asset in assets:
            name = asset["name"].lower()
            if pattern not in name or name.endswith((".sha256", ".sig")):
                continue
            if "live-response" in name:
                continue  # self-contained triage build; we want the standard layout
            return asset
    raise RuntimeError(
        f"No release asset matched any of {patterns}. "
        f"Available assets: {[a['name'] for a in assets]}"
    )


def download(url: str, dest: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "mcp-hayabusa-downloader"})
    with urllib.request.urlopen(request) as response, open(dest, "wb") as f:
        shutil.copyfileobj(response, f)


def install(archive_path: Path, asset_name: str) -> None:
    DEST_DIR.mkdir(parents=True, exist_ok=True)

    if asset_name.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(DEST_DIR)
    else:
        target = DEST_DIR / asset_name
        shutil.copy(archive_path, target)
        target.chmod(target.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    link_stable_name()


def link_stable_name() -> None:
    """Copy the versioned hayabusa-x.y.z-... binary to a fixed name
    (hayabusa.exe / hayabusa) so other tooling can rely on a stable path
    instead of parsing the version out of the filename."""
    stable_name = "hayabusa.exe" if platform.system() == "Windows" else "hayabusa"
    stable_path = DEST_DIR / stable_name

    for candidate in sorted(DEST_DIR.glob("hayabusa-*")):
        if candidate.is_file():
            shutil.copy(candidate, stable_path)
            stable_path.chmod(stable_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            return


def main() -> None:
    patterns = platform_patterns()
    print(f"Looking up latest Hayabusa release for pattern(s): {patterns}")
    release = fetch_latest_release()
    tag = release.get("tag_name", "unknown")
    asset = pick_asset(release, patterns)
    print(f"Found {asset['name']} ({tag})")

    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / asset["name"]
        print(f"Downloading to {archive_path} ...")
        download(asset["browser_download_url"], archive_path)

        print(f"Extracting to {DEST_DIR} ...")
        install(archive_path, asset["name"])

    print(f"Done. Hayabusa {tag} is available under {DEST_DIR}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
