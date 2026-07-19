"""Download MITRE ATT&CK Enterprise technique data and cache it locally as
mappings/attack_techniques.json, so server.py can look up technique
name/description/tactics without fetching the (~40MB) STIX bundle on every
resource read.

Usage:
    python download_attack_data.py
"""

import json
import sys
import urllib.request
from pathlib import Path

ATTACK_DATA_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
DEST_PATH = Path(__file__).parent / "mappings" / "attack_techniques.json"


def fetch_stix_bundle() -> dict:
    request = urllib.request.Request(
        ATTACK_DATA_URL, headers={"User-Agent": "mcp-hayabusa-downloader"}
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def external_attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def extract_techniques(bundle: dict) -> dict:
    techniques = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = external_attack_id(obj)
        if not technique_id:
            continue

        url = next(
            (
                ref.get("url")
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )
        tactics = sorted(
            {
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            }
        )

        techniques[technique_id] = {
            "id": technique_id,
            "name": obj.get("name"),
            "description": (obj.get("description") or "").strip(),
            "tactics": tactics,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "url": url,
        }
    return techniques


def main() -> None:
    print(f"Downloading ATT&CK Enterprise STIX bundle from {ATTACK_DATA_URL} ...")
    bundle = fetch_stix_bundle()

    print("Extracting techniques ...")
    techniques = extract_techniques(bundle)

    DEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(DEST_PATH, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2, sort_keys=True)

    print(f"Done. Wrote {len(techniques)} techniques to {DEST_PATH}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
