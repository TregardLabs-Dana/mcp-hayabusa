"""Quick manual check: calls scan_evtx directly against every sample EVTX file.

Usage:
    python test_server.py
"""

import sys
from pathlib import Path

import server

SAMPLES_DIR = Path(__file__).parent / "samples"


def main() -> None:
    samples = sorted(SAMPLES_DIR.glob("*.evtx"))
    if not samples:
        print(f"No .evtx files found in {SAMPLES_DIR}", file=sys.stderr)
        sys.exit(1)

    failures = []

    for sample in samples:
        result = server.scan_evtx(str(sample), min_severity="informational")

        if "error" in result:
            print(f"{sample.name}: ERROR - {result['error']}")
            failures.append(sample.name)
            continue

        print(f"{sample.name}: count={result['count']}")
        if result["detections"]:
            top_rule = result["detections"][0]["RuleTitle"]
            print(f"  first detection: {top_rule}")

    if failures:
        print(f"\n{len(failures)} sample(s) failed: {failures}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
