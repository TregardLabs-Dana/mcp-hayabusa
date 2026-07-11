import json
import os
import subprocess
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa")

PROJECT_ROOT = Path(__file__).parent
HAYABUSA_DIR = PROJECT_ROOT / "hayabusa"
HAYABUSA_EXE = HAYABUSA_DIR / ("hayabusa.exe" if os.name == "nt" else "hayabusa")
RULES_DIR = HAYABUSA_DIR / "rules"
RULES_CONFIG_DIR = RULES_DIR / "config"

VALID_SEVERITIES = ["informational", "low", "medium", "high", "critical"]

SCAN_TIMEOUT_SECONDS = 300


@mcp.tool()
def scan_evtx(evtx_path: str, min_severity: str = "informational") -> dict:
    """Scan an EVTX file (or directory of EVTX files) with Hayabusa and
    return detections as structured JSON, filtered to a minimum severity
    level (informational, low, medium, high, critical)."""
    path = Path(evtx_path)
    if not path.exists():
        return {"error": f"Path not found: {evtx_path}"}

    min_severity = min_severity.lower()
    if min_severity not in VALID_SEVERITIES:
        return {
            "error": f"Invalid min_severity '{min_severity}'. Must be one of: {VALID_SEVERITIES}"
        }

    if not HAYABUSA_EXE.exists():
        return {"error": f"Hayabusa executable not found at {HAYABUSA_EXE}. Run download_hayabusa.py first."}

    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "results.jsonl"
        input_flag = "-d" if path.is_dir() else "-f"

        command = [
            str(HAYABUSA_EXE), "json-timeline",
            input_flag, str(path.resolve()),
            "-o", str(output_path),
            "-L",
            "-m", min_severity,
            "-r", str(RULES_DIR),
            "-c", str(RULES_CONFIG_DIR),
            "-w", "-K", "-Q", "-C",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=SCAN_TIMEOUT_SECONDS,
                cwd=HAYABUSA_DIR,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"Hayabusa scan timed out after {SCAN_TIMEOUT_SECONDS} seconds"}
        except OSError as exc:
            return {"error": f"Failed to run Hayabusa: {exc}"}

        # Hayabusa can exit 0 even on failure (e.g. bad input path), so
        # error lines in stderr are the reliable signal, not the return code.
        errors = [line for line in result.stderr.splitlines() if "[ERROR]" in line]
        if errors:
            return {"error": "; ".join(errors)}

        if not output_path.exists():
            return {"error": f"Hayabusa produced no output. stderr: {result.stderr.strip()}"}

        detections = []
        with open(output_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    detections.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    return {
        "evtx_path": evtx_path,
        "min_severity": min_severity,
        "count": len(detections),
        "detections": detections,
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
