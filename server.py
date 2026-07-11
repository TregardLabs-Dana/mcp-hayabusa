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
VALID_OUTPUT_FORMATS = ["summary", "full"]

# Fields kept per detection when output_format="summary" - enough to triage
# without the full Details/ExtraFieldInfo payload that can blow past tool
# output size limits on large scans.
SUMMARY_FIELDS = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID"]

SCAN_TIMEOUT_SECONDS = 300


@mcp.tool()
def scan_evtx(
    evtx_path: str,
    min_severity: str = "informational",
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    """Scan an EVTX file (or directory of EVTX files) with Hayabusa and
    return detections as structured JSON, filtered to a minimum severity
    level (informational, low, medium, high, critical).

    rule_filter: case-insensitive substring match against each detection's
        rule title (e.g. "lateral" or "mimikatz"); only matching detections
        are returned.
    output_format: "summary" (default) returns condensed detections (time,
        rule, severity, host, channel, event/record IDs); "full" includes
        the complete Details/ExtraFieldInfo payload for each detection.
    max_results: caps the number of detections returned (after rule_filter
        is applied). The response's "total_count" reflects the count before
        this cap, and "truncated" is set if results were cut off.
    """
    path = Path(evtx_path)
    if not path.exists():
        return {"error": f"Path not found: {evtx_path}"}

    min_severity = min_severity.lower()
    if min_severity not in VALID_SEVERITIES:
        return {
            "error": f"Invalid min_severity '{min_severity}'. Must be one of: {VALID_SEVERITIES}"
        }

    output_format = output_format.lower()
    if output_format not in VALID_OUTPUT_FORMATS:
        return {
            "error": f"Invalid output_format '{output_format}'. Must be one of: {VALID_OUTPUT_FORMATS}"
        }

    if max_results is not None and max_results <= 0:
        return {"error": f"Invalid max_results '{max_results}'. Must be a positive integer."}

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

    if rule_filter:
        needle = rule_filter.lower()
        detections = [d for d in detections if needle in d.get("RuleTitle", "").lower()]

    total_count = len(detections)

    truncated = max_results is not None and total_count > max_results
    if max_results is not None:
        detections = detections[:max_results]

    if output_format == "summary":
        detections = [{k: d.get(k) for k in SUMMARY_FIELDS} for d in detections]

    return {
        "evtx_path": evtx_path,
        "min_severity": min_severity,
        "rule_filter": rule_filter,
        "output_format": output_format,
        "total_count": total_count,
        "count": len(detections),
        "truncated": truncated,
        "detections": detections,
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
