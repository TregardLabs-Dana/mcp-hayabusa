import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa")

PROJECT_ROOT = Path(__file__).parent
HAYABUSA_DIR = PROJECT_ROOT / "hayabusa"
HAYABUSA_EXE = HAYABUSA_DIR / ("hayabusa.exe" if os.name == "nt" else "hayabusa")
RULES_DIR = HAYABUSA_DIR / "rules"
RULES_CONFIG_DIR = RULES_DIR / "config"

# Our own curated Sigma rules (detection engineering knowledge base), distinct
# from RULES_DIR above which holds the full upstream Hayabusa/Sigma ruleset
# used for scanning.
DETECTION_RULES_DIR = PROJECT_ROOT / "rules"
RULE_NAME_RE = re.compile(r"[A-Za-z0-9_\-]+")

# Local cache of MITRE ATT&CK technique metadata, built by download_attack_data.py.
ATTACK_TECHNIQUES_PATH = PROJECT_ROOT / "mappings" / "attack_techniques.json"

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


def _rule_summary(rule: dict, rule_path: Path, base_dir: Path) -> dict:
    description = rule.get("description")
    return {
        "id": rule.get("id"),
        "title": rule.get("title"),
        "level": rule.get("level"),
        "status": rule.get("status"),
        "description": description.strip().splitlines()[0] if description else None,
        "logsource": {k: v for k, v in (rule.get("logsource") or {}).items() if v},
        "tags": rule.get("tags") or [],
        "file": str(rule_path.relative_to(base_dir)),
    }


@mcp.tool()
def get_hayabusa_rules(keyword: str | None = None, max_results: int = 100) -> dict:
    """List available Hayabusa/Sigma detection rules, optionally filtered by
    a keyword. Use this before scan_evtx to see what detections exist (e.g.
    to find a rule_filter value) or to check whether a technique/tool has
    rule coverage.

    keyword: case-insensitive substring matched against each rule's title,
        description, tags, and id. If omitted, all rules are listed
        (subject to max_results).
    max_results: caps the number of rules returned (default 100). The
        response's "total_count" reflects the count before this cap.
    """
    if not RULES_DIR.exists():
        return {"error": f"Rules directory not found at {RULES_DIR}. Run download_hayabusa.py first."}

    if max_results <= 0:
        return {"error": f"Invalid max_results '{max_results}'. Must be a positive integer."}

    needle = keyword.lower() if keyword else None
    matches = []
    for rule_path in RULES_DIR.rglob("*.yml"):
        try:
            text = rule_path.read_text(encoding="utf-8")
        except OSError:
            continue

        # Cheap substring check before the full YAML parse: title/description/
        # tags/id are all plain text in the file, so if the keyword isn't
        # anywhere in the raw text it can't match any of those fields either.
        if needle and needle not in text.lower():
            continue

        try:
            rule = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(rule, dict) or not rule.get("title"):
            continue

        if needle:
            haystack = " ".join(
                str(v) for v in (
                    rule.get("title"), rule.get("description"), rule.get("id"),
                    *(rule.get("tags") or []),
                )
                if v
            ).lower()
            if needle not in haystack:
                continue

        matches.append(_rule_summary(rule, rule_path, RULES_DIR))

    total_count = len(matches)
    truncated = total_count > max_results
    matches = matches[:max_results]

    return {
        "keyword": keyword,
        "total_count": total_count,
        "count": len(matches),
        "truncated": truncated,
        "rules": matches,
    }


def _iter_detection_rules():
    """Yield (path, parsed rule) for every valid Sigma rule in DETECTION_RULES_DIR."""
    for rule_path in sorted(DETECTION_RULES_DIR.glob("*.yml")):
        try:
            rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(rule, dict) and rule.get("title"):
            yield rule_path, rule


def _technique_tag(technique_id: str) -> str:
    """Normalize e.g. "T1003.001", "t1003.001", or "1003.001" to the
    "attack.tNNNN.NNN" form used in a Sigma rule's tags list."""
    return "attack.t" + technique_id.lower().lstrip("t")


def _find_rules_by_technique(technique_id: str) -> list[dict]:
    target_tag = _technique_tag(technique_id)
    return [
        {"name": rule_path.stem, **_rule_summary(rule, rule_path, DETECTION_RULES_DIR)}
        for rule_path, rule in _iter_detection_rules()
        if target_tag in [str(t).lower() for t in (rule.get("tags") or [])]
    ]


def _load_attack_techniques() -> dict:
    """Load the local ATT&CK technique cache built by download_attack_data.py.
    Returns {} if it hasn't been downloaded yet."""
    if not ATTACK_TECHNIQUES_PATH.exists():
        return {}
    try:
        return json.loads(ATTACK_TECHNIQUES_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _assess_coverage(rules: list[dict]) -> str:
    """covered: at least one matching rule has graduated past experimental
    status. partial: rules exist but are all still experimental/unstable.
    gap: no rules reference this technique at all."""
    if not rules:
        return "gap"
    if any(r.get("status") == "stable" for r in rules):
        return "covered"
    return "partial"


@mcp.resource("detection://rules")
def list_detection_rules() -> dict:
    """List all Sigma detection rules in the knowledge base (rules/ directory)."""
    if not DETECTION_RULES_DIR.exists():
        return {"error": f"Rules directory not found at {DETECTION_RULES_DIR}"}

    rules = [
        {"name": rule_path.stem, **_rule_summary(rule, rule_path, DETECTION_RULES_DIR)}
        for rule_path, rule in _iter_detection_rules()
    ]
    return {"count": len(rules), "rules": rules}


@mcp.resource("detection://rules/{rule_name}")
def get_detection_rule(rule_name: str) -> dict:
    """Get a specific Sigma rule's full content by name (the .yml filename in
    rules/, without the extension - use the "name" field from detection://rules)."""
    if not RULE_NAME_RE.fullmatch(rule_name):
        return {"error": f"Invalid rule name '{rule_name}'"}

    rule_path = DETECTION_RULES_DIR / f"{rule_name}.yml"
    if not rule_path.exists():
        return {"error": f"Rule '{rule_name}' not found in {DETECTION_RULES_DIR}"}

    try:
        raw = rule_path.read_text(encoding="utf-8")
        rule = yaml.safe_load(raw)
    except (OSError, yaml.YAMLError) as exc:
        return {"error": f"Failed to read rule '{rule_name}': {exc}"}

    return {"name": rule_name, "file": rule_path.name, "rule": rule, "raw": raw}


@mcp.resource("detection://rules/by-technique/{technique_id}")
def get_rules_by_technique(technique_id: str) -> dict:
    """List rules tagged with a given ATT&CK technique ID, e.g. "T1003.001"
    or "T1558.003" (case-insensitive, with or without the leading "T")."""
    if not DETECTION_RULES_DIR.exists():
        return {"error": f"Rules directory not found at {DETECTION_RULES_DIR}"}

    rules = _find_rules_by_technique(technique_id)
    return {"technique_id": technique_id, "count": len(rules), "rules": rules}


@mcp.resource("detection://attack/techniques/{technique_id}")
def get_attack_technique(technique_id: str) -> dict:
    """Look up a MITRE ATT&CK technique (name, description, tactics) and
    report our Sigma rule coverage for it.

    technique_id: e.g. "T1003.001" (case-insensitive, with or without the
        leading "T"). Technique metadata comes from the local cache at
        mappings/attack_techniques.json - run download_attack_data.py first
        to populate/refresh it from the MITRE ATT&CK STIX dataset. Coverage
        is always computed live from the "attack.tNNNN.NNN" tags on rules in
        rules/, regardless of whether that cache exists.
    """
    normalized_id = "T" + technique_id.upper().lstrip("T")

    rules = _find_rules_by_technique(technique_id)
    result = {
        "technique_id": normalized_id,
        "coverage": _assess_coverage(rules),
        "rules": rules,
    }

    techniques = _load_attack_techniques()
    if not techniques:
        result["name"] = None
        result["description"] = None
        result["attack_data_available"] = False
        result["note"] = (
            f"ATT&CK technique metadata not found at {ATTACK_TECHNIQUES_PATH}. "
            f"Run download_attack_data.py to fetch it."
        )
        return result

    technique = techniques.get(normalized_id)
    if technique is None:
        result["name"] = None
        result["description"] = None
        result["attack_data_available"] = True
        result["note"] = f"'{normalized_id}' was not found in the cached ATT&CK data."
        return result

    result["name"] = technique.get("name")
    result["description"] = technique.get("description")
    result["tactics"] = technique.get("tactics")
    result["url"] = technique.get("url")
    return result


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
