import datetime
import json
import os
import re
import subprocess
import tempfile
import uuid
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
TECHNIQUE_ID_RE = re.compile(r"t?\d{4}(\.\d{3})?", re.IGNORECASE)

# Curated incident response playbooks (YAML), one per alert family.
PLAYBOOKS_DIR = PROJECT_ROOT / "playbooks"

# Local cache of MITRE ATT&CK technique metadata, built by download_attack_data.py.
ATTACK_TECHNIQUES_PATH = PROJECT_ROOT / "mappings" / "attack_techniques.json"

VALID_SEVERITIES = ["informational", "low", "medium", "high", "critical"]
VALID_OUTPUT_FORMATS = ["summary", "full"]

# Fields kept per detection when output_format="summary" - enough to triage
# without the full Details/ExtraFieldInfo payload that can blow past tool
# output size limits on large scans.
SUMMARY_FIELDS = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID"]

SCAN_TIMEOUT_SECONDS = 300

# Coarse starting points for suggest_rule: per MITRE ATT&CK Enterprise
# tactic, a typical Windows/Sysmon log source and the event types worth
# looking at first. These are generic to the tactic, not the technique -
# real detection logic still requires looking at the technique's specific
# artifacts (command-line patterns, registry keys, API calls, etc.).
TACTIC_DETECTION_HINTS = {
    "reconnaissance": {
        "logsource": {"product": "windows", "category": "process_creation"},
        "signals": ["Sysmon/Security EventID 1/4688 (process creation) for recon commands (whoami, nltest, net, nslookup)"],
    },
    "resource-development": {
        "logsource": {"product": "windows", "category": "process_creation"},
        "signals": ["Usually off-host (infrastructure setup); on-host evidence is rare - focus on delivered payloads instead"],
    },
    "initial-access": {
        "logsource": {"product": "windows", "service": "security"},
        "signals": [
            "Security EventID 4624/4625 (logon success/failure) for the entry vector",
            "Sysmon EventID 1 (process creation) for the spawned payload; EventID 3 for the inbound connection",
        ],
    },
    "execution": {
        "logsource": {"product": "windows", "category": "process_creation"},
        "signals": [
            "Sysmon/Security EventID 1/4688 (process creation) for the interpreter/binary and its command line",
            "Sysmon EventID 7 (image load) if a script host or LOLBin is abused",
        ],
    },
    "persistence": {
        "logsource": {"product": "windows", "service": "security"},
        "signals": [
            "Sysmon EventID 12/13/14 (registry) for Run keys/services; Security EventID 4698/4702 (scheduled tasks)",
            "Security EventID 7045 (new service installed)",
        ],
    },
    "privilege-escalation": {
        "logsource": {"product": "windows", "service": "security"},
        "signals": [
            "Security EventID 4672 (special privileges assigned to new logon), 4673 (privileged service called)",
            "Sysmon EventID 1 (process creation) for token manipulation / UAC bypass tooling",
        ],
    },
    "defense-evasion": {
        "logsource": {"product": "windows", "category": "process_creation"},
        "signals": [
            "Sysmon EventID 1 (process creation) for obfuscated/renamed binaries; EventID 4 (Sysmon config change)",
            "Security EventID 4688/1102 (audit log cleared) or Windows Defender EventIDs for tampering",
        ],
    },
    "credential-access": {
        "logsource": {"product": "windows", "service": "security"},
        "signals": [
            "Security EventID 4624/4625 (logon), 4768/4769 (Kerberos TGT/TGS), 4662 (directory service access), 4776 (NTLM validation)",
            "Sysmon EventID 10 (ProcessAccess) if the technique targets LSASS or another credential store process",
        ],
    },
    "discovery": {
        "logsource": {"product": "windows", "category": "process_creation"},
        "signals": ["Sysmon/Security EventID 1/4688 (process creation) for enumeration commands and their arguments"],
    },
    "lateral-movement": {
        "logsource": {"product": "windows", "service": "security"},
        "signals": [
            "Security EventID 4624 (logon, esp. Type 3/10), 4648 (explicit credential logon), 5140/5145 (share/file access)",
            "Sysmon EventID 3 (network connection) for SMB/WinRM/WMI/RDP traffic",
        ],
    },
    "collection": {
        "logsource": {"product": "windows", "category": "file_event"},
        "signals": ["Sysmon EventID 11 (file create) for staged data; EventID 1 for archiving/collection tool execution"],
    },
    "command-and-control": {
        "logsource": {"product": "windows", "category": "network_connection"},
        "signals": ["Sysmon EventID 3 (network connection) and EventID 22 (DNS query) for beacon traffic"],
    },
    "exfiltration": {
        "logsource": {"product": "windows", "category": "network_connection"},
        "signals": ["Sysmon EventID 3 (network connection) for outbound transfer; EventID 11 (file create) for staged archives"],
    },
    "impact": {
        "logsource": {"product": "windows", "service": "security"},
        "signals": ["Security EventID 4657/4663 (object modified/deleted), 1102 (audit log cleared); Sysmon EventID 23 (file delete)"],
    },
}


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


def _normalize_tactic(tactic: str) -> str:
    """Normalize e.g. "Credential Access" or "credential_access" to the
    "credential-access" form used both in ATT&CK's kill_chain_phases data
    and in a Sigma rule's "attack.<tactic>" tags."""
    return re.sub(r"[\s_]+", "-", tactic.strip().lower())


def _technique_report(technique_id: str) -> dict:
    """Build a single technique's coverage report: our rule coverage
    (always computed live from rules/) plus ATT&CK metadata (name,
    description, tactics) from the local cache, if available."""
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
    return _technique_report(technique_id)


def _iter_playbooks():
    """Yield (path, parsed playbook) for every valid playbook in PLAYBOOKS_DIR."""
    for pb_path in sorted(PLAYBOOKS_DIR.glob("*.yml")):
        try:
            playbook = yaml.safe_load(pb_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(playbook, dict) and playbook.get("name"):
            yield pb_path, playbook


def _playbook_summary(playbook: dict, pb_path: Path, base_dir: Path) -> dict:
    description = playbook.get("description")
    return {
        "id": playbook.get("id", pb_path.stem),
        "name": playbook.get("name"),
        "severity": playbook.get("severity"),
        "description": description.strip().splitlines()[0] if description else None,
        "techniques": playbook.get("techniques") or [],
        "triggers": playbook.get("triggers") or [],
        "file": str(pb_path.relative_to(base_dir)),
    }


def _rule_technique_ids(rule: dict) -> set[str]:
    """Extract normalized ATT&CK technique IDs (e.g. "T1003.001") from a
    rule's "attack.tNNNN[.NNN]" tags."""
    ids = set()
    for tag in rule.get("tags") or []:
        tag = str(tag).lower()
        if not tag.startswith("attack."):
            continue
        candidate = tag[len("attack."):]
        if TECHNIQUE_ID_RE.fullmatch(candidate):
            ids.add("T" + candidate.upper().lstrip("T"))
    return ids


def _playbook_technique_ids(playbook: dict) -> set[str]:
    return {"T" + str(t).upper().lstrip("T") for t in (playbook.get("techniques") or [])}


def _find_playbooks_by_alert(alert_name: str) -> tuple[list[dict], str | None]:
    """Match an alert name (a rule title, a rule filename stem, or a bare
    keyword) to playbook(s). First tries each playbook's own "triggers"
    keyword list (substring match, either direction); if nothing matches
    that way, falls back to resolving alert_name against our curated
    rules/ by title/filename substring and matching on shared ATT&CK
    technique IDs - this lets a full Hayabusa scan_evtx RuleTitle resolve
    to a playbook even if it isn't listed verbatim in any "triggers" list.
    """
    needle = alert_name.lower().strip()
    playbooks = list(_iter_playbooks())

    direct = []
    for pb_path, playbook in playbooks:
        triggers = [str(t).lower() for t in (playbook.get("triggers") or [])]
        if any(t and (needle in t or t in needle) for t in triggers):
            direct.append(_playbook_summary(playbook, pb_path, PLAYBOOKS_DIR))
    if direct:
        return direct, "trigger_keyword"

    matching_technique_ids = set()
    for rule_path, rule in _iter_detection_rules():
        haystack = f"{rule.get('title', '')} {rule_path.stem}".lower()
        if needle in haystack:
            matching_technique_ids |= _rule_technique_ids(rule)
    if not matching_technique_ids:
        return [], None

    technique_matches = [
        _playbook_summary(playbook, pb_path, PLAYBOOKS_DIR)
        for pb_path, playbook in playbooks
        if matching_technique_ids & _playbook_technique_ids(playbook)
    ]
    return technique_matches, "technique_overlap" if technique_matches else None


@mcp.resource("detection://playbooks")
def list_playbooks() -> dict:
    """List all incident response playbooks in the knowledge base
    (playbooks/ directory)."""
    if not PLAYBOOKS_DIR.exists():
        return {"error": f"Playbooks directory not found at {PLAYBOOKS_DIR}"}

    playbooks = [_playbook_summary(playbook, pb_path, PLAYBOOKS_DIR) for pb_path, playbook in _iter_playbooks()]
    return {"count": len(playbooks), "playbooks": playbooks}


@mcp.resource("detection://playbooks/{playbook_name}")
def get_playbook(playbook_name: str) -> dict:
    """Get a specific incident response playbook's full content by name (the
    .yml filename in playbooks/, without the extension - use the "id" field
    from detection://playbooks)."""
    if not RULE_NAME_RE.fullmatch(playbook_name):
        return {"error": f"Invalid playbook name '{playbook_name}'"}

    pb_path = PLAYBOOKS_DIR / f"{playbook_name}.yml"
    if not pb_path.exists():
        return {"error": f"Playbook '{playbook_name}' not found in {PLAYBOOKS_DIR}"}

    try:
        raw = pb_path.read_text(encoding="utf-8")
        playbook = yaml.safe_load(raw)
    except (OSError, yaml.YAMLError) as exc:
        return {"error": f"Failed to read playbook '{playbook_name}': {exc}"}

    return {"name": playbook_name, "file": pb_path.name, "playbook": playbook, "raw": raw}


@mcp.resource("detection://playbooks/by-alert/{alert_name}")
def get_playbooks_by_alert(alert_name: str) -> dict:
    """Find incident response playbook(s) for a given alert. alert_name can
    be a short keyword (e.g. "DCSync"), or a full rule title as it appears
    in scan_evtx/get_hayabusa_rules output (e.g. "Active Directory
    Replication Rights Abuse (DCSync)") - matched first against each
    playbook's "triggers" list, then, if nothing matches, against ATT&CK
    technique overlap with our curated rules/."""
    if not PLAYBOOKS_DIR.exists():
        return {"error": f"Playbooks directory not found at {PLAYBOOKS_DIR}"}

    matches, match_type = _find_playbooks_by_alert(alert_name)
    return {
        "alert_name": alert_name,
        "match_type": match_type,
        "count": len(matches),
        "playbooks": matches,
    }


@mcp.tool()
def analyze_coverage(target: str) -> dict:
    """Analyze our Sigma rule detection coverage (rules/) for an ATT&CK
    technique ID or a whole tactic, using the cached ATT&CK technique data
    (mappings/attack_techniques.json) to identify gaps.

    target: either a technique ID, e.g. "T1003.001" or "1558.003"
        (case-insensitive, with or without the leading "T"), or a tactic
        name, e.g. "credential-access" or "Lateral Movement"
        (case-insensitive; spaces/underscores are treated as hyphens).

    For a technique ID, returns that technique's coverage: "covered" (a
    matching rule has graduated to status: stable), "partial" (matching
    rules exist but are all still experimental), or "gap" (no matching
    rules), plus ATT&CK metadata if the cache is available.

    For a tactic name, returns every technique MITRE assigns to that
    tactic, each classified covered/partial/gap the same way, with summary
    counts - run download_attack_data.py first if the cache is missing.
    """
    target = target.strip()
    if not target:
        return {"error": "target must not be empty"}

    if TECHNIQUE_ID_RE.fullmatch(target):
        return {"query_type": "technique", **_technique_report(target)}

    techniques = _load_attack_techniques()
    if not techniques:
        return {
            "error": (
                f"ATT&CK technique metadata not found at {ATTACK_TECHNIQUES_PATH}. "
                f"Run download_attack_data.py to fetch it, then retry."
            )
        }

    tactic = _normalize_tactic(target)
    matching = [t for t in techniques.values() if tactic in (t.get("tactics") or [])]
    if not matching:
        known_tactics = sorted(
            {phase for tech in techniques.values() for phase in (tech.get("tactics") or [])}
        )
        return {
            "error": f"No ATT&CK techniques found for tactic '{tactic}'.",
            "known_tactics": known_tactics,
        }

    covered, partial, gaps = [], [], []
    for tech in sorted(matching, key=lambda t: t["id"]):
        rules = _find_rules_by_technique(tech["id"])
        status = _assess_coverage(rules)
        entry = {
            "technique_id": tech["id"],
            "name": tech.get("name"),
            "is_subtechnique": tech.get("is_subtechnique", False),
        }
        if status == "gap":
            gaps.append(entry)
        else:
            entry["rules"] = [
                {"name": r["name"], "title": r["title"], "status": r["status"]} for r in rules
            ]
            (covered if status == "covered" else partial).append(entry)

    return {
        "query_type": "tactic",
        "tactic": tactic,
        "total_techniques": len(matching),
        "covered_count": len(covered),
        "partial_count": len(partial),
        "gap_count": len(gaps),
        "covered": covered,
        "partial": partial,
        "gaps": gaps,
    }


def _build_suggestion(technique_id: str, name: str | None, tactics: list[str]) -> dict:
    """Build a coarse detection starting point for a technique with no rule
    coverage yet, using TACTIC_DETECTION_HINTS. Not technique-specific logic -
    just where to start looking (log source, event types)."""
    known_tactics = [t for t in tactics if t in TACTIC_DETECTION_HINTS]
    if not known_tactics:
        return {
            "tactics_used": [],
            "suggested_logsource": {"product": "windows", "service": "security"},
            "suggested_signals": [
                "No cached ATT&CK tactic data for this technique - defaulting to the "
                "Windows Security log. Run download_attack_data.py for tailored hints, "
                "or check the technique's page on attack.mitre.org for its Data Sources."
            ],
            "guidance": (
                f"Identify the specific Windows or Sysmon event that captures "
                f"{name or technique_id} activity, then narrow the selection to field "
                f"values unique to this technique rather than the tactic in general."
            ),
        }

    signals = []
    for tactic in known_tactics:
        for signal in TACTIC_DETECTION_HINTS[tactic]["signals"]:
            if signal not in signals:
                signals.append(signal)

    return {
        "tactics_used": known_tactics,
        "suggested_logsource": TACTIC_DETECTION_HINTS[known_tactics[0]]["logsource"],
        "suggested_signals": signals,
        "guidance": (
            f"Identify the specific Windows or Sysmon event that captures "
            f"{name or technique_id} activity, then narrow the selection to field "
            f"values unique to this technique rather than the tactic in general."
        ),
    }


def _render_rule_template(
    technique_id: str,
    name: str | None,
    description: str | None,
    url: str | None,
    tactics: list[str],
    rule_id: str,
) -> str:
    """Render a starter Sigma rule as raw YAML text for a technique with no
    coverage. Hand-formatted (not built via yaml.dump) to match this repo's
    existing rules/*.yml style."""
    today = datetime.date.today().isoformat()
    display_name = name or technique_id

    known_tactics = [t for t in tactics if t in TACTIC_DETECTION_HINTS]
    tag_lines = "\n".join(f"    - attack.{t}" for t in known_tactics) or "    - attack.TODO_TACTIC"
    tag_lines += f"\n    - {_technique_tag(technique_id)}"

    logsource = (
        TACTIC_DETECTION_HINTS[known_tactics[0]]["logsource"]
        if known_tactics
        else {"product": "windows", "service": "security"}
    )
    logsource_lines = "\n".join(f"    {k}: {v}" for k, v in logsource.items())

    first_desc_line = description.strip().splitlines()[0] if description else None
    desc_body = first_desc_line or f"detect {display_name} ({technique_id}) activity"

    ref_lines = f"    - {url}" if url else f"    - https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"

    return f"""title: TODO - {display_name} Detection
id: {rule_id}
status: experimental
description: |
    TODO - this is a generated template, not a validated detection. Replace
    this with a real description once the selection logic below is filled
    in. Starting point: {desc_body}.
references:
{ref_lines}
author: detection-engineering-lab
date: {today}
modified: {today}
tags:
{tag_lines}
logsource:
{logsource_lines}
detection:
    selection:
        # TODO: replace with the real EventID/fields that capture this
        # technique - see the "suggestion" field from suggest_rule for a
        # starting log source and event types.
        EventID: 0
    condition: selection
falsepositives:
    - TODO
level: medium
"""


@mcp.tool()
def suggest_rule(technique_id: str, create_rule: bool = False, rule_name: str | None = None) -> dict:
    """Check whether an ATT&CK technique has rule coverage in rules/, and if
    it's a gap, suggest a detection starting point (and optionally write a
    starter rule template).

    technique_id: e.g. "T1110.003" (case-insensitive, with or without the
        leading "T").
    create_rule: if True and the technique is a genuine gap (no existing
        rules/ reference it at all), writes a starter Sigma template to
        rules/ with TODO placeholders for the real selection logic. Does
        nothing if the technique already has "partial" or "covered"
        coverage, to avoid creating redundant/conflicting rules - improve
        the existing rule(s) instead (see "existing_rules").
    rule_name: filename stem for the created template (letters, digits,
        underscore, hyphen only). If omitted, defaults to
        "template_t<id_with_underscores>", e.g. "template_t1110_003".
    """
    technique_id = technique_id.strip()
    if not TECHNIQUE_ID_RE.fullmatch(technique_id):
        return {"error": f"'{technique_id}' doesn't look like an ATT&CK technique ID (e.g. 'T1110.003')"}

    report = _technique_report(technique_id)
    normalized_id = report["technique_id"]

    result = {
        "technique_id": normalized_id,
        "coverage": report["coverage"],
        "existing_rules": report["rules"],
        "name": report.get("name"),
        "tactics": report.get("tactics"),
    }
    if report.get("note"):
        result["attack_data_note"] = report["note"]

    if report["coverage"] != "gap":
        result["suggestion"] = None
        result["template_created"] = False
        result["template_note"] = (
            f"'{normalized_id}' already has {report['coverage']} coverage from "
            f"{len(report['rules'])} rule(s) - see \"existing_rules\". No template created; "
            f"improve or promote an existing rule instead of adding a redundant one."
        )
        return result

    tactics = report.get("tactics") or []
    result["suggestion"] = _build_suggestion(normalized_id, report.get("name"), tactics)

    if not create_rule:
        result["template_created"] = False
        result["template_note"] = "Pass create_rule=True to write a starter rule template to rules/."
        return result

    if rule_name:
        if not RULE_NAME_RE.fullmatch(rule_name):
            return {"error": f"Invalid rule_name '{rule_name}'"}
        stem = rule_name
    else:
        stem = "template_t" + normalized_id[1:].replace(".", "_").lower()

    rule_path = DETECTION_RULES_DIR / f"{stem}.yml"
    if rule_path.exists():
        result["template_created"] = False
        result["template_note"] = f"'{rule_path.name}' already exists in {DETECTION_RULES_DIR}; not overwriting."
        return result

    rule_id = str(uuid.uuid4())
    template = _render_rule_template(
        normalized_id, report.get("name"), report.get("description"), report.get("url"), tactics, rule_id
    )
    DETECTION_RULES_DIR.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(template, encoding="utf-8")

    result["template_created"] = True
    result["template_path"] = str(rule_path.relative_to(PROJECT_ROOT))
    result["template_raw"] = template
    return result


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
