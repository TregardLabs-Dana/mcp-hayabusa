"""Validate Sigma detection rules against this repo's detection-engineering
rule standards (see ../SKILL.md). Exits non-zero if any rule fails.

Usage:
    python validate_rule.py <rule.yml | directory> [...]
    python validate_rule.py                          # defaults to rules/
    python validate_rule.py --json <rule.yml | directory> [...]
"""

import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_TARGET = REPO_ROOT / "rules"

TECHNIQUE_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
VALID_LEVELS = {"low", "medium", "high", "critical"}
FILENAME_RE = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*$")
GENERIC_FP_PHRASES = {"unknown", "none", "n/a", "na", "todo", "tbd", ""}


def check_technique_mapping(rule: dict) -> tuple[bool, str]:
    tags = [str(t) for t in (rule.get("tags") or [])]
    matches = [t for t in tags if TECHNIQUE_TAG_RE.match(t)]
    if matches:
        return True, f"OK: {', '.join(matches)}"
    return False, "Missing an 'attack.tXXXX[.XXX]' technique tag in tags:"


def check_severity(rule: dict) -> tuple[bool, str]:
    level = rule.get("level")
    if level not in VALID_LEVELS:
        return False, f"level '{level}' must be one of {sorted(VALID_LEVELS)}"
    justification = str(rule.get("severity_justification") or "").strip()
    if not justification:
        return False, "Missing non-empty 'severity_justification:' explaining the chosen level"
    return True, f"OK: level={level}, justification present"


def check_falsepositives(rule: dict) -> tuple[bool, str]:
    fps = rule.get("falsepositives") or []
    if not isinstance(fps, list) or not fps:
        return False, "Missing non-empty 'falsepositives:' list"
    meaningful = [fp for fp in fps if str(fp).strip().lower() not in GENERIC_FP_PHRASES]
    if not meaningful:
        return False, "falsepositives: entries are all generic placeholders (Unknown/None/TODO/...)"
    return True, f"OK: {len(meaningful)} documented condition(s)"


def check_test_cases(rule: dict) -> tuple[bool, str]:
    cases = rule.get("test_cases") or []
    if not isinstance(cases, list) or not cases:
        return False, "Missing 'test_cases:' - at least one is required"
    for i, case in enumerate(cases):
        if not isinstance(case, dict):
            return False, f"test_cases[{i}] is not a mapping"
        if "should_match" not in case:
            return False, f"test_cases[{i}] missing 'should_match: true/false'"
        if not case.get("log"):
            return False, f"test_cases[{i}] missing 'log:' sample event"
    positive = [c for c in cases if c.get("should_match") is True]
    if not positive:
        return False, "test_cases: none has 'should_match: true' - need at least one true-positive example"
    return True, f"OK: {len(cases)} test case(s), {len(positive)} true-positive"


def check_filename(rule_path: Path) -> tuple[bool, str]:
    stem = rule_path.stem
    if not FILENAME_RE.match(stem):
        return False, f"filename '{stem}' must be lowercase_with_underscores"
    return True, f"OK: {stem}"


CHECKS = [
    ("technique_mapping", check_technique_mapping),
    ("severity", check_severity),
    ("falsepositives", check_falsepositives),
    ("test_cases", check_test_cases),
]

CHECK_LABELS = {
    "technique_mapping": "ATT&CK technique mapping",
    "severity": "Severity + justification",
    "falsepositives": "False positives documented",
    "test_cases": "Test cases",
    "filename_convention": "Filename convention",
}


def collect_results(rule_path: Path) -> dict:
    try:
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return {
            "file": str(rule_path),
            "passed": False,
            "checks": {},
            "issues": [f"could not parse YAML: {exc}"],
        }

    if not isinstance(rule, dict):
        return {
            "file": str(rule_path),
            "passed": False,
            "checks": {},
            "issues": ["not a YAML mapping"],
        }

    checks = {}
    issues = []
    ok = True
    for name, fn in CHECKS:
        passed, detail = fn(rule)
        checks[name] = {"passed": passed, "detail": detail}
        ok = ok and passed
        if not passed:
            issues.append(f"{name}: {detail}")

    passed, detail = check_filename(rule_path)
    checks["filename_convention"] = {"passed": passed, "detail": detail}
    ok = ok and passed
    if not passed:
        issues.append(f"filename_convention: {detail}")

    return {"file": str(rule_path), "passed": ok, "checks": checks, "issues": issues}


def print_results(result: dict) -> None:
    print(f"\n{result['file']}")
    for key, info in result["checks"].items():
        label = CHECK_LABELS.get(key, key)
        print(f"  [{'PASS' if info['passed'] else 'FAIL'}] {label}: {info['detail']}")


def resolve_paths(targets: list[str]) -> list[Path]:
    paths = []
    for target in targets:
        path = Path(target)
        if path.is_dir():
            paths.extend(sorted(path.glob("*.yml")))
        elif path.is_file():
            paths.append(path)
        else:
            print(f"warning: '{target}' not found", file=sys.stderr)
    return paths


def main() -> None:
    args = sys.argv[1:]
    as_json = "--json" in args
    targets = [a for a in args if a != "--json"] or [str(DEFAULT_TARGET)]

    paths = resolve_paths(targets)
    if not paths:
        if as_json:
            print(json.dumps({"error": "No rule files found.", "results": []}))
        else:
            print("No rule files found.", file=sys.stderr)
        sys.exit(1)

    results = [collect_results(path) for path in paths]
    all_ok = all(r["passed"] for r in results)

    if as_json:
        print(json.dumps({"all_passed": all_ok, "results": results}, indent=2))
    else:
        for result in results:
            print_results(result)
        print()
        print("All rules PASS" if all_ok else "Some rules FAILED - see above")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
