"""Validate Sigma detection rules against this repo's detection-engineering
rule standards (see ../SKILL.md). Exits non-zero if any rule fails.

Usage:
    python validate_rule.py <rule.yml | directory> [...]
    python validate_rule.py                          # defaults to rules/
"""

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
    ("ATT&CK technique mapping", check_technique_mapping),
    ("Severity + justification", check_severity),
    ("False positives documented", check_falsepositives),
    ("Test cases", check_test_cases),
]


def validate_file(rule_path: Path) -> bool:
    try:
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        print(f"{rule_path}: FAIL - could not parse YAML: {exc}")
        return False

    if not isinstance(rule, dict):
        print(f"{rule_path}: FAIL - not a YAML mapping")
        return False

    ok = True
    print(f"\n{rule_path}")
    for name, fn in CHECKS:
        passed, detail = fn(rule)
        ok = ok and passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}")

    passed, detail = check_filename(rule_path)
    ok = ok and passed
    print(f"  [{'PASS' if passed else 'FAIL'}] Filename convention: {detail}")

    return ok


def main() -> None:
    targets = sys.argv[1:] or [str(DEFAULT_TARGET)]
    paths = []
    for target in targets:
        path = Path(target)
        if path.is_dir():
            paths.extend(sorted(path.glob("*.yml")))
        elif path.is_file():
            paths.append(path)
        else:
            print(f"warning: '{target}' not found", file=sys.stderr)

    if not paths:
        print("No rule files found.", file=sys.stderr)
        sys.exit(1)

    all_ok = True
    for path in paths:
        all_ok = validate_file(path) and all_ok

    print()
    print("All rules PASS" if all_ok else "Some rules FAILED - see above")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
