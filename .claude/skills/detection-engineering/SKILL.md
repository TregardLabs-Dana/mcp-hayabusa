---
name: detection-engineering
description: Enforces this repo's detection rule standards for the curated Sigma rules under rules/ - ATT&CK technique mapping (attack.tXXXX tags), a severity level with justification, documented false-positive conditions, at least one test case, and lowercase_with_underscores rule names. Use when writing or creating Sigma rules, reviewing detection rules, discussing detection coverage, or working with YAML detection files.
tools: Read, Write, Edit, Grep, Glob, Bash
---

# Detection Engineering Standards

Five non-negotiable standards for every rule under `rules/` in this repo (our curated knowledge base — separate from Hayabusa's bundled ruleset in `hayabusa/rules/`, which these standards don't apply to). Apply them whenever writing a new rule, reviewing an existing one, or discussing what the ruleset does/doesn't cover.

## The five standards

### 1. ATT&CK technique mapping

`tags:` must include at least one entry matching `attack.tXXXX` or `attack.tXXXX.XXX` (case-insensitive), e.g. `attack.t1003.001`. This is what powers `detection://rules/by-technique/{technique_id}`, `analyze_coverage`, and `suggest_rule` in `server.py` — a rule without this tag is invisible to every coverage query.

```yaml
tags:
    - attack.credential-access   # tactic tag - encouraged but not required
    - attack.t1003.006           # technique tag - REQUIRED
```

### 2. Severity with justification

`level:` must be exactly one of `low`, `medium`, `high`, `critical` (no `informational`, no custom values — this is stricter than Sigma's own spec and than `scan_evtx`'s `min_severity` filter, which does accept `informational`; that value is fine for filtering scan output but not as a rule's own assigned severity).

Alongside it, add a `severity_justification:` field — a sentence or two on *why* that level, not just what the rule detects (the `description:` field already covers that). Justify in terms of blast radius / what the attacker gains if the technique succeeds unnoticed, not just "this seems bad":

```yaml
level: critical
severity_justification: >
    Successful DCSync yields domain-wide credential material including
    krbtgt, enabling Golden Ticket forgery - full domain compromise, not
    just one account.
```

`critical`/`high` generally means credential material or domain-wide access is at stake (see the existing DCSync, Kerberoasting, AS-REP Roasting, LSASS rules); `medium` for confirmed-but-contained techniques with a real false-positive rate (see the Pass-the-Hash and password-spraying rules); `low` for weak/noisy signals not otherwise covered here.

### 3. Documented false-positive conditions

`falsepositives:` must be a non-empty list of *specific* conditions, not generic filler. `["Unknown"]`, `["None"]`, `["TODO"]` don't count - name the actual legitimate tool, process, or workflow that can trigger this pattern:

```yaml
falsepositives:
    - Legitimate administration tools and EDR/AV agents that inspect lsass.exe
    - Windows Error Reporting handling a crash of lsass.exe
```

If investigating a detection turns up a false positive that the existing `falsepositives:` list didn't anticipate, that's a signal to both file it as a lesson learned (see `investigations/`) and add it here.

### 4. At least one test case

Add a `test_cases:` list — not part of the official Sigma spec, but a convention for this repo (parsers here and in Hayabusa ignore unrecognized top-level keys, so it's safe to include). Each entry needs `description`, `should_match` (bool), and `log` (a representative sample of the relevant fields from the real event):

```yaml
test_cases:
    - description: Kerberoasting RC4 ticket request for a service account
      should_match: true
      log:
          EventID: 4769
          TicketEncryptionType: "0x17"
          ServiceName: svc-sql
    - description: Normal AES ticket request
      should_match: false
      log:
          EventID: 4769
          TicketEncryptionType: "0x12"
          ServiceName: svc-sql
```

At minimum one `should_match: true` case is required (proves the rule actually fires on the thing it claims to detect); a `should_match: false` case demonstrating a filter/exclusion is strongly encouraged whenever the rule has a `filter_*` block, but not separately mandatory.

### 5. Rule naming convention

Filenames (the `.yml` stem, which becomes the `name` field in `detection://rules` and the identifier used everywhere else) must be `lowercase_with_underscores` - no hyphens, no camelCase, no spaces: `dcsync_4662.yml`, not `DCSync-4662.yml` or `dcSyncDetection.yml`.

## Automated validation

`scripts/validate_rule.py` checks all five standards mechanically (technique mapping, severity value + justification presence, false-positive list quality, test case structure, filename pattern) and prints PASS/FAIL per rule per check:

```bash
python .claude/skills/detection-engineering/scripts/validate_rule.py           # validates everything in rules/
python .claude/skills/detection-engineering/scripts/validate_rule.py rules/dcsync_4662.yml   # validates one rule
python .claude/skills/detection-engineering/scripts/validate_rule.py --json rules/dcsync_4662.yml   # same checks, JSON output for tooling
```

Exits non-zero if anything fails. Run this after writing or editing a rule, before considering the work done.

## Reference material

- `references/example-rules/lsass_memory_access.yml` — a fully compliant rule hitting all five standards at once; use as a starting template for a new rule.
- `references/severity-guide.md` — the rubric behind standard #2: when a technique is `low`/`medium`/`high`/`critical`, and what `severity_justification:` should actually argue.
- `references/false-positive-patterns.md` — a catalog of common, real FP sources by category, to check against before calling a rule's `falsepositives:` list complete.

**Known gap:** as of this skill's creation, none of the 8 existing rules in `rules/` have `severity_justification:` or `test_cases:` yet (both are new requirements introduced by this skill, not retrofitted). Don't treat that as acceptable for *new* rules - and if asked to touch an existing rule for an unrelated reason, it's worth backfilling those two fields on the file you're already editing.

## When this applies

- **Writing/creating a new rule**: build it to satisfy all five from the start, then run the validator before calling it done.
- **Reviewing a rule** (yours or someone else's): run the validator and walk through each FAIL with the specific fix, not just "add more fields."
- **Discussing detection coverage** (`analyze_coverage`, `suggest_rule`, `detection://attack/techniques/{id}`): remember that `coverage: "covered"` only reflects `status: stable` + a technique tag - it says nothing about whether that rule meets these five standards. A rule can be `covered` and still be missing `severity_justification:`/`test_cases:`.
- **Working with any YAML file under `rules/`**: these standards apply; they don't apply to `hayabusa/rules/` (the upstream bundled ruleset, which we don't maintain) or to `playbooks/`/`environment/`/`investigations/` (different schemas, different purpose).
