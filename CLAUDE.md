# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) (the Windows event log forensics/threat-hunting tool) for EVTX analysis, exposing it to Claude. In addition to Hayabusa scanning, the server provides a detection engineering knowledge base — browsable Sigma rules, ATT&CK technique mappings, detection coverage queries and gap-filling, and incident response playbooks.

### Goals

- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON
- Support filtering by severity level
- Expose a `get_hayabusa_rules` tool to list/search available detection rules
- Handle errors gracefully
- Expose Sigma rules as browsable resources
- Expose ATT&CK technique mappings
- Allow Claude to query detection coverage, and identify + fill gaps
- Expose incident response playbooks, resolvable from an alert name
- Combine with Hayabusa scanning from Module 3

### Stack

- Python with the `mcp` and `pyyaml` libraries
- Hayabusa CLI (installed locally)

### Structure

- `rules/` — Sigma detection rules (YAML)
- `mappings/` — ATT&CK technique to rule mappings
- `playbooks/` — incident response playbooks (YAML)
- `server.py` — MCP server with resources and tools

## Commands

```
pip install -r requirements.txt           # install dependencies (mcp, pyyaml)
python download_hayabusa.py               # fetch the Hayabusa binary + Sigma rules into ./hayabusa/
./hayabusa/hayabusa.exe update-rules       # refresh the ruleset (Windows; drop .exe elsewhere)
python download_attack_data.py            # fetch MITRE ATT&CK technique data into ./mappings/attack_techniques.json
python server.py                           # run the MCP server over stdio
```

## Architecture

- **`download_hayabusa.py`** — fetches the latest Hayabusa GitHub release for the current OS/arch (skipping the self-contained `-live-response` variant in favor of the standard build with an external `rules/` directory), extracts it to `./hayabusa/`, and copies the versioned binary to a stable `hayabusa.exe`/`hayabusa` name so other tooling doesn't need to track the release version.
- **`download_attack_data.py`** — fetches the MITRE ATT&CK Enterprise STIX bundle (`enterprise-attack.json`, ~40MB), extracts non-revoked/non-deprecated `attack-pattern` objects (technique `id`, `name`, `description`, `tactics`, `is_subtechnique`, `url`), and writes a compact lookup to `./mappings/attack_techniques.json` keyed by ATT&CK ID (e.g. `T1003.001`). This cache is gitignored and regenerated on demand rather than fetched live per-request, since the source bundle is too large to download on every resource read.
- **`rules/`** — our own curated Sigma detection rules (YAML), separate from the full upstream ruleset Hayabusa downloads into `./hayabusa/rules/`. Each rule is tagged with `attack.tNNNN[.NNN]` ATT&CK tags, which drive the `detection://` resources below.
- **`mappings/`** — generated/gitignored; holds `attack_techniques.json` from `download_attack_data.py`.
- **`playbooks/`** — our own curated incident response playbooks (YAML), one per alert family (`credential-theft`, `pass-the-hash`, `password-spraying`). Each declares `techniques` (ATT&CK IDs) and `triggers` (alert-name keywords), which drive the `detection://playbooks/*` resources below, plus `triage`/`containment`/`eradication`/`recovery` step lists.
- **`server.py`** — a `FastMCP` server exposing four tools and seven resources:
  - `scan_evtx(evtx_path, min_severity="informational", rule_filter=None, output_format="summary", max_results=None)`. It shells out to `hayabusa json-timeline -L` (JSONL output — the plain `-o` JSON format is a stream of pretty-printed objects, not valid JSON or true JSONL, so `-L` is required for reliable parsing), passes `min_severity` through as Hayabusa's `-m`/`--min-level` rule filter, and parses the resulting JSONL into a `detections` list. `rule_filter` is a case-insensitive substring match against each detection's `RuleTitle`, applied in Python after parsing since Hayabusa has no native rule-title filter (only `--include-tag`/`--include-category`). `output_format="summary"` (the default) strips detections down to `Timestamp`/`RuleTitle`/`Level`/`Computer`/`Channel`/`EventID`/`RecordID` to avoid blowing past tool output size limits on large scans; `"full"` keeps the complete `Details`/`ExtraFieldInfo` payload. `max_results` caps the returned list; the response reports `total_count` (pre-cap) and `truncated`. Hayabusa exits `0` even on failure (e.g. a bad input path), so errors are detected by scanning stderr for `[ERROR]` lines rather than trusting the return code. All failure modes (missing path, invalid severity/output_format/max_results, missing Hayabusa binary, timeout, scan error) return `{"error": "..."}` instead of raising.
  - `get_hayabusa_rules(keyword=None, max_results=100)`. Hayabusa has no built-in rule-listing command, so this walks `./hayabusa/rules/**/*.yml` directly and parses each Sigma rule with `pyyaml`. When `keyword` is given, a raw-text substring prefilter runs before the YAML parse (keyword search is ~1-2s; a full unfiltered listing takes several seconds longer since every rule file must be parsed). Matches are checked against `title`/`description`/`tags`/`id`; results are summarized (`id`, `title`, `level`, `status`, first line of `description`, `logsource`, `tags`, relative `file` path) and capped by `max_results`, with `total_count`/`truncated` reported the same way as `scan_evtx`.
  - `analyze_coverage(target)` — coverage report for a single ATT&CK technique ID or an entire tactic name (`target` disambiguated by `TECHNIQUE_ID_RE`). A technique query returns the same shape as `detection://attack/techniques/{technique_id}` below (built on the shared `_technique_report()` helper). A tactic query (e.g. `"credential-access"`, normalized via `_normalize_tactic`) enumerates every technique MITRE assigns to that tactic from the ATT&CK cache and classifies each `covered`/`partial`/`gap`, with summary counts — this is how gaps across a tactic are found without checking techniques one at a time.
  - `suggest_rule(technique_id, create_rule=False, rule_name=None)` — checks a single technique's coverage and, if it's a genuine gap, suggests a starting log source/event types from a small built-in `TACTIC_DETECTION_HINTS` table (coarse, tactic-level, not technique-specific logic) and, with `create_rule=True`, writes a starter Sigma template into `rules/` with a real UUID, ATT&CK-derived tags, and a placeholder `EventID: 0` selection marked `# TODO`. Refuses to create a template (even with `create_rule=True`) if the technique already has `partial`/`covered` coverage, to avoid redundant rules.
  - `detection://rules` — lists every rule in `./rules/` (our curated set, not Hayabusa's bundled ruleset), summarized the same way as `get_hayabusa_rules`.
  - `detection://rules/{rule_name}` — returns one rule's full parsed content plus raw YAML, looked up by filename stem (e.g. `lsass_access_sysmon`). `rule_name` is validated against `[A-Za-z0-9_-]+` before being used to build a path, since resource URI template params can't contain `/` but could otherwise contain arbitrary characters.
  - `detection://rules/by-technique/{technique_id}` — lists rules whose `tags` include `attack.<technique_id>`, matched case-insensitively after normalizing input like `T1003.001`/`t1003.001`/`1003.001` to `attack.t1003.001`.
  - `detection://attack/techniques/{technique_id}` — combines ATT&CK metadata (name/description/tactics/url, from the `download_attack_data.py` cache) with our own rule coverage for that technique (reusing the by-technique lookup above). Coverage is `"gap"` (no matching rules), `"partial"` (matching rules exist but none have `status: stable`), or `"covered"` (at least one matching rule is `stable`). Coverage is always computed live from `rules/`, independent of whether the ATT&CK cache exists; if the cache is missing or the ID isn't found in it, `name`/`description` come back `null` with an explanatory `note` rather than an error, so the resource stays useful for coverage alone.
  - `detection://playbooks` — lists every playbook in `./playbooks/`, summarized (`id`, `name`, `severity`, first line of `description`, `techniques`, `triggers`, `file`).
  - `detection://playbooks/{playbook_name}` — returns one playbook's full parsed content plus raw YAML, looked up by filename stem (e.g. `credential-theft`). Same `[A-Za-z0-9_-]+` validation as `detection://rules/{rule_name}`.
  - `detection://playbooks/by-alert/{alert_name}` — resolves an alert name (a short keyword or a full `RuleTitle` from `scan_evtx`/`get_hayabusa_rules`) to playbook(s) in two passes: first a case-insensitive substring match (either direction) against each playbook's `triggers` list; if that finds nothing, a fallback resolves `alert_name` against our curated `rules/` by title/filename substring and matches on shared ATT&CK technique IDs between that rule and each playbook's `techniques` list (`_find_playbooks_by_alert`). The response's `match_type` (`"trigger_keyword"`, `"technique_overlap"`, or `null`) reports which pass (if any) matched.
- **`README.md`** — user-facing setup/usage instructions, including the Claude Desktop `mcpServers` config snippet for wiring this server in.
