# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) (the Windows event log forensics/threat-hunting tool) for EVTX analysis, exposing it to Claude.

### Goals

- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON
- Support filtering by severity level
- Expose a `get_hayabusa_rules` tool to list/search available detection rules
- Handle errors gracefully

### Stack

- Python with the `mcp` and `pyyaml` libraries
- Hayabusa CLI (installed locally)

## Commands

```
pip install -r requirements.txt           # install dependencies (mcp, pyyaml)
python download_hayabusa.py               # fetch the Hayabusa binary + Sigma rules into ./hayabusa/
./hayabusa/hayabusa.exe update-rules       # refresh the ruleset (Windows; drop .exe elsewhere)
python server.py                           # run the MCP server over stdio
```

## Architecture

- **`download_hayabusa.py`** — fetches the latest Hayabusa GitHub release for the current OS/arch (skipping the self-contained `-live-response` variant in favor of the standard build with an external `rules/` directory), extracts it to `./hayabusa/`, and copies the versioned binary to a stable `hayabusa.exe`/`hayabusa` name so other tooling doesn't need to track the release version.
- **`server.py`** — a `FastMCP` server exposing two tools:
  - `scan_evtx(evtx_path, min_severity="informational", rule_filter=None, output_format="summary", max_results=None)`. It shells out to `hayabusa json-timeline -L` (JSONL output — the plain `-o` JSON format is a stream of pretty-printed objects, not valid JSON or true JSONL, so `-L` is required for reliable parsing), passes `min_severity` through as Hayabusa's `-m`/`--min-level` rule filter, and parses the resulting JSONL into a `detections` list. `rule_filter` is a case-insensitive substring match against each detection's `RuleTitle`, applied in Python after parsing since Hayabusa has no native rule-title filter (only `--include-tag`/`--include-category`). `output_format="summary"` (the default) strips detections down to `Timestamp`/`RuleTitle`/`Level`/`Computer`/`Channel`/`EventID`/`RecordID` to avoid blowing past tool output size limits on large scans; `"full"` keeps the complete `Details`/`ExtraFieldInfo` payload. `max_results` caps the returned list; the response reports `total_count` (pre-cap) and `truncated`. Hayabusa exits `0` even on failure (e.g. a bad input path), so errors are detected by scanning stderr for `[ERROR]` lines rather than trusting the return code. All failure modes (missing path, invalid severity/output_format/max_results, missing Hayabusa binary, timeout, scan error) return `{"error": "..."}` instead of raising.
  - `get_hayabusa_rules(keyword=None, max_results=100)`. Hayabusa has no built-in rule-listing command, so this walks `./hayabusa/rules/**/*.yml` directly and parses each Sigma rule with `pyyaml`. When `keyword` is given, a raw-text substring prefilter runs before the YAML parse (keyword search is ~1-2s; a full unfiltered listing takes several seconds longer since every rule file must be parsed). Matches are checked against `title`/`description`/`tags`/`id`; results are summarized (`id`, `title`, `level`, `status`, first line of `description`, `logsource`, `tags`, relative `file` path) and capped by `max_results`, with `total_count`/`truncated` reported the same way as `scan_evtx`.
- **`README.md`** — user-facing setup/usage instructions, including the Claude Desktop `mcpServers` config snippet for wiring this server in.
