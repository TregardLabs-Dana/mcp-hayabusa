# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) (the Windows event log forensics/threat-hunting tool) for EVTX analysis, exposing it to Claude.

### Goals

- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON
- Support filtering by severity level
- Handle errors gracefully

### Stack

- Python with the `mcp` library
- Hayabusa CLI (installed locally)

## Commands

```
pip install -r requirements.txt           # install dependencies (mcp)
python download_hayabusa.py               # fetch the Hayabusa binary + Sigma rules into ./hayabusa/
./hayabusa/hayabusa.exe update-rules       # refresh the ruleset (Windows; drop .exe elsewhere)
python server.py                           # run the MCP server over stdio
```

## Architecture

- **`download_hayabusa.py`** — fetches the latest Hayabusa GitHub release for the current OS/arch (skipping the self-contained `-live-response` variant in favor of the standard build with an external `rules/` directory), extracts it to `./hayabusa/`, and copies the versioned binary to a stable `hayabusa.exe`/`hayabusa` name so other tooling doesn't need to track the release version.
- **`server.py`** — a `FastMCP` server exposing one tool, `scan_evtx(evtx_path, min_severity="informational")`. It shells out to `hayabusa json-timeline -L` (JSONL output — the plain `-o` JSON format is a stream of pretty-printed objects, not valid JSON or true JSONL, so `-L` is required for reliable parsing), passes `min_severity` through as Hayabusa's `-m`/`--min-level` rule filter, and parses the resulting JSONL into a `detections` list. Hayabusa exits `0` even on failure (e.g. a bad input path), so errors are detected by scanning stderr for `[ERROR]` lines rather than trusting the return code. All failure modes (missing path, invalid severity, missing Hayabusa binary, timeout, scan error) return `{"error": "..."}` instead of raising.
- **`README.md`** — user-facing setup/usage instructions, including the Claude Desktop `mcpServers` config snippet for wiring this server in.
