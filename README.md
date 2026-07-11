# mcp-hayabusa

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows event log) analysis, exposing `scan_evtx` and `get_hayabusa_rules` tools to Claude.

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Download the Hayabusa binary and Sigma rules into `./hayabusa/`:
   ```
   python download_hayabusa.py
   ```
   This fetches the latest release for your OS/architecture and extracts it to `./hayabusa/` (binary at `./hayabusa/hayabusa.exe` on Windows or `./hayabusa/hayabusa` elsewhere, plus `rules/` and `rules/config/`).

3. Keep the ruleset current (recommended before each scanning session):
   ```
   ./hayabusa/hayabusa.exe update-rules      # Windows
   ./hayabusa/hayabusa update-rules          # Linux/macOS
   ```

## Running the server

```
python server.py
```

This starts the MCP server over stdio. Point an MCP client at it, e.g. in Claude Desktop's config:

```json
{
  "mcpServers": {
    "hayabusa": {
      "command": "python",
      "args": ["C:\\path\\to\\mcp-hayabusa\\server.py"]
    }
  }
}
```

## Tool: `scan_evtx`

Scans an EVTX file (or a directory of EVTX files) with Hayabusa and returns detections as structured JSON.

**Parameters:**
- `evtx_path` (string, required) — path to a `.evtx` file or a directory containing them
- `min_severity` (string, optional, default `"informational"`) — minimum severity to include: `informational`, `low`, `medium`, `high`, `critical`
- `rule_filter` (string, optional) — case-insensitive substring match against each detection's rule title (e.g. `"lateral"` or `"mimikatz"`); only matching detections are returned. Hayabusa has no native rule-title filter, so this is applied after the scan.
- `output_format` (string, optional, default `"summary"`) — `"summary"` returns condensed detections (`Timestamp`, `RuleTitle`, `Level`, `Computer`, `Channel`, `EventID`, `RecordID`); `"full"` includes the complete `Details`/`ExtraFieldInfo` payload for each detection
- `max_results` (integer, optional) — caps the number of detections returned, applied after `rule_filter`

**Returns:**
```json
{
  "evtx_path": "...",
  "min_severity": "...",
  "rule_filter": "...",
  "output_format": "...",
  "total_count": 68,
  "count": 42,
  "truncated": false,
  "detections": [ { "Timestamp": "...", "RuleTitle": "...", "Level": "...", "...": "..." } ]
}
```
`total_count` is the number of matching detections before `max_results` is applied; `count` is the number actually returned; `truncated` is `true` if `max_results` cut off results.

On failure (missing file, missing Hayabusa binary, invalid `min_severity`/`output_format`/`max_results`, scan timeout, or a Hayabusa scan error), it returns `{"error": "..."}` instead of raising.

## Tool: `get_hayabusa_rules`

Lists available Hayabusa/Sigma detection rules from `./hayabusa/rules/`, optionally filtered by keyword. Useful for seeing what detections exist before scanning, or for finding a good `rule_filter` value for `scan_evtx`. Hayabusa has no built-in rule-listing command, so this reads and parses the rule YAML files directly.

**Parameters:**
- `keyword` (string, optional) — case-insensitive substring matched against each rule's title, description, tags, and id. If omitted, all rules are listed (subject to `max_results`)
- `max_results` (integer, optional, default `100`) — caps the number of rules returned

**Returns:**
```json
{
  "keyword": "...",
  "total_count": 66,
  "count": 66,
  "truncated": false,
  "rules": [
    {
      "id": "...",
      "title": "...",
      "level": "...",
      "status": "...",
      "description": "...",
      "logsource": { "product": "windows", "service": "..." },
      "tags": ["attack.lateral-movement", "..."],
      "file": "hayabusa\\builtin\\System\\Sys_7045_Med_LateralMovement-PSEXEC.yml"
    }
  ]
}
```
`total_count` is the number of matching rules before `max_results` is applied; `count` is the number actually returned; `truncated` is `true` if `max_results` cut off results.

A keyword search checks a raw-text prefilter before parsing each rule's YAML, so it typically runs in ~1-2 seconds. Listing all ~5,000 rules with no keyword takes several seconds longer since every rule file must be parsed.

On failure (missing rules directory or invalid `max_results`), it returns `{"error": "..."}` instead of raising.

## Requirements

- Python with the `mcp` and `pyyaml` libraries (see `requirements.txt`)
- The Hayabusa CLI, installed via `download_hayabusa.py`
