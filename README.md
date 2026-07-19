# mcp-hayabusa

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows event log) analysis, exposing `scan_evtx` and `get_hayabusa_rules` tools to Claude. It also provides a small detection engineering knowledge base — a curated set of Sigma rules under `rules/`, browsable as `detection://` MCP resources, cross-referenced against MITRE ATT&CK technique data to report coverage.

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

4. (Optional, for the `detection://attack/techniques/{technique_id}` resource) Download MITRE ATT&CK technique data into `./mappings/attack_techniques.json`:
   ```
   python download_attack_data.py
   ```
   This fetches the MITRE ATT&CK Enterprise STIX dataset and caches technique name/description/tactics locally. Without it, coverage lookups still work but technique name/description come back `null`.

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

## Resources: `detection://...`

These read our own curated Sigma rules in `./rules/` — a small, hand-picked set covering things like LSASS credential access, Kerberoasting, DCSync, and Pass-the-Hash — as opposed to `get_hayabusa_rules`, which lists Hayabusa's full bundled ruleset.

### `detection://rules`

Lists every rule in `./rules/`.

```json
{
  "count": 6,
  "rules": [
    {
      "name": "lsass_access_sysmon",
      "id": "c81db55e-5f41-49ab-b5ef-b5241d67e3d8",
      "title": "Suspicious Process Access to LSASS Memory",
      "level": "high",
      "status": "stable",
      "description": "Detects a process opening a handle to lsass.exe with an access mask commonly...",
      "logsource": { "category": "process_access", "product": "windows" },
      "tags": ["attack.credential-access", "attack.t1003.001", "attack.s0002"],
      "file": "lsass_access_sysmon.yml"
    }
  ]
}
```

### `detection://rules/{rule_name}`

Returns one rule's full parsed content plus its raw YAML. `rule_name` is the filename stem (the `name` field from `detection://rules`), e.g. `detection://rules/kerberoasting_4769`.

```json
{
  "name": "kerberoasting_4769",
  "file": "kerberoasting_4769.yml",
  "rule": { "title": "...", "id": "...", "detection": { "...": "..." } },
  "raw": "title: Kerberoasting - Suspicious Service Ticket Request...\n..."
}
```

Returns `{"error": "..."}` for an unknown or invalid rule name.

### `detection://rules/by-technique/{technique_id}`

Lists rules tagged with a given ATT&CK technique ID via `attack.tNNNN[.NNN]` Sigma tags. `technique_id` is case-insensitive and works with or without the leading `T` (`T1003.001`, `t1003.001`, `1003.001` are equivalent).

```json
{
  "technique_id": "T1003.001",
  "count": 2,
  "rules": [ { "name": "lsass_access_sysmon", "...": "..." }, { "name": "lsass_dump_comsvcs", "...": "..." } ]
}
```

### `detection://attack/techniques/{technique_id}`

Combines MITRE ATT&CK technique metadata with our rule coverage for that technique. Technique name/description/tactics come from the local cache built by `download_attack_data.py`; rule coverage is always computed live from `./rules/`, independent of whether that cache exists.

```json
{
  "technique_id": "T1003.001",
  "coverage": "covered",
  "rules": [ { "name": "lsass_access_sysmon", "...": "..." }, { "name": "lsass_dump_comsvcs", "...": "..." } ],
  "name": "OS Credential Dumping: LSASS Memory",
  "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS)...",
  "tactics": ["credential-access"],
  "url": "https://attack.mitre.org/techniques/T1003/001"
}
```

`coverage` is one of:
- `"covered"` — at least one matching rule has `status: stable`
- `"partial"` — matching rules exist, but all are still `experimental`/unstable
- `"gap"` — no rules reference this technique at all

If the ATT&CK cache hasn't been downloaded, or the technique ID isn't found in it, `name`/`description`/`tactics`/`url` come back `null` and a `note` field explains why — `coverage`/`rules` are still populated either way.

## Requirements

- Python with the `mcp` and `pyyaml` libraries (see `requirements.txt`)
- The Hayabusa CLI, installed via `download_hayabusa.py`
- (Optional) MITRE ATT&CK technique data, installed via `download_attack_data.py`, for `detection://attack/techniques/{technique_id}` to return technique name/description/tactics
