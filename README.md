# mcp-hayabusa

An MCP server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for EVTX (Windows event log) analysis, exposing `scan_evtx` and `get_hayabusa_rules` tools to Claude. It also provides a small detection engineering knowledge base — a curated set of Sigma rules under `rules/`, browsable as `detection://` MCP resources and queryable via `analyze_coverage`, cross-referenced against MITRE ATT&CK technique data to report coverage — plus `suggest_rule` to turn an identified gap into a starter rule template, and a set of incident response playbooks under `playbooks/`, browsable via `detection://playbooks` and resolvable from an alert name via `detection://playbooks/by-alert/{alert_name}`.

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
  "count": 8,
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

### `detection://playbooks`

Lists all incident response playbooks in `./playbooks/` — a small curated set covering the alert families our `./rules/` currently detect (credential theft, pass-the-hash, password spraying).

```json
{
  "count": 3,
  "playbooks": [
    {
      "id": "credential-theft",
      "name": "Credential Theft Response",
      "severity": "critical",
      "description": "Response procedure for detections indicating credential material was...",
      "techniques": ["T1003.001", "T1003.006", "T1218.011", "T1558.003", "T1558.004"],
      "triggers": ["LSASS", "DCSync", "Kerberoast", "AS-REP", "comsvcs", "..."],
      "file": "credential-theft.yml"
    }
  ]
}
```

### `detection://playbooks/{playbook_name}`

Returns one playbook's full parsed content plus its raw YAML. `playbook_name` is the filename stem (the `id`/`file` from `detection://playbooks`), e.g. `detection://playbooks/pass-the-hash`. Each playbook has `triage`/`containment`/`eradication`/`recovery` phases, each a list of concrete steps.

```json
{
  "name": "pass-the-hash",
  "file": "pass-the-hash.yml",
  "playbook": {
    "id": "pass-the-hash",
    "name": "Pass-the-Hash Lateral Movement Response",
    "severity": "high",
    "techniques": ["T1550.002", "T1021.002"],
    "phases": {
      "triage": ["Identify the account, source workstation/IP, and target host from the logon event (4624 Type 3, AuthenticationPackageName NTLM).", "..."],
      "containment": ["..."],
      "eradication": ["..."],
      "recovery": ["..."]
    },
    "references": ["https://attack.mitre.org/techniques/T1550/002/"]
  },
  "raw": "id: pass-the-hash\nname: Pass-the-Hash Lateral Movement Response\n..."
}
```

Returns `{"error": "..."}` for an unknown or invalid playbook name.

### `detection://playbooks/by-alert/{alert_name}`

Finds the playbook(s) for a given alert. `alert_name` can be a short keyword (`"DCSync"`) or a full rule title as it appears in `scan_evtx`/`get_hayabusa_rules` output (`"Active Directory Replication Rights Abuse (DCSync)"`). Matching happens in two passes:

1. **Trigger keyword** — case-insensitive substring match (either direction) against each playbook's `triggers` list.
2. **Technique overlap** (fallback, only tried if step 1 finds nothing) — resolves `alert_name` against our curated `rules/` by title/filename substring, then matches on shared ATT&CK technique IDs with each playbook's `techniques` list. This lets an alert title that isn't in any `triggers` list still resolve correctly, as long as it maps to one of our curated rules.

```json
{
  "alert_name": "DCSync",
  "match_type": "trigger_keyword",
  "count": 1,
  "playbooks": [ { "id": "credential-theft", "...": "..." } ]
}
```

`match_type` is `"trigger_keyword"`, `"technique_overlap"`, or `null` if nothing matched either way (`playbooks` is then `[]`).

## Tool: `analyze_coverage`

Analyzes our `./rules/` coverage for either a single ATT&CK technique or an entire tactic, using the ATT&CK cache to know which techniques exist. For a technique ID this returns the same shape as `detection://attack/techniques/{technique_id}` (it's built on the same helper). For a tactic name it walks every technique MITRE assigns to that tactic and classifies each `covered`/`partial`/`gap`, so gaps in the ruleset are visible without checking techniques one at a time.

**Parameters:**
- `target` (string, required) — either a technique ID (`T1003.001`, `t1558.003`, `1003.006` are equivalent) or a tactic name (`credential-access`, `Lateral Movement`, `lateral_movement` are equivalent — matched case-insensitively, spaces/underscores treated as hyphens)

**Returns (technique query):**
```json
{
  "query_type": "technique",
  "technique_id": "T1003.006",
  "coverage": "covered",
  "rules": [ { "name": "dcsync_4662", "...": "..." } ],
  "name": "DCSync",
  "description": "...",
  "tactics": ["credential-access"],
  "url": "https://attack.mitre.org/techniques/T1003/006"
}
```

**Returns (tactic query):**
```json
{
  "query_type": "tactic",
  "tactic": "credential-access",
  "total_techniques": 67,
  "covered_count": 3,
  "partial_count": 0,
  "gap_count": 64,
  "covered": [
    { "technique_id": "T1003.001", "name": "LSASS Memory", "is_subtechnique": true,
      "rules": [ { "name": "lsass_access_sysmon", "title": "...", "status": "stable" } ] }
  ],
  "partial": [],
  "gaps": [
    { "technique_id": "T1552.004", "name": "Private Keys", "is_subtechnique": true }
  ]
}
```

Requires the ATT&CK cache from `download_attack_data.py` — without it, a technique query still returns `coverage`/`rules` (with `name`/`description` `null`, same as the resource), but a tactic query returns `{"error": "..."}` since it has no way to enumerate that tactic's techniques. An unrecognized tactic name returns `{"error": "...", "known_tactics": [...]}` listing the valid tactic names.

## Tool: `suggest_rule`

Checks a single ATT&CK technique's coverage (same lookup as `analyze_coverage`/`detection://attack/techniques/{technique_id}`) and, if it's a genuine gap, suggests where to start looking and can write a starter Sigma template to `./rules/`.

**Parameters:**
- `technique_id` (string, required) — e.g. `T1110.003` (case-insensitive, with or without the leading `T`)
- `create_rule` (boolean, optional, default `false`) — if `true` and the technique is a gap, writes a starter `.yml` template to `./rules/`
- `rule_name` (string, optional) — filename stem for the created template. Defaults to `template_t<id_with_underscores>`, e.g. `template_t1110_003`

**Returns (gap, no creation):**
```json
{
  "technique_id": "T1552.004",
  "coverage": "gap",
  "existing_rules": [],
  "name": "Private Keys",
  "tactics": ["credential-access"],
  "suggestion": {
    "tactics_used": ["credential-access"],
    "suggested_logsource": { "product": "windows", "service": "security" },
    "suggested_signals": [
      "Security EventID 4624/4625 (logon), 4768/4769 (Kerberos TGT/TGS), 4662 (directory service access), 4776 (NTLM validation)",
      "Sysmon EventID 10 (ProcessAccess) if the technique targets LSASS or another credential store process"
    ],
    "guidance": "Identify the specific Windows or Sysmon event that captures Private Keys activity, then narrow the selection to field values unique to this technique rather than the tactic in general."
  },
  "template_created": false,
  "template_note": "Pass create_rule=True to write a starter rule template to rules/."
}
```

The `suggestion` is a coarse, tactic-level starting point (which log source and event types to look at first) drawn from a small built-in table (`TACTIC_DETECTION_HINTS` in `server.py`) covering all 14 MITRE Enterprise tactics — it is not technique-specific detection logic, since that requires knowing the technique's actual artifacts (specific command lines, registry keys, API calls, etc.), which isn't something this server can derive automatically.

With `create_rule=true`, the response additionally includes `"template_created": true`, `"template_path"`, and the generated YAML as `"template_raw"`. The template has a real `id` (freshly generated UUID), `status: experimental`, ATT&CK-derived `tags`/`references`, and a suggested `logsource`, but its `detection:` block is a placeholder (`EventID: 0`) marked `# TODO` — it's meant to be hand-edited, not scanned as-is.

If the technique already has `partial` or `covered` coverage, `suggestion` is `null` and no template is created (even with `create_rule=true`) — the response points at the `existing_rules` to improve instead, so gap-filling doesn't create redundant or conflicting rules for a technique that already has one. Coverage is re-derived live each call, so once a suggested template (or a hand-written rule) exists, a later `suggest_rule`/`analyze_coverage` call for the same technique reports `partial` instead of `gap`.

## Requirements

- Python with the `mcp` and `pyyaml` libraries (see `requirements.txt`)
- The Hayabusa CLI, installed via `download_hayabusa.py`
- (Optional) MITRE ATT&CK technique data, installed via `download_attack_data.py`, for `detection://attack/techniques/{technique_id}` to return technique name/description/tactics
