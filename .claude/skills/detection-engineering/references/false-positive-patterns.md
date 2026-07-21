# False-Positive Patterns

`falsepositives:` must name the actual legitimate tool, process, or workflow
that can trigger the rule (standard #3) - never generic filler like
`["Unknown"]`, `["None"]`, or `["TODO"]`. This is a catalog of common,
real FP sources by category, to check against before deciding a list is
complete. Not exhaustive - if an investigation turns up a false positive
this list didn't anticipate, add it here *and* to the rule's
`falsepositives:` (see `investigations/` for the workflow this feeds).

## Credential access / LSASS

- EDR and antivirus agents that inspect `lsass.exe` as part of normal
  behavioral monitoring (e.g. `MsMpEng.exe`, third-party EDR sensors).
- Windows Error Reporting (`werfault.exe`) handling a crash of `lsass.exe`.
- Backup/imaging agents that enumerate process memory as part of a
  system-state or forensic backup job.
- Sysinternals tools (`procdump.exe`, `procexp.exe`) used legitimately by
  admins for troubleshooting, not credential theft - hard to distinguish
  from malicious use by image name alone, so pair with parent-process or
  command-line context where possible.

## Kerberos (Kerberoasting / AS-REP roasting)

- Legacy applications or service accounts still configured without AES
  support, forcing RC4 ticket requests that look identical to a
  Kerberoasting scan.
- Vulnerability scanners and pentest tools running authorized assessments
  in the same environment (coordinate with the pentest calendar/environment
  notes rather than suppressing blindly).
- Service accounts with `Do not require Kerberos preauthentication` set
  intentionally for a legacy integration, which will always look like
  AS-REP roasting traffic.

## Pass-the-hash / lateral movement

- Legitimate remote administration via PsExec, SCCM, or similar
  management tooling, which produces NTLM logons that pattern-match
  pass-the-hash indicators.
- Service accounts performing scheduled cross-host tasks (backup jobs,
  monitoring agents) that authenticate the same way across many hosts in a
  short window - looks like lateral movement, is a maintenance window.

## Password spraying

- Helpdesk-driven bulk password resets, where many accounts fail/succeed
  logon in a tight window right after a reset campaign.
- SSO/federation retry behavior - a client silently retrying stale cached
  credentials against multiple accounts (e.g. shared kiosk or service
  machine) after a domain password policy change.
- Legitimate automated testing or QA harnesses that iterate test accounts
  on a schedule.

## Registry hive dumps (SAM/SYSTEM/SECURITY)

- Backup and imaging software (Windows Server Backup, third-party backup
  agents) that legitimately reads these hives as part of a full system
  backup.
- Domain controller promotion/demotion and other legitimate `ntdsutil`/
  system-state operations performed by AD administrators.

## Azure / cloud identity

- Applications performing ROPC as part of automated integration testing
  or a legacy application that genuinely cannot be migrated to a modern
  auth flow (track these explicitly - they should be a known, inventoried
  list, not an unbounded excuse).
- Conditional Access / MFA exclusion accounts used for break-glass or
  service-to-service auth, which will trip alerts tuned for interactive
  user sign-in anomalies.
- Migration/hybrid-identity sync accounts (e.g. Azure AD Connect) that
  authenticate with patterns atypical for a human user.

## General patterns worth checking on every new rule

- **Scheduled tasks / cron-like automation** - anything that repeats on a
  fixed interval from a fixed host tends to look suspicious in isolation but
  is trivially explained by a task name/schedule lookup.
- **Backup and monitoring agents** - broad filesystem/process/registry
  access is their normal job; they show up across almost every credential-
  access and file-access category above.
- **EDR/AV/vulnerability-scanner self-activity** - security tooling itself
  frequently performs the same actions the rule is trying to catch.
- **Non-production environments** (lab, QA, load-testing) - behavior that
  would be alarming in production (bulk auth attempts, credential reuse
  across many accounts) may be expected there; confirm the rule's intended
  scope against `environment/` before assuming it applies everywhere.
- **Legacy applications frozen on old protocols** - can't be modernized
  short-term, so they'll keep tripping technique-based rules (RC4 Kerberos,
  ROPC, NTLM) indefinitely; track them as known exceptions rather than
  re-discovering the same FP every time.
