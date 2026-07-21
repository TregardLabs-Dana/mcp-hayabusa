# Severity Guide

How to pick `level:` for a rule in `rules/`, and what `severity_justification:`
should actually argue. The four allowed values are `low`, `medium`, `high`,
`critical` (see `SKILL.md` standard #2) - no `informational`, no custom tiers.

The question `severity_justification:` must answer is **not** "how bad does
this look" but **"what does the attacker gain if this succeeds unnoticed"**.
Justify in terms of blast radius: how many accounts/hosts are exposed, whether
the credential/access obtained is reusable, and whether it's a stepping stone
to something bigger (lateral movement, domain compromise) or a contained,
single-account event.

## critical

Reserve for techniques that yield **domain-wide** compromise or material that
lets an attacker mint new trust anywhere in the environment, not just on one
host or account.

- Domain controller replication abuse (DCSync) - the technique itself hands
  over `krbtgt` and every domain credential in one request, enabling Golden
  Ticket forgery.
- Anything that dumps `NTDS.dit` or the domain's `SYSTEM`/`SECURITY` hives
  wholesale, rather than one machine's local secrets.

Ask: *if this succeeds, can the attacker impersonate anyone in the domain
afterward, indefinitely, without needing to touch this host again?* If yes,
critical.

## high

Techniques that yield credential material or access broad enough to move
laterally or compromise multiple accounts from a single host, but stop short
of domain-wide forgery in one step.

- LSASS memory access (T1003.001) - every logged-on account's secrets on
  *that host*, often including cached domain admin credentials on a shared
  or jump host.
- Kerberoasting / AS-REP roasting - an offline-crackable credential for a
  service or user account, obtainable at scale across many accounts in one
  pass.
- SAM/SYSTEM/SECURITY registry hive dumps of a single host - local account
  hashes and LSA secrets, a plausible lateral-movement pivot.

Ask: *does this hand the attacker something reusable against more than one
account or system, even if it's not the whole domain?* If yes, high.

## medium

Techniques that are confirmed and real but contained: a single account, a
single session, or a flow that's legitimate-but-risky rather than inherently
malicious, and where the ruleset already has a documented, non-trivial
false-positive rate.

- Pass-the-hash - real lateral movement, but scoped to whatever access that
  one compromised hash grants.
- Password spraying - account compromise risk, but the signal is
  probabilistic/statistical and shares a boundary with normal
  helpdesk-reset or SSO retry traffic.
- ROPC authentication flow - not proof of compromise on its own; the risk is
  that a compromised or malicious application ends up holding a reusable
  plaintext password instead of a scoped token, which is a *should-be-reviewed*
  condition, not a confirmed breach signal.

Ask: *is this a confirmed technique whose damage is scoped to one account or
session, or a legitimate-but-discouraged pattern worth a human look?* If yes,
medium.

## low

Weak or noisy signals: enumeration/recon that doesn't itself grant access,
or telemetry that's only useful as corroborating context for another alert.
Nothing currently in `rules/` is `low` - if you're about to add something here,
double check it isn't actually `medium` in disguise (e.g. "just recon" that
also incidentally returns credential material belongs at `medium` or higher).

## Choosing between two adjacent levels

When a technique sits on a boundary, weight these in order:

1. **Reusability** - a hash, ticket, or plaintext password that works again
   later outranks a one-time access event.
2. **Scope** - one account vs. every account on a host vs. every account in
   the domain.
3. **Confirmation vs. probability** - a technique that's unambiguous when it
   fires (LSASS access with a credential-dumping mask) can sit a tier above a
   technique that's inherently statistical (password spraying), even if the
   underlying goal is similar.
4. **Existing FP rate** - if `falsepositives:` is genuinely long and common
   (see `false-positive-patterns.md`), that's a pull toward `medium` even when
   the worst-case impact looks high, because the rule will be tuned/suppressed
   in practice and shouldn't page on every legitimate hit.

## What NOT to write in severity_justification

- Restating the description ("detects X technique") - that belongs in
  `description:`, not here.
- "This seems dangerous" / "this is bad" with no blast-radius reasoning.
- Justifying by tool reputation alone ("Mimikatz is used by APTs") instead of
  by what the technique yields.
