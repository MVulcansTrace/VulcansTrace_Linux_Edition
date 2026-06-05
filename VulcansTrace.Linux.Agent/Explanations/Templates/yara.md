## YARA-001

**What we found:** {{count}} YARA rule match(es) detected, starting with {{path}} (scan path: {{scanPath}}, target kind: {{targetKind}}, rule: {{ruleIdentifier}}).

**Matched targets:**
{{matchList}}

**Why this matters:** YARA matches indicate the file contains byte sequences, strings, or structural patterns associated with malware, packers, or attacker tooling. When the match is on a SUID/SGID binary, a running process executable, or a cron script, the risk is especially high because these are common persistence and privilege-escalation locations.

**How to verify:**
1. Confirm the matched file is still present: `ls -la {{path}}`
2. Inspect file type and hashes: `file {{path}}` and `sha256sum {{path}}`
3. Review the matching YARA rule definition in `~/.config/VulcansTrace/yara/` or the bundled rule set.
4. If the match is on a running process (PID {{processId}}), inspect it further: `cat /proc/{{processId}}/cmdline | tr '\0' ' '` and `ls -la /proc/{{processId}}/fd/`
5. For process hits, compare the display path (`{{resolvedPath}}`) with the scanned `/proc` path (`{{scanPath}}`) so deleted or replaced executables are not missed.

**Backup commands:**
1. Copy the file for offline analysis before removing it: `sudo cp {{path}} /var/quarantine/$(basename {{path}}).$(date +%s).bak`
2. Record file metadata: `stat {{path}} > /tmp/yara-match-{{ruleIdentifier}}.meta`

**Suggested next action:**
1. Treat the match as suspicious until proven otherwise. Do not execute the file.
2. Compare hashes against reputable sources (e.g., VirusTotal, NBD) before deletion.
3. If the file is not legitimate, remove it: `sudo rm {{path}}`
4. If the match is on a recurring cron script, check for related entries in `/etc/cron.d/`, `/etc/cron.daily/`, and user crontabs.
5. Review recent authentication and process logs for related compromise indicators.

**Rollback commands:**
1. Restore the file from a known-good backup if it was mistakenly removed.
2. Re-enable any cron entries only after confirming they are clean.

**Risk level:** HIGH

**Confidence / caveat:** High confidence for rule identifiers with low false-positive signatures — always verify against your environment baseline before deleting system binaries.

> These are suggestions only. Review commands before running them on your system.
