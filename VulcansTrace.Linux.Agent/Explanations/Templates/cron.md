## CRON-001

**What we found:** Cron entry in {{sourceFile}} runs as {{runAsUser}} and contains suspicious pattern "{{pattern}}" in command: {{command}}.

**Why this matters:** Cron is a favorite persistence mechanism for attackers. Suspicious patterns like network downloaders (wget, curl), interactive shells (bash -i), temporary paths (/tmp/), reverse-shell techniques (/dev/tcp/), and encoded payloads (base64, python -c) in scheduled jobs indicate potential compromise or risky automation.

**How to verify:**
1. Review the cron entry: `sudo cat {{sourceFile}}`
2. Inspect the command or script being executed.
3. Check file integrity and recent modifications.

**Backup commands:**
1. Back up the crontab: `sudo cp {{sourceFile}} {{sourceFile}}.bak.$(date +%s)`

**Suggested next action:**
1. Remove or disable the suspicious entry.
2. Investigate how it was added (audit logs, login history).
3. Scan for additional persistence mechanisms.

**Rollback commands:**
1. Restore the backup: `sudo cp {{sourceFile}}.bak.* {{sourceFile}}`

**Risk level:** HIGH

**Confidence / caveat:** High confidence — direct pattern match on cron content. Review before acting; some legitimate monitoring scripts may use curl or wget.

> These are suggestions only. Review commands before running them on your system.

## CRON-002

**What we found:** Cron script {{path}} has permissions {{mode}} and is owned by {{owner}}:{{group}}.

**Why this matters:** Scripts executed by cron often run with elevated privileges. If the script is world-writable, any local user can modify it to inject arbitrary commands, achieving instant privilege escalation when cron next executes it.

**How to verify:**
1. Check permissions: `ls -l {{path}}`
2. Check ownership: `stat -c '%a %U %G' {{path}}`

**Backup commands:**
1. Document current permissions: `stat -c '%a %U %G %n' {{path}} > /tmp/cron-script-perms.bak`

**Suggested next action:**
1. Remove world-write: `sudo chmod o-w {{path}}`
2. Set strict ownership: `sudo chmod 755 {{path}} && sudo chown root:root {{path}}`

**Rollback commands:**
1. Re-apply documented permissions manually if needed.

**Risk level:** HIGH

**Confidence / caveat:** High confidence — direct metadata read.

> These are suggestions only. Review commands before running them on your system.

## CRON-003

**What we found:** System cron entry in {{sourceFile}} runs as root but references a non-root user path in command: {{command}}.

**Why this matters:** System-wide cron jobs running as root should operate on system resources. Jobs that reference user home directories or user-specific tools should be placed in that user's own crontab. Root jobs pointing to user paths may indicate privilege misuse, misconfiguration, or attacker persistence.

**How to verify:**
1. Review the entry: `sudo cat {{sourceFile}}`
2. Verify the referenced path and its ownership.
3. Check if the job is legitimate system administration.

**Backup commands:**
1. Back up the crontab: `sudo cp {{sourceFile}} {{sourceFile}}.bak.$(date +%s)`

**Suggested next action:**
1. If the job is user-specific, move it to the user's crontab: `sudo crontab -u USER -e`
2. If it must run as root, ensure the path is owned by root and not writable by others.

**Rollback commands:**
1. Restore the backup: `sudo cp {{sourceFile}}.bak.* {{sourceFile}}`

**Risk level:** MEDIUM

**Confidence / caveat:** Medium-High confidence. Some legitimate root jobs may reference user directories for backups or maintenance. Review context before acting.

> These are suggestions only. Review commands before running them on your system.
