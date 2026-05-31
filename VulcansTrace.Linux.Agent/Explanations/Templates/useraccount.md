## USER-001

**What we found:** Account {{username}} has UID 0 in addition to root.

**Why this matters:** UID 0 grants unrestricted superuser access. Multiple UID-0 accounts break accountability, hide privilege escalation, and bypass normal auditing. Attackers often create secondary UID-0 accounts as backdoors.

**How to verify:**
1. List UID-0 accounts: `awk -F: '($3 == 0) {print $1}' /etc/passwd`

**Backup commands:**
1. Back up passwd: `sudo cp /etc/passwd /etc/passwd.bak.$(date +%s)`

**Suggested next action:**
1. Change the UID to a unique non-zero value: `sudo usermod -u NEWUID {{username}}`
2. Or remove the account if it is unauthorized: `sudo userdel {{username}}`

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/passwd.bak.* /etc/passwd`

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence — direct passwd read.

> These are suggestions only. Review commands before running them on your system.

## USER-002

**What we found:** {{username}} has {{reason}}.

**Why this matters:** Empty password hashes allow login without credentials. Locked hashes on interactive accounts indicate dormant accounts that may be reactivated by an attacker or administrator without oversight.

**How to verify:**
1. Check the shadow entry: `sudo getent shadow {{username}}`

**Backup commands:**
1. Back up shadow: `sudo cp /etc/shadow /etc/shadow.bak.$(date +%s)`

**Suggested next action:**
1. Set a strong password: `sudo passwd {{username}}`
2. Or lock the account if it should not be used: `sudo passwd -l {{username}}`
3. Consider removing unused accounts entirely.

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/shadow.bak.* /etc/shadow`

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence — direct shadow read.

> These are suggestions only. Review commands before running them on your system.

## USER-003

**What we found:** Password aging setting {{setting}} is {{value}} (expected {{expected}}).

**Why this matters:** Weak or absent password aging allows credentials to remain static for long periods, increasing the window of exposure from leaks, phishing, or brute-force success.

**How to verify:**
1. Check login.defs: `grep -E 'PASS_(MAX|MIN|WARN)_DAYS' /etc/login.defs`
2. Check per-user values: `sudo chage -l {{username}}`

**Backup commands:**
1. Back up login.defs: `sudo cp /etc/login.defs /etc/login.defs.bak.$(date +%s)`

**Suggested next action:**
1. Edit `/etc/login.defs` and set:
   - `PASS_MAX_DAYS 90`
   - `PASS_MIN_DAYS 1`
   - `PASS_WARN_AGE 7`
2. Apply to existing users: `sudo chage -M 90 -m 1 -W 7 USERNAME`

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/login.defs.bak.* /etc/login.defs`

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence — direct file read.

> These are suggestions only. Review commands before running them on your system.

## USER-004

**What we found:** No PAM password complexity module ({{expectedModules}}) was found in the password stack.

**Why this matters:** Without complexity enforcement users routinely choose short, dictionary-based passwords that fall to automated attacks in seconds.

**How to verify:**
1. Inspect PAM password config:
   - Debian/Ubuntu: `cat /etc/pam.d/common-password`
   - RHEL/CentOS: `cat /etc/pam.d/system-auth` and `cat /etc/pam.d/password-auth`

**Backup commands:**
1. Back up PAM configs: `sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.bak.$(date +%s)`

**Suggested next action:**
1. Install libpam-pwquality (or pam_cracklib) and add a line like:
   `password requisite pam_pwquality.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1`
2. For RHEL, edit `/etc/security/pwquality.conf` accordingly.

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/pam.d/common-password.bak.* /etc/pam.d/common-password`

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence. Some custom PAM stacks may use alternative modules not detected here.

> These are suggestions only. Review commands before running them on your system.

## USER-005

**What we found:** Interactive account {{username}} is {{reason}}.

**Why this matters:** Inactive or expired interactive accounts remain in the authentication database. If re-enabled or exploited through misconfiguration, they provide a foothold for lateral movement or privilege escalation.

**How to verify:**
1. Check account status: `sudo passwd -S {{username}}`
2. Check expiry: `sudo chage -l {{username}}`

**Backup commands:**
1. Back up passwd and shadow before changes.

**Suggested next action:**
1. Remove the account if no longer needed: `sudo userdel -r {{username}}`
2. Or keep it locked and document the exception.

**Rollback commands:**
1. Restore from backups if removed in error.

**Risk level:** LOW

**Confidence / caveat:** High confidence. Some service accounts may legitimately appear inactive if they are used only by automated tools.

> These are suggestions only. Review commands before running them on your system.

## USER-006

**What we found:** UID {{uid}} is shared by: {{usernames}}.

**Why this matters:** Duplicate UIDs violate the one-to-one mapping between users and identifiers. File ownership becomes ambiguous, audit logs conflate identities, and access control decisions may apply to the wrong principal.

**How to verify:**
1. List duplicates: `cut -d: -f3 /etc/passwd | sort | uniq -d`
2. Map to names: `awk -F: '{print $3, $1}' /etc/passwd | sort -n | uniq -D`

**Backup commands:**
1. Back up passwd: `sudo cp /etc/passwd /etc/passwd.bak.$(date +%s)`

**Suggested next action:**
1. Assign unique UIDs: `sudo usermod -u NEWUID USERNAME`
2. Fix file ownership with: `sudo find / -uid OLDUID -exec chown NEWUID {} +`

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/passwd.bak.* /etc/passwd`

**Risk level:** HIGH

**Confidence / caveat:** High confidence — direct passwd read.

> These are suggestions only. Review commands before running them on your system.

## USER-007

**What we found:** {{username}} home directory {{homeDirectory}} does not exist.

**Why this matters:** Missing home directories break user sessions, mail delivery, and application expectations. They may also indicate incomplete account deprovisioning.

**How to verify:**
1. Check the directory: `ls -ld {{homeDirectory}}`
2. Check passwd: `getent passwd {{username}}`

**Backup commands:**
1. Back up passwd: `sudo cp /etc/passwd /etc/passwd.bak.$(date +%s)`

**Suggested next action:**
1. Create the directory: `sudo mkdir -p {{homeDirectory}} && sudo chown {{username}}:{{username}} {{homeDirectory}} && sudo chmod 700 {{homeDirectory}}`
2. Or update the home path in `/etc/passwd` if it has changed.
3. If the account is unused, remove it: `sudo userdel -r {{username}}`

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/passwd.bak.* /etc/passwd`

**Risk level:** LOW

**Confidence / caveat:** High confidence. NFS or automounted home directories may legitimately not be present during the scan.

> These are suggestions only. Review commands before running them on your system.
