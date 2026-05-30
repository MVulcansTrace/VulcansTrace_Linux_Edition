## FILE-001

**What we found:** /etc/shadow has permissions {{mode}} and is owned by {{owner}}:{{group}}.

**Why this matters:** The shadow file stores password hashes. If it is readable by non-root users, attackers can exfiltrate hashes for offline cracking. Group-writable permissions allow password hash tampering. CIS benchmarks require 640 (or 600) with root ownership.

**How to verify:**
1. Check permissions: `ls -l /etc/shadow`
2. Check ownership: `stat -c '%a %U %G' /etc/shadow`

**Backup commands:**
1. Back up before changing: `sudo cp /etc/shadow /etc/shadow.bak.$(date +%s)`

**Suggested next action:**
1. Restore secure permissions: `sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow`

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/shadow.bak.* /etc/shadow`

**Risk level:** HIGH

**Confidence / caveat:** High confidence — this is a direct metadata read.

> These are suggestions only. Review commands before running them on your system.

## FILE-002

**What we found:** /etc/passwd has permissions {{mode}} and is owned by {{owner}}:{{group}}.

**Why this matters:** /etc/passwd maps usernames to UIDs and home directories. Writable by non-root users enables account creation, UID manipulation, and privilege escalation. It should be world-readable (644) but strictly root-owned.

**How to verify:**
1. Check permissions: `ls -l /etc/passwd`

**Backup commands:**
1. Back up before changing: `sudo cp /etc/passwd /etc/passwd.bak.$(date +%s)`

**Suggested next action:**
1. Restore secure permissions: `sudo chmod 644 /etc/passwd && sudo chown root:root /etc/passwd`

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/passwd.bak.* /etc/passwd`

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence.

> These are suggestions only. Review commands before running them on your system.

## FILE-003

**What we found:** SSH host private key {{path}} has permissions {{mode}} and is owned by {{owner}}:{{group}}.

**Why this matters:** Host private keys prove the server's identity during SSH handshakes. If readable by other users, an attacker can impersonate the server (MITM) or decrypt captured SSH sessions. CIS requires 600 and root ownership.

**How to verify:**
1. List keys: `ls -l /etc/ssh/ssh_host_*_key`

**Backup commands:**
1. Back up the key before changing: `sudo cp {{path}} {{path}}.bak.$(date +%s)`

**Suggested next action:**
1. Tighten permissions: `sudo chmod 600 {{path}} && sudo chown root:root {{path}}`

**Rollback commands:**
1. Restore the backup: `sudo cp {{path}}.bak.* {{path}}`

**Risk level:** HIGH

**Confidence / caveat:** High confidence.

> These are suggestions only. Review commands before running them on your system.

## FILE-004

**What we found:** {{path}} has permissions {{mode}} and is owned by {{owner}}:{{group}}.

**Why this matters:** The root SSH directory and authorized_keys file control password-less root access. World-readable permissions leak valid public keys; writable permissions allow attackers to inject their own keys and gain root instantly.

**How to verify:**
1. Check directory: `ls -ld /root/.ssh`
2. Check file: `ls -l /root/.ssh/authorized_keys`

**Backup commands:**
1. Back up before changing: `sudo cp -r /root/.ssh /root/.ssh.bak.$(date +%s)`

**Suggested next action:**
1. Fix directory: `sudo chmod 700 /root/.ssh && sudo chown root:root /root/.ssh`
2. Fix authorized_keys: `sudo chmod 600 /root/.ssh/authorized_keys && sudo chown root:root /root/.ssh/authorized_keys`

**Rollback commands:**
1. Restore the backup: `sudo cp -r /root/.ssh.bak.* /root/.ssh`

**Risk level:** HIGH

**Confidence / caveat:** High confidence.

> These are suggestions only. Review commands before running them on your system.

## FILE-005

**What we found:** Cron directory {{path}} has permissions {{mode}} and is owned by {{owner}}:{{group}}.

**Why this matters:** World-writable cron directories allow any local user to drop scheduled jobs. These jobs run with elevated privileges, creating an easy privilege-escalation and persistence vector.

**How to verify:**
1. Check cron dirs: `ls -ld /etc/cron.* /var/spool/cron*`

**Backup commands:**
1. Document current permissions: `stat -c '%a %n' /etc/cron.* /var/spool/cron* > /tmp/cron-perms.bak`

**Suggested next action:**
1. Remove world-write: `sudo chmod o-w {{path}}`
2. Or set strict permissions: `sudo chmod 755 {{path}} && sudo chown root:root {{path}}`

**Rollback commands:**
1. Re-apply documented permissions manually if needed.

**Risk level:** HIGH

**Confidence / caveat:** High confidence.

> These are suggestions only. Review commands before running them on your system.

## FILE-006

**What we found:** /etc/crontab has permissions {{mode}} and is owned by {{owner}}:{{group}}.

**Why this matters:** The system crontab schedules privileged tasks. Writable by non-root users allows arbitrary command execution as root. It should be readable but not writable by non-owners.

**How to verify:**
1. Check permissions: `ls -l /etc/crontab`

**Backup commands:**
1. Back up before changing: `sudo cp /etc/crontab /etc/crontab.bak.$(date +%s)`

**Suggested next action:**
1. Restore secure permissions: `sudo chmod 644 /etc/crontab && sudo chown root:root /etc/crontab`

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/crontab.bak.* /etc/crontab`

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence.

> These are suggestions only. Review commands before running them on your system.

## FILE-007

**What we found:** User SSH path {{path}} has permissions {{mode}} and is owned by {{owner}}:{{group}}.

**Why this matters:** User SSH private keys and authorized_keys files grant password-less access to individual accounts. World-readable permissions leak valid keys; writable permissions allow attackers to inject their own keys and pivot laterally across the system.

**How to verify:**
1. Check user SSH dirs: `ls -ld /home/*/.ssh`
2. Check authorized_keys: `ls -l /home/*/.ssh/authorized_keys`

**Backup commands:**
1. Back up a user's SSH config: `sudo cp -r /home/USER/.ssh /home/USER/.ssh.bak.$(date +%s)`

**Suggested next action:**
1. Fix directory: `sudo chmod 700 /home/USER/.ssh && sudo chown USER:USER /home/USER/.ssh`
2. Fix authorized_keys: `sudo chmod 600 /home/USER/.ssh/authorized_keys && sudo chown USER:USER /home/USER/.ssh/authorized_keys`

**Rollback commands:**
1. Restore the backup: `sudo cp -r /home/USER/.ssh.bak.* /home/USER/.ssh`

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence. Some shared-home or NFS configurations may have legitimate exceptions.

> These are suggestions only. Review commands before running them on your system.
