## SSH-001

**What we found:** PermitRootLogin is set to {{value}}.

**Why this matters:** Allowing direct root login via SSH is one of the highest-risk configurations. If an attacker guesses or brute-forces the root password, they gain immediate unrestricted access. Even key-based root login increases blast radius if the key is compromised.

**How to verify:**
1. Check the current setting: `grep -i '^PermitRootLogin' /etc/ssh/sshd_config`
2. Or run: `sshd -T | grep -i permitrootlogin`

**Preconditions:**
- Ensure you have a non-root user with sudo privileges before disabling root login.
- Test the non-root login from a separate session.

**Backup commands:**
1. Back up sshd_config: `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)`

**Suggested next action:**
1. Edit `/etc/ssh/sshd_config` and set `PermitRootLogin no` or `PermitRootLogin prohibit-password`.
2. Restart SSH: `sudo systemctl restart sshd` (or `sudo service ssh restart`).

**Rollback commands:**
1. Restore the backup: `sudo cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config`
2. Restart SSH to apply.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence — this is a direct configuration read. Some distributions manage sshd_config via automation; apply changes through the same channel if applicable.

> These are suggestions only. Review commands before running them on your system.

## SSH-002

**What we found:** PasswordAuthentication is set to {{value}}.

**Why this matters:** Passwords can be guessed, brute-forced, or leaked. Key-based authentication is cryptographically stronger and not vulnerable to dictionary attacks. Disabling password auth forces attackers to compromise a private key, which is significantly harder.

**How to verify:**
1. Check the current setting: `grep -i '^PasswordAuthentication' /etc/ssh/sshd_config`
2. Or run: `sshd -T | grep -i passwordauthentication`

**Preconditions:**
- You have already configured and tested key-based login for all users.
- You have an alternative access method (console/IPMI) if keys fail.

**Backup commands:**
1. Back up sshd_config: `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)`

**Suggested next action:**
1. Edit `/etc/ssh/sshd_config` and set `PasswordAuthentication no`.
2. Restart SSH: `sudo systemctl restart sshd`

**Rollback commands:**
1. Restore the backup and restart SSH.

**Risk level:** HIGH

**Confidence / caveat:** High confidence. If you rely on password auth for emergency console access, consider keeping it enabled only via Match blocks for specific IPs.

> These are suggestions only. Review commands before running them on your system.

## SSH-003

**What we found:** MaxAuthTries is set to {{value}}.

**Why this matters:** A high (or default) MaxAuthTries gives attackers many attempts per connection, making online brute-force attacks more efficient. Lowering it to 4 or less forces attackers to reconnect frequently, increasing noise and detection opportunity.

**How to verify:**
1. Check the current setting: `grep -i '^MaxAuthTries' /etc/ssh/sshd_config`
2. Or run: `sshd -T | grep -i maxauthtries`

**Backup commands:**
1. Back up sshd_config: `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)`

**Suggested next action:**
1. Edit `/etc/ssh/sshd_config` and set `MaxAuthTries 4` (or lower).
2. Restart SSH: `sudo systemctl restart sshd`

**Rollback commands:**
1. Restore the backup and restart SSH.

**Risk level:** MEDIUM

**Confidence / caveat:** High confidence. Very low risk of breaking legitimate users who mistype passwords occasionally.

> These are suggestions only. Review commands before running them on your system.

## SSH-004

**What we found:** SSH Protocol is set to {{value}}.

**Why this matters:** SSH Protocol 1 is cryptographically broken and vulnerable to multiple attacks (CVE-2001-0572, CRC32 compensation attack, etc.). Modern OpenSSH defaults to Protocol 2, but an explicit Protocol 1 or 1,2 line re-enables the weak protocol.

**How to verify:**
1. Check the current setting: `grep -i '^Protocol' /etc/ssh/sshd_config`
2. Or run: `sshd -T | grep -i '^protocol'`

**Backup commands:**
1. Back up sshd_config: `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)`

**Suggested next action:**
1. Edit `/etc/ssh/sshd_config` and set `Protocol 2` or remove the line entirely.
2. Restart SSH: `sudo systemctl restart sshd`

**Rollback commands:**
1. Restore the backup and restart SSH.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence. Modern clients and servers support Protocol 2 exclusively.

> These are suggestions only. Review commands before running them on your system.

## SSH-005

**What we found:** PermitEmptyPasswords is set to {{value}}.

**Why this matters:** Empty passwords allow anyone who knows a valid username to log in without any credential. This is trivially exploitable and should never be enabled on any internet-facing or multi-user system.

**How to verify:**
1. Check the current setting: `grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config`
2. Or run: `sshd -T | grep -i permitemptypasswords`

**Backup commands:**
1. Back up sshd_config: `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)`

**Suggested next action:**
1. Edit `/etc/ssh/sshd_config` and set `PermitEmptyPasswords no`.
2. Restart SSH: `sudo systemctl restart sshd`

**Rollback commands:**
1. Restore the backup and restart SSH.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence. Empty passwords are almost never intentional in production.

> These are suggestions only. Review commands before running them on your system.

## SSH-006

**What we found:** PubkeyAuthentication is set to {{value}}.

**Why this matters:** Public-key authentication is the recommended primary authentication method for SSH. Disabling it forces users to rely on weaker methods such as passwords or keyboard-interactive, increasing the attack surface.

**How to verify:**
1. Check the current setting: `grep -i '^PubkeyAuthentication' /etc/ssh/sshd_config`
2. Or run: `sshd -T | grep -i pubkeyauthentication`

**Backup commands:**
1. Back up sshd_config: `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)`

**Suggested next action:**
1. Edit `/etc/ssh/sshd_config` and set `PubkeyAuthentication yes`.
2. Restart SSH: `sudo systemctl restart sshd`

**Rollback commands:**
1. Restore the backup and restart SSH.

**Risk level:** HIGH

**Confidence / caveat:** High confidence. Ensure users have deployed their public keys before enforcing this if it was previously disabled.

> These are suggestions only. Review commands before running them on your system.

## SSH-007

**What we found:** X11Forwarding is set to {{value}}.

**Why this matters:** X11 forwarding can expose the server to additional attack surface through the X11 protocol, including keystroke logging and unauthorized screen capture. Servers rarely need graphical forwarding.

**How to verify:**
1. Check the current setting: `grep -i '^X11Forwarding' /etc/ssh/sshd_config`
2. Or run: `sshd -T | grep -i x11forwarding`

**Backup commands:**
1. Back up sshd_config: `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)`

**Suggested next action:**
1. Edit `/etc/ssh/sshd_config` and set `X11Forwarding no`.
2. Restart SSH: `sudo systemctl restart sshd`

**Rollback commands:**
1. Restore the backup and restart SSH.

**Risk level:** MEDIUM

**Confidence / caveat:** Moderate confidence. Workstations or jump hosts may legitimately need X11 forwarding; this rule is lenient on workstations.

> These are suggestions only. Review commands before running them on your system.
