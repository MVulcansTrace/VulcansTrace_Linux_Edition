## SRV-001

**What we found:** Telnet service ({{service}}) is running.

**Why this matters:** Telnet transmits all data, including passwords, in plain text. It offers no encryption and is trivially intercepted.

**How to verify:**
1. Check if telnet is listening: `sudo ss -tulnp | grep :23`
2. Confirm the service unit: `systemctl status {{service}}`

**Preconditions:**
- Alternative remote access (SSH) is already configured and working
- Root or sudo access

**Backup commands:**
1. Document current service state: `sudo sh -c 'systemctl status telnet.socket > /root/vulcanstrace-srv-001-telnet-status.txt'`

**Suggested next action:**
1. Consider stopping and disabling telnet: `sudo systemctl stop telnet.socket && sudo systemctl disable telnet.socket`
2. Use SSH for all remote access.
3. You may remove the telnet package: `sudo apt remove telnetd`

**Rollback commands:**
1. Re-enable telnet: `sudo systemctl enable telnet.socket && sudo systemctl start telnet.socket`
2. Reinstall package if removed: `sudo apt install telnetd`

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence — Telnet is universally considered insecure. No modern system should need it.

> These are suggestions only. Review commands before running them on your system.

## SRV-002

**What we found:** FTP service ({{service}}) is running.

**Why this matters:** Like Telnet, traditional FTP sends credentials and data unencrypted. It is also a common target for anonymous access abuse.

**How to verify:**
1. Check if FTP is listening: `sudo ss -tulnp | grep -E ':21|:20'`
2. Confirm the service unit: `systemctl status {{service}}`

**Preconditions:**
- SSH is configured for SFTP file transfers
- Root or sudo access

**Backup commands:**
1. Document current FTP config: `sudo sh -c 'test -f /etc/vsftpd.conf && cp /etc/vsftpd.conf /etc/vsftpd.conf.vulcanstrace.bak || true'`

**Suggested next action:**
1. Consider using SFTP (over SSH) instead.
2. You may stop and disable FTP: `sudo systemctl stop {{service}} && sudo systemctl disable {{service}}`
3. Ensure SSH is enabled for file transfers.
4. Remove the FTP package if no longer needed.

**Rollback commands:**
1. Re-enable FTP service: `sudo systemctl enable {{service}} && sudo systemctl start {{service}}`
2. Reinstall package if removed: `sudo apt install vsftpd`
3. Restore config: `sudo cp /etc/vsftpd.conf.vulcanstrace.bak /etc/vsftpd.conf`

**Risk level:** HIGH

**Confidence / caveat:** High confidence — unless you have a specific legacy need, SFTP is the modern replacement.

> These are suggestions only. Review commands before running them on your system.

## SRV-003

**What we found:** SSH service is not running.

**Why this matters:** Without SSH, you have no encrypted remote management capability. If remote access is needed, you would have to use insecure alternatives.

**How to verify:**
1. Check SSH status: `systemctl status ssh` or `systemctl status sshd`
2. Check if port 22 is listening: `sudo ss -tulnp | grep :22`

**Suggested next action:**
1. Consider installing and starting SSH: `sudo apt install openssh-server && sudo systemctl enable --now ssh`
2. Harden the configuration in `/etc/ssh/sshd_config`.

**Risk level:** MEDIUM

**Confidence / caveat:** Low confidence — this may be intentional for a local-only workstation. Verify before enabling remote access.

> These are suggestions only. Review commands before running them on your system.

## SRV-004

**What we found:** Legacy r-service ({{service}}) is running.

**Why this matters:** rsh, rexec, and rlogin rely on host-based trust and transmit data without encryption. They are obsolete and widely exploited.

**How to verify:**
1. Check the service status: `systemctl status {{service}}`
2. Look for listening ports associated with r-services.

**Suggested next action:**
1. Consider stopping and disabling the service: `sudo systemctl stop {{service}} && sudo systemctl disable {{service}}`
2. You may remove the package: `sudo apt remove rsh-server`
3. Use SSH exclusively for remote shell access.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence — r-services have been deprecated for decades. There is no legitimate use case in modern environments.

> These are suggestions only. Review commands before running them on your system.

## SRV-005

**What we found:** Unnecessary service ({{service}}) is running ({{count}} total found).

**Why this matters:** Every running service expands your attack surface. Services like CUPS (printing), Avahi (mDNS), or Bluetooth may not be needed on a server and can expose vulnerabilities.

**How to verify:**
1. Review all running services: `systemctl list-units --type=service --state=running`
2. Research whether {{service}} is needed for your workload.

**Suggested next action:**
1. Consider stopping and disabling unnecessary services: `sudo systemctl stop {{service}} && sudo systemctl disable {{service}}`
2. Review all running services: `systemctl list-units --type=service --state=running`
3. Remove packages if not needed.

**Risk level:** LOW

**Confidence / caveat:** Low confidence — what is "unnecessary" depends on your use case. Review each service individually.

> These are suggestions only. Review commands before running them on your system.
