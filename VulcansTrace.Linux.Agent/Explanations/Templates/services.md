## SRV-001

**What we found:** Telnet service ({{service}}) is running.

**Why this matters:** Telnet transmits all data, including passwords, in plain text. It offers no encryption and is trivially intercepted.

**How to fix it:**
1. Stop and disable telnet: `sudo systemctl stop telnet.socket && sudo systemctl disable telnet.socket`
2. Use SSH for all remote access.
3. Remove the telnet package: `sudo apt remove telnetd`

**Risk level:** CRITICAL

## SRV-002

**What we found:** FTP service ({{service}}) is running.

**Why this matters:** Like Telnet, traditional FTP sends credentials and data unencrypted. It is also a common target for anonymous access abuse.

**How to fix it:**
1. Use SFTP (over SSH) instead: `sudo systemctl stop {{service}} && sudo systemctl disable {{service}}`
2. Ensure SSH is enabled for file transfers.
3. Remove the FTP package if no longer needed.

**Risk level:** HIGH

## SRV-003

**What we found:** SSH service is not running.

**Why this matters:** Without SSH, you have no encrypted remote management capability. If remote access is needed, you would have to use insecure alternatives.

**How to fix it:**
1. Install and start SSH: `sudo apt install openssh-server && sudo systemctl enable --now ssh`
2. Harden the configuration in `/etc/ssh/sshd_config`.

**Risk level:** MEDIUM

## SRV-004

**What we found:** Legacy r-service ({{service}}) is running.

**Why this matters:** rsh, rexec, and rlogin rely on host-based trust and transmit data without encryption. They are obsolete and widely exploited.

**How to fix it:**
1. Stop and disable the service: `sudo systemctl stop {{service}} && sudo systemctl disable {{service}}`
2. Remove the package: `sudo apt remove rsh-server`
3. Use SSH exclusively for remote shell access.

**Risk level:** CRITICAL

## SRV-005

**What we found:** Unnecessary service ({{service}}) is running ({{count}} total found).

**Why this matters:** Every running service expands your attack surface. Services like CUPS (printing), Avahi (mDNS), or Bluetooth may not be needed on a server and can expose vulnerabilities.

**How to fix it:**
1. Stop and disable unnecessary services: `sudo systemctl stop {{service}} && sudo systemctl disable {{service}}`
2. Review all running services: `systemctl list-units --type=service --state=running`
3. Remove packages if not needed.

**Risk level:** LOW
