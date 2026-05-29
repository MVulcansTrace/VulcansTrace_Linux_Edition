## PORT-001

**What we found:** SSH is running on the default port (22).

**Why this matters:** While not a vulnerability by itself, running SSH on port 22 makes your system an easy target for automated scanners and brute-force bots.

**How to fix it:**
1. Change the SSH port in `/etc/ssh/sshd_config`: `Port 2222`
2. Update firewall rules to allow the new port.
3. Note: This is security through obscurity — always pair with key-based auth and fail2ban.

**Risk level:** INFO

## PORT-002

**What we found:** {{count}} service(s) listening on all interfaces ({{address}}:{{port}} — {{process}}).

**Why this matters:** Services bound to 0.0.0.0 or :: are reachable from any network interface. Unless they are intentionally public-facing, this increases exposure.

**How to fix it:**
1. Reconfigure services to bind to specific interfaces or 127.0.0.1.
2. Use firewall rules to restrict access to trusted IPs.
3. Review each service to confirm it needs to be externally accessible.

**Risk level:** MEDIUM

## PORT-003

**What we found:** Database port {{port}} ({{process}}) is exposed to all interfaces.

**Why this matters:** Exposing database ports directly to the internet is a major risk. Attackers routinely scan for open MySQL, PostgreSQL, MongoDB, and Redis ports.

**How to fix it:**
1. Bind the database to 127.0.0.1 in its configuration.
2. If remote access is needed, use an SSH tunnel or VPN.
3. Add a firewall rule: `sudo iptables -A INPUT -p tcp --dport {{port}} -s 127.0.0.1 -j ACCEPT` and drop all others.

**Risk level:** CRITICAL

## PORT-004

**What we found:** {{count}} high port(s) listening without an identifiable process (first: {{port}}).

**Why this matters:** Unidentified listening ports can indicate malware, backdoors, or forgotten services.

**How to fix it:**
1. Identify the process: `sudo ss -tulnp | grep :{{port}}`
2. Check the process tree: `ps aux | grep <pid>`
3. If unrecognized, terminate and investigate further.

**Risk level:** INFO
