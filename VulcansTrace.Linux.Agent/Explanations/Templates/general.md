## PORT-001

**What we found:** SSH is running on the default port (22).

**Why this matters:** While not a vulnerability by itself, running SSH on port 22 makes your system an easy target for automated scanners and brute-force bots.

**How to verify:**
1. Check the SSH port: `sudo ss -tulnp | grep ssh`
2. Review `/etc/ssh/sshd_config` for the `Port` directive.

**Suggested next action:**
1. You may change the SSH port in `/etc/ssh/sshd_config`: `Port 2222`
2. Update firewall rules to allow the new port.
3. Note: This is security through obscurity — always pair with key-based auth and fail2ban.

**Risk level:** INFO

**Confidence / caveat:** Low confidence — this is informational only. Changing the port reduces log noise but does not improve cryptographic security.

> These are suggestions only. Review commands before running them on your system.

## PORT-002

**What we found:** {{count}} service(s) listening on all interfaces ({{address}}:{{port}} — {{process}}).

**Why this matters:** Services bound to 0.0.0.0 or :: are reachable from any network interface. Unless they are intentionally public-facing, this increases exposure.

**How to verify:**
1. Check listening addresses: `sudo ss -tulnp | grep {{port}}`
2. Review the service configuration for bind/listen directives.

**Suggested next action:**
1. Consider reconfiguring services to bind to specific interfaces or 127.0.0.1.
2. Use firewall rules to restrict access to trusted IPs.
3. Review each service to confirm it needs to be externally accessible.

**Risk level:** MEDIUM

**Confidence / caveat:** Moderate confidence — some services legitimately need to be public-facing (web servers, mail servers). Verify intent before restricting.

> These are suggestions only. Review commands before running them on your system.

## PORT-003

**What we found:** Database port {{port}} ({{process}}) is exposed to all interfaces.

**Why this matters:** Exposing database ports directly to the internet is a major risk. Attackers routinely scan for open MySQL, PostgreSQL, MongoDB, and Redis ports.

**How to verify:**
1. Check the database bind address in its configuration file.
2. Test from an external host: `nmap -p {{port}} <this-host>`

**Suggested next action:**
1. Consider binding the database to 127.0.0.1 in its configuration.
2. If remote access is needed, use an SSH tunnel or VPN.
3. You may add a firewall rule: `sudo iptables -A INPUT -p tcp --dport {{port}} -s 127.0.0.1 -j ACCEPT` and drop all others.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence — databases should almost never be directly internet-facing. This is one of the most common security misconfigurations.

> These are suggestions only. Review commands before running them on your system.

## PORT-004

**What we found:** {{count}} high port(s) listening without an identifiable process (first: {{port}}).

**Why this matters:** Unidentified listening ports can indicate malware, backdoors, or forgotten services.

**How to verify:**
1. Run with sudo to see process names: `sudo ss -tulnp | grep :{{port}}`
2. Check the process tree: `ps aux | grep <pid>`
3. If still unidentified, check for kernel-level listeners.

**Suggested next action:**
1. Consider identifying the process with elevated privileges: `sudo ss -tulnp | grep :{{port}}`
2. Check the process tree: `ps aux | grep <pid>`
3. If unrecognized, terminate and investigate further.

**Risk level:** INFO

**Confidence / caveat:** Low confidence — the process may be hidden due to permission limits. Run with sudo for full visibility.

> These are suggestions only. Review commands before running them on your system.
