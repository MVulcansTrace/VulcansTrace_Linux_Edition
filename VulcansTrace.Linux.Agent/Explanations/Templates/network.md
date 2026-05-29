## NET-001

**What we found:** No default gateway is configured.

**Why this matters:** Without a default route, your system cannot reach external networks. While this limits outbound exposure, it may indicate a misconfiguration or an isolated segment that still needs internal routing review.

**How to verify:**
1. Check routes: `ip route`
2. Look for a line starting with `default via ...`

**Suggested next action:**
1. Review your network configuration: `ip route`
2. Consider adding a default route if needed: `sudo ip route add default via 192.168.1.1 dev eth0`
3. Make it persistent in `/etc/netplan/` or your distro's network config.

**Risk level:** MEDIUM

**Confidence / caveat:** Moderate confidence — air-gapped systems intentionally have no default gateway. Verify this is expected in your environment.

> These are suggestions only. Review commands before running them on your system.

## NET-002

**What we found:** Suspicious outbound connection to {{remote}} (high-risk port).

**Why this matters:** Outbound connections to ports like 23 (telnet), 445 (SMB), or 3389 (RDP) can indicate lateral movement, data exfiltration, or command-and-control activity.

**How to verify:**
1. Investigate the process: `ss -tunap | grep :{{port}}`
2. Check process tree and command line: `ps aux | grep {{port}}`

**Preconditions:**
- Confirm the connection is not legitimate business traffic
- Root or sudo access

**Backup commands:**
1. Save current iptables rules: `sudo sh -c 'iptables-save > /root/vulcanstrace-net-002.rules'`

**Suggested next action:**
1. Investigate the process owning the connection.
2. Consider blocking outbound traffic to high-risk ports if not needed: `sudo iptables -A OUTPUT -p tcp --dport {{port}} -j DROP`
3. Run a full malware scan.

**Rollback commands:**
1. Remove the OUTPUT rule: `sudo iptables -D OUTPUT -p tcp --dport {{port}} -j DROP`
2. Restore saved rules: `sudo sh -c 'iptables-restore < /root/vulcanstrace-net-002.rules'`

**Risk level:** HIGH

**Confidence / caveat:** Moderate confidence — the connection may be legitimate (e.g., SMB to a file server). Verify the remote IP and process before taking action.

> These are suggestions only. Review commands before running them on your system.

## NET-003

**What we found:** No network interface is currently up.

**Why this matters:** All interfaces are down. This may be intentional (air-gapped) or a sign of network misconfiguration. If unexpected, it could also indicate interface tampering.

**How to verify:**
1. Check interface status: `ip link show`
2. Look for interfaces with state `UP`.

**Suggested next action:**
1. Review interface status: `ip link show`
2. Consider bringing up the interface: `sudo ip link set eth0 up`
3. Verify DHCP or static IP configuration.

**Risk level:** HIGH

**Confidence / caveat:** Low confidence — this may be intentional for an offline system. Verify before making changes.

> These are suggestions only. Review commands before running them on your system.

## NET-004

**What we found:** A service ({{process}}) is listening on {{address}}:{{port}}, which may also be listening on loopback.

**Why this matters:** If a service intended only for local use (like a database admin interface or metrics endpoint) is bound to all interfaces, it becomes reachable from the network.

**How to verify:**
1. Check binding addresses: `sudo ss -tulnp | grep {{port}}`
2. Review the service configuration file for bind/listen directives.

**Suggested next action:**
1. Consider reconfiguring the service to bind to 127.0.0.1 only.
2. If remote access is needed, use a VPN or SSH tunnel instead.
3. Add a firewall rule restricting access to trusted IPs.

**Risk level:** MEDIUM

**Confidence / caveat:** Moderate confidence — some services legitimately need to bind to all interfaces. Review the service documentation.

> These are suggestions only. Review commands before running them on your system.
