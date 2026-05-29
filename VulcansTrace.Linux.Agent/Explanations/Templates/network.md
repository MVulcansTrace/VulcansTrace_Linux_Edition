## NET-001

**What we found:** No default gateway is configured.

**Why this matters:** Without a default route, your system cannot reach external networks. While this limits outbound exposure, it may indicate a misconfiguration or an isolated segment that still needs internal routing review.

**How to fix it:**
1. Check your network configuration: `ip route`
2. Add a default route if needed: `sudo ip route add default via 192.168.1.1 dev eth0`
3. Make it persistent in `/etc/netplan/` or your distro's network config.

**Risk level:** MEDIUM

## NET-002

**What we found:** Suspicious outbound connection to {{remote}} (high-risk port).

**Why this matters:** Outbound connections to ports like 23 (telnet), 445 (SMB), or 3389 (RDP) can indicate lateral movement, data exfiltration, or command-and-control activity.

**How to fix it:**
1. Investigate the process: `ss -tunap | grep :{{port}}`
2. Check process tree and command line: `ps aux | grep {{port}}`
3. Block outbound traffic to high-risk ports if not needed: `sudo iptables -A OUTPUT -p tcp --dport {{port}} -j DROP`
4. Run a full malware scan.

**Risk level:** HIGH

## NET-003

**What we found:** No network interface is currently up.

**Why this matters:** All interfaces are down. This may be intentional (air-gapped) or a sign of network misconfiguration. If unexpected, it could also indicate interface tampering.

**How to fix it:**
1. Check interface status: `ip link show`
2. Bring up the interface: `sudo ip link set eth0 up`
3. Verify DHCP or static IP configuration.

**Risk level:** HIGH

## NET-004

**What we found:** A service ({{process}}) is listening on {{address}}:{{port}}, which may also be listening on loopback.

**Why this matters:** If a service intended only for local use (like a database admin interface or metrics endpoint) is bound to all interfaces, it becomes reachable from the network.

**How to fix it:**
1. Reconfigure the service to bind to 127.0.0.1 only.
2. If remote access is needed, use a VPN or SSH tunnel instead.
3. Add a firewall rule restricting access to trusted IPs.

**Risk level:** MEDIUM
