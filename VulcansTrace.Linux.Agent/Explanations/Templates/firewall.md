## FW-001

**What we found:** Your firewall default INPUT policy is {{policy}} instead of DROP.

**Why this matters:** A default ACCEPT policy means any incoming traffic that doesn't match an explicit rule is allowed through. This leaves your system exposed to scanning, unauthorized access, and automated attacks.

**How to fix it:**
1. Change the default policy: `sudo iptables -P INPUT DROP`
2. Ensure you have rules to allow necessary traffic (SSH, HTTP, etc.) before applying the policy.
3. Save the rules so they persist after reboot: `sudo iptables-save > /etc/iptables/rules.v4`

**Risk level:** HIGH

## FW-002

**What we found:** SSH (port 22) is accepting connections from any IP address ({{source}}).

**Why this matters:** Anyone on the internet can attempt to log into your system. Automated bots constantly scan for open SSH and try thousands of passwords.

**How to fix it:**
1. Restrict SSH to specific IPs: `sudo iptables -A INPUT -p tcp --dport 22 -s YOUR_IP -j ACCEPT`
2. Use key-based authentication: edit `/etc/ssh/sshd_config`, set `PasswordAuthentication no`
3. Install fail2ban: `sudo apt install fail2ban`

**Risk level:** HIGH

## FW-003

**What we found:** No connection state tracking rule (ESTABLISHED,RELATED) was found.

**Why this matters:** Without state tracking, your firewall cannot distinguish between legitimate response traffic and unsolicited incoming connections. This forces you to open more ports than necessary.

**How to fix it:**
1. Add a state tracking rule: `sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`
2. Place this rule early in your INPUT chain (before any DROP rules).

**Risk level:** MEDIUM

## FW-004

**What we found:** No active firewall (iptables or nftables) was detected on this system.

**Why this matters:** Without a firewall, all ports are effectively open to the network. Any service listening on any interface is directly reachable from any source.

**How to fix it:**
1. Install and configure iptables or nftables.
2. Set a default DROP policy and add explicit allow rules for required services.
3. Enable the firewall service to start on boot.

**Risk level:** CRITICAL

## FW-005

**What we found:** ICMP is blanket-accepted from any source without rate limiting.

**Why this matters:** Unrestricted ICMP can be abused for network reconnaissance (ping sweeps), Smurf amplification attacks, and ICMP tunneling.

**How to fix it:**
1. Rate-limit ICMP: `sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT`
2. Drop excess ICMP: `sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP`
3. Or restrict ICMP to specific trusted networks.

**Risk level:** LOW
