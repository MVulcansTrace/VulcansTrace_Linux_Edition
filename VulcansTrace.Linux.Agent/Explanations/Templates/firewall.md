## FW-001

**What we found:** Your firewall default INPUT policy is {{policy}} instead of DROP.

**Why this matters:** A default ACCEPT policy means any incoming traffic that doesn't match an explicit rule is allowed through. This leaves your system exposed to scanning, unauthorized access, and automated attacks.

**How to verify:**
1. Check the current policy: `sudo iptables -L INPUT | head -n 1`
2. Look for the line "Chain INPUT (policy ...)" — it should say DROP.

**Suggested next action:**
1. Consider changing the default policy: `sudo iptables -P INPUT DROP`
2. Ensure you have rules to allow necessary traffic (SSH, HTTP, etc.) before applying the policy.
3. Save the rules so they persist after reboot: `sudo iptables-save > /etc/iptables/rules.v4`

**Risk level:** HIGH

**Confidence / caveat:** High confidence — this is a direct configuration read. If you are in a container or VM, the host firewall may also matter.

> These are suggestions only. Review commands before running them on your system.

## FW-002

**What we found:** SSH (port 22) is accepting connections from any IP address ({{source}}).

**Why this matters:** Anyone on the internet can attempt to log into your system. Automated bots constantly scan for open SSH and try thousands of passwords.

**How to verify:**
1. Check current SSH listening address: `sudo ss -tulnp | grep :22`
2. Review iptables rules for port 22: `sudo iptables -L INPUT -n | grep 22`

**Suggested next action:**
1. Consider restricting SSH to specific IPs: `sudo iptables -A INPUT -p tcp --dport 22 -s YOUR_IP -j ACCEPT`
2. Review key-based authentication in `/etc/ssh/sshd_config`
3. You may install fail2ban: `sudo apt install fail2ban`

**Risk level:** HIGH

**Confidence / caveat:** High confidence if the scanner can read iptables/nftables rules. If rules are managed by a higher-level tool (ufw, firewalld), use that tool instead.

> These are suggestions only. Review commands before running them on your system.

## FW-003

**What we found:** No connection state tracking rule (ESTABLISHED,RELATED) was found.

**Why this matters:** Without state tracking, your firewall cannot distinguish between legitimate response traffic and unsolicited incoming connections. This forces you to open more ports than necessary.

**How to verify:**
1. List rules and grep for conntrack: `sudo iptables -L -v -n | grep -i conntrack`
2. Alternatively look for `--state ESTABLISHED,RELATED` in the rule set.

**Suggested next action:**
1. Consider adding a state tracking rule: `sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`
2. Place this rule early in your INPUT chain (before any DROP rules).

**Risk level:** MEDIUM

**Confidence / caveat:** Moderate confidence — some nftables setups use implicit state tracking. Verify with your distribution's firewall documentation.

> These are suggestions only. Review commands before running them on your system.

## FW-004

**What we found:** No active firewall (iptables or nftables) was detected on this system.

**Why this matters:** Without a firewall, all ports are effectively open to the network. Any service listening on any interface is directly reachable from any source.

**How to verify:**
1. Check iptables: `sudo iptables -L -n`
2. Check nftables: `sudo nft list ruleset`
3. Check if a wrapper like ufw or firewalld is active: `sudo ufw status` or `sudo firewall-cmd --state`

**Suggested next action:**
1. Consider installing and configuring iptables or nftables.
2. Set a default DROP policy and add explicit allow rules for required services.
3. Enable the firewall service to start on boot.

**Risk level:** CRITICAL

**Confidence / caveat:** High confidence if the scanner has permission to query iptables/nftables. If you use a cloud security group or host-level firewall, that may provide protection even if local rules are empty.

> These are suggestions only. Review commands before running them on your system.

## FW-005

**What we found:** ICMP is blanket-accepted from any source without rate limiting.

**Why this matters:** Unrestricted ICMP can be abused for network reconnaissance (ping sweeps), Smurf amplification attacks, and ICMP tunneling.

**How to verify:**
1. Check ICMP rules: `sudo iptables -L INPUT -n | grep -i icmp`
2. Test from another host: `ping -f <this-host>` and observe if all packets are accepted.

**Suggested next action:**
1. Consider rate-limiting ICMP: `sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT`
2. Drop excess ICMP: `sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP`
3. Or restrict ICMP to specific trusted networks.

**Risk level:** LOW

**Confidence / caveat:** Low confidence — some environments intentionally allow ICMP for monitoring. Rate limiting is a safe middle ground.

> These are suggestions only. Review commands before running them on your system.
