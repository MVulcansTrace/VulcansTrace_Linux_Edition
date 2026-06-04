## TI-001

**What we found:** {{count}} active connection(s) to known malicious IP address(es). First match: {{first_ip}}:{{first_port}}.

**Why this matters:** Active connections to IPs flagged in threat intelligence feeds are strong indicators of compromise, command-and-control communication, or lateral movement.

**How to verify:**
1. Investigate the connection: `ss -tunap | grep {{first_ip}}`
2. Check the process tree: `ps auxf | grep -i {{first_port}}`
3. Review netfilter logs for related traffic: `sudo dmesg | grep {{first_ip}}`

**Suggested next action:**
1. Isolate the host from the network if compromise is suspected.
2. Terminate suspicious processes after investigation.
3. Block the IP at the firewall: `sudo iptables -A OUTPUT -d {{first_ip}} -j DROP`
4. Run a full malware scan and forensic timeline analysis.

**Risk level:** HIGH

**Confidence / caveat:** Confidence varies per IOC ({{match_1_confidence}}%). Verify the connection is not legitimate before taking action.

> These are suggestions only. Review commands before running them on your system.

## TI-002

**What we found:** {{count}} open port(s) match known malicious port IOC(s). First match: port {{first_port}} (process: {{first_process}}).

**Why this matters:** Services listening on ports associated with known malware or backdoors may indicate an active compromise or unauthorized service.

**How to verify:**
1. Check the listening service: `sudo ss -tulnp | grep :{{first_port}}`
2. Inspect the process: `ps aux | grep {{first_process}}`
3. Review how the service was started (systemd, cron, manual).

**Suggested next action:**
1. Stop and disable the suspicious service if confirmed malicious.
2. Remove the associated binary if it is unauthorized.
3. Add firewall rules to block inbound traffic on the port if not needed.

**Risk level:** HIGH

**Confidence / caveat:** Confidence varies per IOC ({{match_1_confidence}}%). Some ports may be used legitimately.

> These are suggestions only. Review commands before running them on your system.

## TI-003

**What we found:** {{count}} file(s) on disk match known malicious hash(es). First match: {{first_path}} (hash: {{first_hash}}).

**Why this matters:** A file whose SHA-256 hash exactly matches a known malicious hash is near-certain evidence of malware or a malicious tool.

**How to verify:**
1. Recompute the hash manually: `sha256sum {{first_path}}`
2. Check file metadata: `ls -la {{first_path}}`
3. Review when the file appeared: `stat {{first_path}}`

**Suggested next action:**
1. Quarantine the file immediately: `sudo mv {{first_path}} /quarantine/`
2. Do not execute the file.
3. Initiate incident response and forensic analysis.
4. Hunt for related indicators (persistence, network connections, scheduled tasks).

**Risk level:** CRITICAL

**Confidence / caveat:** Hash matches are high-confidence indicators. Verify the file path is not a known false positive before quarantining.

> These are suggestions only. Review commands before running them on your system.
