# Evasion and Limitations: Privilege Escalation Detection

## Known Limitations

| Limitation | Impact | Severity |
|---|---|---|
| Slow brute force | An attacker sending 1 attempt every 6 minutes may never trigger the spike threshold | Medium |
| Distributed attacks | Multiple source IPs each attempting 2–4 admin connections evade per-source grouping | High |
| Non-standard admin ports | Services on ports outside the baseline + profile set are invisible | Medium |
| Sweep state reset after burst | Only one finding per contiguous burst; a paused and resumed sweep may be reported as separate findings | Low |
| Legitimate admin activity | Automated monitoring or admin scripts connecting to admin services may trigger false positives | Medium |
| No authentication result | The detector sees connection attempts, not login outcomes — it cannot distinguish successful from failed logins | High |
| No application-layer analysis | The detector operates at the network level and cannot inspect authentication protocols | Medium |

---

### Slow Brute Force (Timing-Based Evasion)

An attacker who sends one SSH login attempt every 6 minutes will generate events spread across many 5-minute windows. With a spike threshold of 5 attempts per window and a 5-minute window, the attacker would need to send at least 5 attempts within a single sliding window to trigger the detector. At one attempt per 6 minutes, the attacker would need 30 minutes to accumulate 5 attempts within any 5-minute span.

**Mitigation options:** Reduce the window size via the Medium profile (5 minutes), or add a cumulative per-source counter that tracks total admin-port attempts across all windows. The current design prioritizes burst detection because rapid brute-force attacks are more common and more immediately dangerous than slow-and-low credential guessing.

---

### Distributed Attacks

If an attacker controls multiple source IPs and distributes admin-port attempts across them (e.g., 2 attempts per source from 3 sources), no individual source will reach the spike threshold of 5. Similarly, a distributed sweep where each source probes a different admin port would produce only 1 distinct port per source, below the sweep threshold of 3.

**Mitigation options:** Cross-source correlation could be added by identifying multiple sources targeting the same destination's admin ports within a time window. Threat intelligence feeds could flag known botnet infrastructure. These are future improvements.

---

### Non-Standard Admin Ports

The baseline admin port set covers SSH (22, 2222, 2200, 22022), RDP (3389), VNC (5900), PostgreSQL (5432), and MySQL (3306). If an organization runs SSH on port 8022 or a custom database on port 3307, the detector will not monitor those ports unless they are added to `AdminPorts` in the profile.

**Mitigation options:** Organizations should configure `AdminPorts` in their `AnalysisProfile` to include all administrative service ports, including those on non-standard ports. The merge pattern ensures custom ports are added alongside the baseline.

---

### No Authentication Result Awareness

The detector operates on connection-level events from firewall logs. It sees that a connection was attempted to port 22, but not whether the SSH login succeeded or failed. A legitimate administrator connecting to SSH 5 times in 5 minutes (e.g., reconnecting after network issues) would trigger the same spike finding as a brute-force attack.

**Mitigation options:** Correlate with authentication logs (e.g., `/var/log/auth.log`) to distinguish successful from failed logins. This requires log enrichment beyond the iptables event stream and is a future enhancement.

---

### Legitimate Admin Activity

System administrators, monitoring tools, and automation scripts may connect to admin services frequently, triggering false positives. A Nagios monitor checking SSH availability every 30 seconds would generate 10 connections per 5-minute window, exceeding the spike threshold.

**Mitigation options:** Whitelist known monitoring IPs before events reach the detector, or use the Low profile in environments with heavy automated admin traffic. The profile-gated activation under Low is specifically designed for this scenario.

---

## Improvement Roadmap

| Improvement | Description | Priority |
|---|---|---|
| Authentication log correlation | Cross-reference findings with `/var/log/auth.log` to distinguish successful from failed logins | High |
| Cumulative spike counter | Track total admin-port attempts per source across all windows for slow-and-low detection | Medium |
| Cross-source correlation | Identify distributed attacks by correlating multiple sources targeting the same admin services | Medium |
| Whitelist support | Allow trusted source IPs to be excluded from detection | High |
| Per-port thresholds | Different thresholds for different admin ports (e.g., lower for RDP than for SSH) | Low |
| Sweep multi-report option | Allow configurable cap on sweep findings per source (currently unlimited) | Low |
| Destination-aware analysis | Differentiate findings by destination host to support multi-target environments | Medium |

---

## Security Takeaways

1. The detector is most effective against fast, aggressive attacks — the most common and immediately dangerous privilege escalation patterns
2. Slow, distributed, and non-standard-port attacks require additional detection layers or future improvements
3. The lack of authentication result awareness is the most significant limitation — the detector flags connection patterns, not successful compromises
4. False positives from legitimate admin activity can be managed through profile selection and environment-specific configuration
5. The improvement roadmap prioritizes authentication log correlation and whitelisting for the highest immediate impact
6. Profile-based activation under Low provides a clear escape valve for environments where admin-port monitoring is not appropriate
