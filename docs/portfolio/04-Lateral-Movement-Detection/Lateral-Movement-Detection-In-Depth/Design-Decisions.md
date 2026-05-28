# Lateral Movement Detection — Design Decisions

> Every design choice in the lateral movement detector prioritizes detection accuracy over completeness — better to catch one confirmed pivot than flood analysts with ambiguous alerts.

---

## Decision 1: Two-Pointer Sliding Window Over Fixed Bins

**Decision:** Use a two-pointer sliding window instead of fixed time bins (e.g., "per hour" or "per minute").

**Rationale:** Fixed bins suffer from boundary artifacts — an attacker connecting to 5 hosts at 11:59 and 5 hosts at 12:01 would split across two bins and evade detection. The sliding window advances through chronologically ordered events, maintaining the widest valid time window at each step, ensuring temporal patterns are always captured regardless of alignment.

**Security Rationale:** Attackers don't respect clock boundaries. The sliding window eliminates a significant class of false negatives that fixed-bin approaches would miss.

**Business Value:** Higher detection rate with no increase in false positives, directly improving the signal quality analysts receive.

---

## Decision 2: Distinct Destination IP Counting

**Decision:** Count distinct destination IPs rather than total connection count within the window.

**Rationale:** A legitimate admin might open dozens of SSH sessions to the same server (e.g., during a configuration task). Counting raw connections would flag this benign behavior. Counting distinct hosts ensures the detector fires only when a source is touching many different machines — the actual hallmark of lateral movement.

**Security Rationale:** Lateral movement is defined by the breadth of target reach, not connection volume. This distinction is what separates malicious pivoting from normal administrative workloads.

**Business Value:** Dramatically reduces false positives on networks with centralized management tools that make frequent admin-port connections.

---

## Decision 3: Internal-to-Internal Traffic Only

**Decision:** Require both the source IP and destination IP to be classified as internal (RFC 1918 private addresses: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`; IPv4 loopback `127.0.0.0/8`, link-local `169.254.0.0/16`, `0.0.0.0/8`, `100.64.0.0/10`; IPv6 ULA `fc00::/7`, loopback `::1`, and link-local `fe80::/10`) before considering an event for lateral movement analysis.

**Rationale:** Lateral movement is, by definition, traversal *within* a compromised network. External-to-internal traffic is an initial-access or perimeter problem, handled by other detectors. Internal-to-external traffic is exfiltration or command-and-control, not pivoting. Restricting the detector to internal-to-internal flows eliminates entire categories of false positives from internet-facing traffic.

**Security Rationale:** Scoping the detector to internal-to-internal connections ensures it fires only on the specific threat it is designed to catch — an attacker who has already gained a foothold and is probing or pivoting through internal hosts.

**Business Value:** Dramatically reduces noise from inbound scans and outbound C2 traffic, which are the responsibility of other detectors in the pipeline. Analysts see only findings relevant to post-compromise lateral movement.

---

## Decision 4: Admin-Port-Only Filtering

**Decision:** Restrict analysis to admin ports — by default, ports 445 (SMB), 3389 (RDP), and 22 (SSH) — configurable via the `AdminPorts` property on `AnalysisProfile`.

**Rationale:** These three protocols are the primary tools attackers use for lateral movement. Including all ports would drown the detector in noise from HTTP, DNS, and other high-volume legitimate traffic.

**Security Rationale:** SMB and RDP are among the most commonly observed lateral movement protocols in MITRE ATT&CK's T1021 (Remote Services) technique family. SSH covers Linux environments. Together they cover the vast majority of real-world lateral movement techniques.

**Business Value:** Focused detection means faster analysis and clearer findings, reducing mean time to triage.

---

## Decision 5: Burst-Aware Finding Emission

**Decision:** Emit one finding per contiguous above-threshold burst rather than one per event or one per source.

**Rationale:** A source may exhibit lateral movement in multiple distinct time-separated bursts. The detector uses an `inFinding` state flag to track whether it is currently inside an active above-threshold window. When the threshold is first crossed, a finding is created. As long as the distinct-host count stays above threshold, the same finding is extended (tracking the peak host count). When the count drops below threshold, the finding is finalized with its actual time range and peak count. This allows separate bursts to produce separate findings while avoiding duplicate findings from overlapping windows.

**Security Rationale:** Alert fatigue is a real operational risk, but so is missing follow-on attack phases. One finding per burst gives analysts a clean timeline of attacker activity without suppressing repeated pivoting attempts. Note that if the same source IP also triggers the beaconing detector, the pipeline's `RiskEscalator` will escalate this finding from High to Critical severity — signaling a host that is both beaconing to an external C2 address *and* pivoting internally.

**Business Value:** Cleaner analyst experience with a complete timeline of attacker activity.

---

## Decision 6: Profile-Driven Thresholds

**Decision:** Make minimum host count, window duration, and admin port list configurable via `AnalysisProfile` rather than hardcoded.

**Rationale:** Different network environments have different baselines. A large enterprise with automated management tools may have legitimate admin connections to 5+ hosts in 10 minutes, while a small office network would not. Profile-driven thresholds let operators calibrate without code changes.

**Security Rationale:** Overly sensitive thresholds generate noise; overly permissive thresholds miss attacks. Configurability ensures the detector can be tuned to each environment's specific risk profile.

**Business Value:** One detector serves all deployment scenarios, from small business to enterprise, without code modification.

---

## Summary

| Decision | Trade-off | Security Outcome |
|---|---|---|
| Sliding window | Slightly higher compute than fixed bins | Eliminates boundary artifacts |
| Distinct host counting | Ignores connection volume | Reduces admin-traffic false positives |
| Internal-to-internal filtering | Misses external pivoting | Eliminates perimeter and C2 false positives |
| Admin-port filtering | Misses non-admin pivoting | High signal-to-noise ratio |
| Burst-aware emission | One finding per contiguous above-threshold burst | Prevents duplicate findings from overlapping windows while capturing repeated pivoting
| Profile-driven thresholds | Requires configuration awareness | Adapts to any network environment |
