# Policy Violation Detection — Why This Matters

## Security Problem

Most network security efforts focus on preventing attackers from getting in. But one of the most damaging attack phases — data exfiltration — is an outbound activity. Attackers who have already compromised a host need to send stolen data out, and they often use protocols that are uncommon or prohibited in modern environments: FTP (port 21), Telnet (port 23), or outbound SMB (port 445).

These protocols are rarely used legitimately in well-managed networks. FTP has been replaced by SFTP and HTTPS. Telnet has been replaced by SSH. Outbound SMB is almost never needed and is a primary vector for data exfiltration and command-and-control tunnels. When these protocols appear in outbound traffic, it is almost always a sign of compromise, misconfiguration, or policy non-compliance.

Additionally, compliance frameworks such as PCI DSS, HIPAA, and SOC 2 require organizations to monitor and enforce network access policies. Detecting prohibited outbound connections is not just a security best practice — it is often a regulatory requirement.

---

## Implementation Overview

The detector operates as a stateless per-event filter on pre-normalized `UnifiedEvent` records:

1. **Build disallowed port set** — create a `HashSet<int>` from the profile's `DisallowedOutboundPorts`
2. **Iterate all events** — single pass with three-condition filtering
3. **Group by (SourceIP, DstPort)** — matching events are collected into a dictionary for aggregation
4. **Emit finding** — one finding per group with connection counts, distinct destination tallies, and min/max timestamps

The entire implementation is 71 lines — the most compact detector in the engine.

---

## Operational Benefits

| Benefit | Description |
|---|---|
| Compliance evidence | Every violation produces a finding, creating an auditable record of policy enforcement |
| Exfiltration detection | Catches data leaving the network via unusual protocols |
| Misconfiguration discovery | Identifies hosts running outdated or unauthorized services |
| Threshold-aware grouping | Groups below `PolicyViolationMinEvents` are skipped; default is 1 (every group reported) |
| Minimal overhead | O(n) single pass with O(1) checks per event and dictionary grouping |

---

## Security Principles Applied

| Principle | Application |
|---|---|
| Default deny | Ports on the disallowed list are presumed unauthorized until proven otherwise |
| Defense in depth | Operates behind the firewall — catching traffic that perimeter rules may have missed |
| Least privilege | Enforces that internal hosts should only use approved outbound protocols |
| Complete audit | Every violation is recorded, not just the first or worst |
| Separation of concerns | Detection is decoupled from policy definition (set in AnalysisProfile) |

---

## Implementation Evidence

- [PolicyViolationDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PolicyViolationDetector.cs) — filter-and-group implementation (71 lines)
- [IpClassification.cs](../../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — internal/external classification (157 lines)
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — disallowed port configuration (195 lines)
- [PolicyViolationDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PolicyViolationDetectorTests.cs) — test suite (138 lines)

---

> **Elevator Pitch:** This detector is the organization's outbound policy guard — watching for any internal host that tries to send data out via FTP, Telnet, or SMB. In 71 lines, it turns every policy violation group into a documented, auditable finding that compliance teams and incident responders can act on immediately.

---

## Security Takeaways

- Policy violation detection closes the outbound side of network security that perimeter-focused tools often neglect
- The stateless design guarantees complete coverage — no windowing or grouping means no false negatives from temporal misalignment
- FTP, Telnet, and outbound SMB are high-confidence indicators of compromise in modern networks
- One finding per (SourceIP, DstPort) group creates the detailed audit trail that compliance frameworks require
- The 71-line implementation proves that effective security tooling does not require complexity
