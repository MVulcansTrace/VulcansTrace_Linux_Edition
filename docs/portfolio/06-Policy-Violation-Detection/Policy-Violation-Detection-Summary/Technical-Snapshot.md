# Policy Violation Detection — Technical Snapshot

> The policy violation detector is one of the most deterministic detectors in the engine — a filter that flags internal hosts connecting to external destinations on prohibited ports, then groups violations by `(SourceIP, DstPort)` to produce aggregated findings. In compact production C#, it enforces outbound firewall policy by checking three conditions per event: internal source, external destination, and disallowed port. Each group generates its own finding with connection counts and distinct destination tallies, providing complete audit coverage for compliance and forensic analysis.
>
> This subsystem demonstrates skills in **policy-as-code enforcement**, **dictionary-based event grouping**, **network classification**, and **compliance-oriented detection**.

---

## Implementation Overview

The detector iterates over every `UnifiedEvent`, checking whether the source is internal, the destination is external, and the destination port is in the `DisallowedOutboundPorts` set. Matching events are grouped by `(SourceIP, DstPort)` in a dictionary, then each group produces a single high-severity finding with aggregated connection counts, distinct destination tallies, and the min/max time range across the group.

---

## Key Metrics

| Metric | Value |
|---|---|
| Test coverage | Unit-tested across policy ports, IP direction, and grouping behavior |
| Time complexity | O(n) — single pass, constant-time checks per event |
| Space complexity | O(k) — k = number of (SourceIP, DstPort) groups |
| Disallowed ports | 3 (21/FTP, 23/Telnet, 445/SMB) |
| State required | Dictionary grouping by (SourceIP, DstPort) |
| MITRE ATT&CK coverage | T1071, T1048, TA0010 |

---

## Why It Matters

- Outbound policy violations are **high-confidence indicators** of compromise — legitimate services rarely use FTP, Telnet, or outbound SMB
- Data exfiltration often uses **unusual protocols** precisely because security teams don't monitor them
- Compliance frameworks (PCI DSS, HIPAA, SOC 2) require monitoring and alerting on prohibited network flows
- The grouping design ensures **complete coverage** — every violation is captured, with aggregated counts for forensic context

---

## Key Evidence

- [PolicyViolationDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PolicyViolationDetector.cs) — filter-and-group implementation
- [IpClassification.cs](../../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — internal/external classification
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — disallowed port configuration
- [PolicyViolationDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PolicyViolationDetectorTests.cs) — test suite

---

## Key Design Choices

1. **Dictionary-based grouping by (SourceIP, DstPort)** — matching events are collected into groups for aggregated reporting
2. **One finding per group** — each `(SourceIP, DstPort)` pair produces a single finding with connection counts and distinct destination tallies
3. **HashSet for port lookup** — O(1) check on the hot path
4. **Internal-to-external scope only** — ignores inbound policy violations and internal traffic
5. **Profile-driven port list** — `DisallowedOutboundPorts` is fully configurable without code changes
