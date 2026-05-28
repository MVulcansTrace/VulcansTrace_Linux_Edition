# Policy Violation Detection

The policy violation detector flags internal hosts making outbound connections to external destinations on explicitly prohibited ports — catching data exfiltration attempts, unauthorized protocol usage, and compliance violations in a single pass.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Policy-Violation-Detection-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its design, and where the proof lives
- [Quick Reference](./Policy-Violation-Detection-Summary/Quick-Reference.md) — algorithm stages, configuration, output schema, and thresholds at a glance
- [Why This Matters](./Policy-Violation-Detection-In-Depth/Why-This-Matters.md) — the security problem this detector solves and the principles behind it
- [Detection Algorithm](./Policy-Violation-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md) — step-by-step walkthrough of the filter-and-group pipeline
- [Design Decisions](./Policy-Violation-Detection-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Policy-Violation-Detection-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Policy-Violation-Detection-In-Depth/Attack-Scenario.md) — worked example showing a policy violation being detected
- [Evasion and Limitations](./Policy-Violation-Detection-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [MITRE ATT&CK Mapping](./Policy-Violation-Detection-In-Depth/MITRE-ATTACK-Mapping.md) — technique and tactic mapping with detection gaps

## System Capabilities

- **Filter-and-group detection** — evaluates each event independently, then groups matching events by `(SourceIP, DstPort)` for aggregated reporting
- **Disallowed port enforcement** — flags connections on ports 21 (FTP), 23 (Telnet), and 445 (SMB) to external destinations
- **Internal-to-external scope** — only fires when an internal host connects outward, ignoring inbound and internal traffic
- **One finding per group** — each `(SourceIP, DstPort)` pair produces a single finding with connection counts and distinct destination tallies
- **HashSet-based port lookup** — O(1) membership check on the hot path

## Implementation Evidence

- [PolicyViolationDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/PolicyViolationDetector.cs) — filter-and-group policy violation detector (71 lines)
- [IpClassification.cs](../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — RFC 1918 internal/external classification (157 lines)
- [AnalysisProfile.cs](../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — disallowed port configuration (195 lines)
- [PolicyViolationDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PolicyViolationDetectorTests.cs) — baseline test coverage (138 lines)
