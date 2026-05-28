# Lateral Movement Detection

The lateral movement detector identifies internal hosts rapidly connecting to multiple other internal hosts on administrative ports within a sliding time window — a hallmark of post-compromise network traversal.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Lateral-Movement-Detection-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its design, and where the proof lives
- [Quick Reference](./Lateral-Movement-Detection-Summary/Quick-Reference.md) — algorithm stages, configuration, output schema, and thresholds at a glance
- [Why This Matters](./Lateral-Movement-Detection-In-Depth/Why-This-Matters.md) — the security problem this detector solves and the principles behind it
- [Detection Algorithm](./Lateral-Movement-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md) — step-by-step walkthrough of the sliding-window pipeline
- [Design Decisions](./Lateral-Movement-Detection-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Lateral-Movement-Detection-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Lateral-Movement-Detection-In-Depth/Attack-Scenario.md) — worked example showing a lateral movement attack being detected
- [Evasion and Limitations](./Lateral-Movement-Detection-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [MITRE ATT&CK Mapping](./Lateral-Movement-Detection-In-Depth/MITRE-ATTACK-Mapping.md) — technique and tactic mapping with detection gaps

## System Capabilities

- **Internal-to-internal filtering** — only considers connections originating from and destined to internal addresses (RFC 1918 and IPv6 private ranges), eliminating internet noise
- **Admin port focus** — targets SMB (445), RDP (3389), and SSH (22) where lateral pivoting actually occurs
- **Two-pointer sliding window** — O(n log n) per source (sort dominates; sliding distinct counting is O(n)) that counts distinct destination hosts within a configurable time window
- **Profile-driven thresholds** — Low (6 hosts / 10 min), Medium (4 hosts / 10 min), High (3 hosts / 10 min) to match operational risk tolerance
- **Burst-aware finding emission** — one finding per contiguous above-threshold burst; separate time-separated bursts from the same source produce separate findings

## Implementation Evidence

- [LateralMovementDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/LateralMovementDetector.cs) — sliding-window lateral movement detector (120 lines)
- [IpClassification.cs](../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — RFC 1918 and IPv6 ULA internal/external classification (157 lines)
- [AnalysisProfile.cs](../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold and enable-flag configuration record (195 lines)
- [LateralMovementDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Baseline/LateralMovementDetectorTests.cs) — baseline test coverage (687 lines)
