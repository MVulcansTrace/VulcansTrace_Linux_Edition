# Flood Detection

The flood detector identifies denial-of-service conditions by detecting source IPs generating an abnormally high volume of connection events within a short sliding time window.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Flood-Detection-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its design, and where the proof lives
- [Quick Reference](./Flood-Detection-Summary/Quick-Reference.md) — algorithm stages, configuration, output schema, and thresholds at a glance
- [Why This Matters](./Flood-Detection-In-Depth/Why-This-Matters.md) — the security problem this detector solves and the principles behind it
- [Detection Algorithm](./Flood-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md) — step-by-step walkthrough of the sliding-window pipeline
- [Design Decisions](./Flood-Detection-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Flood-Detection-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Flood-Detection-In-Depth/Attack-Scenario.md) — worked example showing a flood attack being detected
- [Evasion and Limitations](./Flood-Detection-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [MITRE ATT&CK Mapping](./Flood-Detection-In-Depth/MITRE-ATTACK-Mapping.md) — technique and tactic mapping with detection gaps

## System Capabilities

- **Per-source event counting** — groups events by source IP and measures volume within a sliding window
- **Two-pointer sliding window** — O(n log n) per source with linear-time window management
- **Profile-driven thresholds** — Low (400 events / 60s), Medium (200 events / 60s), High (100 events / 60s)
- **Burst-aware finding emission** — one finding per contiguous above-threshold burst; separate time-separated bursts from the same source produce separate findings
- **Cancellation-aware** — respects `CancellationToken` for responsive batch and UI operations

## Implementation Evidence

- [FloodDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/FloodDetector.cs) — sliding-window flood detector
- [AnalysisProfile.cs](../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold and enable-flag configuration record
- [FloodDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Baseline/FloodDetectorTests.cs) — baseline test coverage
