# Port Scan Detection

The port scan detector identifies reconnaissance activity by grouping firewall events by source IP and flagging hosts that contact many distinct destination ports within a sliding time window.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Port-Scan-Detection-Summary/Technical-Snapshot.md) — one-page overview of the detector, its design, and where the proof lives
- [Quick Reference](./Port-Scan-Detection-Summary/Quick-Reference.md) — algorithm stages, configuration, output schema, and thresholds at a glance
- [Why This Matters](./Port-Scan-Detection-In-Depth/Why-This-Matters.md) — the security problem this detector solves and the principles behind it
- [Detection Algorithm](./Port-Scan-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md) — step-by-step walkthrough of the detection pipeline
- [Design Decisions](./Port-Scan-Detection-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Port-Scan-Detection-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Port-Scan-Detection-In-Depth/Attack-Scenario.md) — worked example showing a real port scan being detected
- [Evasion and Limitations](./Port-Scan-Detection-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [MITRE ATT&CK Mapping](./Port-Scan-Detection-In-Depth/MITRE-ATTACK-Mapping.md) — technique mapping and attack lifecycle context

## System Capabilities

- **Per-source grouping** — events are grouped by source IP, then ordered chronologically before analysis
- **Configurable thresholds** — minimum distinct ports and time window are set per analysis intensity profile (Low: 30 ports/5 min, Medium: 15 ports/5 min, High: 8 ports/5 min)
- **Optional truncation with warnings** — a `PortScanMaxEntriesPerSource` cap prevents unbounded memory growth and emits warnings when hit
- **Time-windowed detection** — distinct destination ports are counted within a sliding time window, isolating bursts from background noise without fixed-boundary splits
- **Cancellation-safe** — cooperative cancellation checks at every group iteration prevent runaway processing
- **Risk escalation integration** — when a source host produces correlated port scan and flag anomaly findings, the `RiskEscalator` escalates those participating findings to Critical severity

## Implementation Evidence

- [PortScanDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/PortScanDetector.cs) — detector implementation: grouping, truncation, windowing, and finding creation (133 lines)
- [AnalysisProfile.cs](../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — profile record with port scan threshold properties (195 lines)
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — intensity-based threshold presets (239 lines)
- [RiskEscalator.cs](../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) — correlates PortScan + FlagAnomaly to Critical severity (130 lines)
- [PortScanDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) — threshold boundary, multi-source, and property validation tests
