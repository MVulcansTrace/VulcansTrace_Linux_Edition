# Beaconing Detection

This folder contains technical documentation for the beaconing detection engine.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the algorithm, trade-offs, and implementation details

## Start Here

- [Technical Snapshot](./Beaconing-Detection-Summary/Technical-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Beaconing-Detection-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Detection Algorithm](./Beaconing-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md): the core detection pipeline and its trade-offs
- [Design Decisions](./Beaconing-Detection-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./Beaconing-Detection-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Beaconing-Detection-In-Depth/Attack-Scenario.md): a worked example showing the detector catching a synthetic C2-like beaconing pattern
- [Evasion and Limitations](./Beaconing-Detection-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [MITRE ATT&CK Mapping](./Beaconing-Detection-In-Depth/MITRE-ATTACK-Mapping.md): mapping to the ATT&CK framework

## System Capabilities

- Detection engineering: translating timing analysis into actionable C2 beaconing findings
- Statistical reasoning: applying population standard deviation with outlier trimming to identify automated behavior
- Security judgment: choosing severity, thresholds, and escalation rules with analyst workflow in mind
- Trade-off awareness: balancing detection sensitivity, false-positive risk, and resource constraints

## Implementation Evidence

- [BeaconingDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/BeaconingDetector.cs): tuple grouping, interval computation, outlier trimming, statistical thresholds, and finding creation
- [AnalysisProfile.cs](../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs): detector configuration model with eight beaconing-specific parameters (1 toggle + 7 thresholds)
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High profiles
- [RiskEscalator.cs](../../../VulcansTrace.Linux.Engine/RiskEscalator.cs): cross-detector correlation that escalates to Critical when Beaconing + LateralMovement co-occur on the same host
- [BeaconingDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Baseline/BeaconingDetectorTests.cs): happy path, irregular intervals, gating, trimming, sample cap, mixed-traffic, and nftables format coverage
- [ProfileComparisonTests.cs](../../../VulcansTrace.Linux.Tests/Integration/ProfileComparisonTests.cs): end-to-end analysis across all three intensity levels
