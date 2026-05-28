# C2 Channel Detection

This folder contains technical documentation for the C2 channel detection engine.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the algorithm, trade-offs, and implementation details

## Start Here

- [Technical Snapshot](./C2-Channel-Detection-Summary/Technical-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./C2-Channel-Detection-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Detection Algorithm](./C2-Channel-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md): the core detection pipeline and its trade-offs
- [Design Decisions](./C2-Channel-Detection-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./C2-Channel-Detection-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./C2-Channel-Detection-In-Depth/Attack-Scenario.md): a worked example showing the detector catching a synthetic C2 channel pattern
- [Evasion and Limitations](./C2-Channel-Detection-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [MITRE ATT&CK Mapping](./C2-Channel-Detection-In-Depth/MITRE-ATTACK-Mapping.md): mapping to the ATT&CK framework

## System Capabilities

- Detection engineering: translating tolerance-based interval clustering into actionable C2 channel findings
- Statistical reasoning: applying greedy delta clustering with configurable tolerance to identify periodic communication patterns
- Security judgment: choosing severity, thresholds, and interval bounds with analyst workflow in mind
- Trade-off awareness: balancing detection sensitivity, false-positive risk, and resource constraints

## Implementation Evidence

- [C2ChannelDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/C2ChannelDetector.cs): connection-key grouping, interval clustering, pattern reconstruction, and finding creation
- [AnalysisProfile.cs](../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs): detector configuration model with seven C2-specific parameters (1 toggle + 6 thresholds)
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low (disabled), Medium, and High profiles
- [C2ChannelDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/C2ChannelDetectorTests.cs): periodic pattern detection, disabled toggle, and no-pattern rejection coverage
