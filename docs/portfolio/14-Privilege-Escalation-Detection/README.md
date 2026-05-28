# Privilege Escalation Detection

The privilege escalation detector identifies potential privilege escalation indicators by monitoring for suspicious admin access patterns — rapid-fire attempts against administrative ports and sweeps across multiple admin services within short time windows.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Privilege-Escalation-Detection-Summary/Technical-Snapshot.md) — one-page overview of the detector, its design, and where the proof lives
- [Quick Reference](./Privilege-Escalation-Detection-Summary/Quick-Reference.md) — algorithm stages, configuration, output schema, and thresholds at a glance
- [Why This Matters](./Privilege-Escalation-Detection-In-Depth/Why-This-Matters.md) — the security problem this detector solves and the principles behind it
- [Detection Algorithm](./Privilege-Escalation-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md) — step-by-step walkthrough of the detection pipeline
- [Design Decisions](./Privilege-Escalation-Detection-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Privilege-Escalation-Detection-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Privilege-Escalation-Detection-In-Depth/Attack-Scenario.md) — worked example showing a real escalation attack being detected
- [Evasion and Limitations](./Privilege-Escalation-Detection-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [MITRE ATT&CK Mapping](./Privilege-Escalation-Detection-In-Depth/MITRE-ATTACK-Mapping.md) — technique mapping and attack lifecycle context

## System Capabilities

- **Per-source grouping** — events targeting admin ports are grouped by source IP, then ordered chronologically before analysis
- **Dual detection modes** — `DetectAdminSpikes` flags high-volume brute-force-style bursts (>= 5 attempts/window), while `DetectAdminPortSweeps` flags multi-port service enumeration (>= 3 distinct admin ports/window)
- **Configurable time windows** — `PrivilegeSpikeWindowMinutes` adapts per analysis intensity profile (Low: 10/disabled, Medium: 5, High: 10)
- **Extensible admin port list** — a hardcoded baseline of 8 Linux-relevant admin ports is merged with any profile-supplied `AdminPorts`
- **Cancellation-safe** — cooperative cancellation checks at every group iteration prevent runaway processing
- **Profile-gated activation** — the detector is disabled entirely under the Low intensity profile

## Implementation Evidence

- [PrivilegeEscalationDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/PrivilegeEscalationDetector.cs) — detector implementation: dual sub-detectors, admin port filtering, and finding creation
- [AnalysisProfile.cs](../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — profile record with privilege escalation threshold properties
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — intensity-based threshold presets
- [PrivilegeEscalationDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/PrivilegeEscalationDetectorTests.cs) — spike detection, sweep detection, disabled-mode, and below-threshold tests
