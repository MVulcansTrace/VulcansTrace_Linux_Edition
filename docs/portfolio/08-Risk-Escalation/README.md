# Risk Escalation

The risk escalation subsystem takes individual detector findings and applies host-scoped correlation rules to escalate severity when multiple threat indicators point to the same compromised host.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Risk-Escalation-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its design, and where the proof lives
- [Quick Reference](./Risk-Escalation-Summary/Quick-Reference.md) — pipeline stages, correlation rules, severity levels, and key types at a glance
- [Why This Matters](./Risk-Escalation-In-Depth/Why-This-Matters.md) — the security problem this subsystem solves and the principles behind it
- [Correlation Algorithm](./Risk-Escalation-In-Depth/Core-Logic-Breakdown/Correlation-Algorithm.md) — step-by-step walkthrough of the escalation logic
- [Design Decisions](./Risk-Escalation-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Risk-Escalation-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Risk-Escalation-In-Depth/Attack-Scenario.md) — worked example showing correlated findings being escalated
- [Evasion and Limitations](./Risk-Escalation-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [MITRE ATT&CK Mapping](./Risk-Escalation-In-Depth/MITRE-ATTACK-Mapping.md) — how correlation rules map to the MITRE ATT&CK framework

## System Capabilities

- **Host-scoped correlation** — groups findings by source host so that cross-category escalation only fires when indicators share the same attacker origin
- **Three correlation rules** — Beaconing + LateralMovement, FlagAnomaly + PortScan, MacSpoofing + InterfaceHopping each escalate to Critical
- **Immutable escalation** — original findings are never mutated; escalated copies are produced via C# `with` expressions on the `Finding` record
- **Pipeline orchestration** — `SentryAnalyzer` coordinates normalization, three detection layers with fault isolation, escalation, Beaconing/C2 deduplication, severity filtering, and finding caps in a single pass
- **Fault isolation** — each detector is wrapped in a try/catch so a crash in one detector cannot prevent escalation of findings from other detectors

## Implementation Evidence

- [RiskEscalator.cs](../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) — correlated severity escalation
- [SentryAnalyzer.cs](../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs) — full pipeline orchestration with three detection layers and fault isolation
- [AnalysisProfile.cs](../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — `MinSeverityToShow` and detector enable flags that gate escalation output
- [Finding.cs](../../../VulcansTrace.Linux.Core/Finding.cs) — immutable record that supports the `with` expression used during escalation
- [Severity.cs](../../../VulcansTrace.Linux.Core/Severity.cs) — five-level enum: Info, Low, Medium, High, Critical
- [SentryAnalyzerTests.cs](../../../VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs) — integration tests covering the full pipeline including escalation
- [RealWorldAttackScenarioTests.cs](../../../VulcansTrace.Linux.Tests/Integration/RealWorldAttackScenarioTests.cs) — real-world attack scenario tests validating end-to-end detection and escalation
