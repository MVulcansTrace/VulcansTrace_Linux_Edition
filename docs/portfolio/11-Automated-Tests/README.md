# Automated Tests

The test suite validates every stage of the VulcansTrace analysis pipeline — from log parsing and normalization through detector logic, evidence packaging, risk escalation, and the Avalonia UI — using xUnit with 40+ test files across unit, integration, and scenario-based categories.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Automated-Tests-Summary/Technical-Snapshot.md) — one-page overview of the test suite, its design, and where the proof lives
- [Quick Reference](./Automated-Tests-Summary/Quick-Reference.md) — test structure, categories, commands, and assertions at a glance
- [Why This Matters](./Automated-Tests-In-Depth/Why-This-Matters.md) — the quality problem this test suite solves and the principles behind it
- [Testing Algorithm](./Automated-Tests-In-Depth/Core-Logic-Breakdown/Testing-Algorithm.md) — step-by-step walkthrough of how tests are organized and executed
- [Design Decisions](./Automated-Tests-In-Depth/Design-Decisions.md) — rationale for key architectural choices in the test suite
- [Code Patterns](./Automated-Tests-In-Depth/Code-Patterns.md) — recurring test implementation patterns and how they support reliability
- [Attack Scenario](./Automated-Tests-In-Depth/Attack-Scenario.md) — worked example showing a test catching a real attack pattern
- [Evasion and Limitations](./Automated-Tests-In-Depth/Evasion-and-Limitations.md) — known testing gaps and the improvement roadmap
- [Test Coverage by Threat Behavior](./Automated-Tests-In-Depth/Test-Coverage-by-Threat-Behavior.md) — capability mapping, threat behavior coverage matrix, and verification procedures

## System Capabilities

- **Full pipeline coverage** — tests span Core (parsing, normalization, events, compliance models), Detectors (baseline, Linux-specific, advanced), Evidence (formatters, integrity, compliance scorecard), Integration (orchestration, real logs, performance), and Avalonia (ViewModels)
- **Synthetic scenario generation** — `LogScenarioBuilder` produces realistic iptables log entries for port scans, beaconing, floods, and lateral movement
- **Real-world log fixtures** — sample attack logs (`iptables-attack.log`, `nftables-traffic.log`, `large-portscan.log`, `iptables-mixed-prefixes.log`, `golden-compromise-timeline.log`) validate against actual firewall output
- **Boundary testing** — detector tests probe exact threshold boundaries (at-threshold, just-below, well-above) to verify detection edges
- **Integration testing** — `SentryAnalyzerTests` exercises the complete pipeline from raw log text through all detector layers to final `AnalysisResult`
- **Log Diff testing** — `LogDiffAnalyzerTests` verifies baseline-vs-incident event and finding comparison, source-port wildcard matching, count thresholds, action shifts, and deduplication behavior; `LogDiffViewModelTests` verifies result binding for the desktop window
- **Performance validation** — dedicated tests assert analysis completes within time bounds on large inputs

## Implementation Evidence

- [UnifiedEventTests.cs](../../../VulcansTrace.Linux.Tests/Core/UnifiedEventTests.cs) — event construction, connection key, IP validation
- [LinuxIptablesParserTests.cs](../../../VulcansTrace.Linux.Tests/Core/LinuxIptablesParserTests.cs) — iptables field extraction and edge cases
- [LinuxNftablesParserTests.cs](../../../VulcansTrace.Linux.Tests/Core/LinuxNftablesParserTests.cs) — nftables field extraction and action derivation
- [LogNormalizerTests.cs](../../../VulcansTrace.Linux.Tests/Core/LogNormalizerTests.cs) — format detection and normalization pipeline
- [PortScanDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) — threshold boundary, multi-source, and property validation tests
- [SentryAnalyzerTests.cs](../../../VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs) — full-pipeline integration tests
- [RealWorldAttackScenarioTests.cs](../../../VulcansTrace.Linux.Tests/Integration/RealWorldAttackScenarioTests.cs) — attack scenario tests
- [EvidenceBuilderTests.cs](../../../VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs) — evidence package integrity tests
- [ComplianceScorecardBuilderTests.cs](../../../VulcansTrace.Linux.Tests/Agent/ComplianceScorecardBuilderTests.cs) — compliance scorecard computation tests
- [ComplianceScorecardFormatterTests.cs](../../../VulcansTrace.Linux.Tests/Evidence/ComplianceScorecardFormatterTests.cs) — compliance scorecard HTML and Markdown formatter tests
- [LogScenarioBuilder.cs](../../../VulcansTrace.Linux.Tests/Helpers/LogScenarioBuilder.cs) — synthetic log generator helper
