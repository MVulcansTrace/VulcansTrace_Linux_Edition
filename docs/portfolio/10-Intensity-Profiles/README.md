# Intensity Profiles

The intensity profile subsystem controls every detection threshold, feature toggle, and output filter in Vulcan's Trace — mapping three intensity levels (Low, Medium, High) to fully configured analysis profiles that determine what the engine detects, how sensitive each detector is, and which findings surface to the analyst.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Intensity-Profiles-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its design, and where the proof lives
- [Quick Reference](./Intensity-Profiles-Summary/Quick-Reference.md) — all thresholds, enable flags, and shared settings at a glance
- [Why This Matters](./Intensity-Profiles-In-Depth/Why-This-Matters.md) — the security problem profiles solve and the principles behind them
- [Profile Pipeline Algorithm](./Intensity-Profiles-In-Depth/Core-Logic-Breakdown/Profile-Pipeline-Algorithm.md) — step-by-step walkthrough of how intensity level becomes a live analysis profile
- [Design Decisions](./Intensity-Profiles-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Intensity-Profiles-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Intensity-Profiles-In-Depth/Attack-Scenario.md) — worked example showing how the same log produces different results across profiles
- [Evasion and Limitations](./Intensity-Profiles-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [Detection Coverage and Profile Tuning](./Intensity-Profiles-In-Depth/Detection-Coverage-and-Profile-Tuning.md) — capability mapping, detector coverage by profile, threshold comparison, and tuning guidance

## System Capabilities

- **Three-tier intensity model** — Low, Medium, and High profiles with progressively lower thresholds and more enabled detectors
- **13 detector enable flags** — granular control over which detectors run in each profile
- **Per-detector threshold tuning** — port scan, flood, lateral movement, beaconing, C2, and privilege escalation thresholds all vary by profile
- **Shared policy lists** — AdminPorts and DisallowedOutboundPorts are consistent across all profiles
- **Output shaping** — MinSeverityToShow gates which findings reach the analyst, then MaxFindingsPerDetector caps visible findings per category
- **Override support** — SentryAnalyzer accepts an optional custom profile for specialized analysis
- **Sealed record immutability** — AnalysisProfile is a sealed record with init-only properties, safe for concurrent reads

## Implementation Evidence

- [AnalysisProfile.cs](../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — sealed record with all config knobs
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — factory mapping IntensityLevel to AnalysisProfile
- [IntensityLevel.cs](../../../VulcansTrace.Linux.Engine/IntensityLevel.cs) — Low / Medium / High enum
- [SentryAnalyzer.cs](../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs) — orchestrator that resolves profile and runs all detectors
- [ProfileComparisonTests.cs](../../../VulcansTrace.Linux.Tests/Integration/ProfileComparisonTests.cs) — integration test comparing findings across profiles
