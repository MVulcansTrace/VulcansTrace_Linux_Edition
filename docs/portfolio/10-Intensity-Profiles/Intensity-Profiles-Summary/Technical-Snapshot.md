# Intensity Profiles — Technical Snapshot

> The intensity profile subsystem is the central nervous system of Vulcan's Trace. In the production profile code across the profile model, factory, enum, and analyzer, it maps a single user-facing concept — Low, Medium, or High sensitivity — into a fully configured analysis profile with 13 detector enable flags, 20+ threshold knobs, shared policy lists, an output severity filter, and a per-category finding cap. The sealed-record data model ensures immutability, the switch-expression factory provides exhaustive pattern matching, and the orchestrator resolves the profile once per analysis run — making every detection decision traceable to a single configuration object.
>
> This subsystem demonstrates skills in **configuration-driven architecture**, **sealed-record immutability**, **switch-expression exhaustive matching**, **defense-in-depth threshold tuning**, and **profile-aware feature toggling**.

---

## Implementation Overview

The `AnalysisProfile` sealed record holds every config knob: enable flags for 13 detectors, numeric thresholds for port scan, flood, lateral movement, beaconing, C2, and privilege escalation detection, plus shared policy lists (AdminPorts, DisallowedOutboundPorts), the output severity filter (MinSeverityToShow), and the per-category cap (MaxFindingsPerDetector). The `AnalysisProfileProvider` factory maps each `IntensityLevel` enum value to a fully populated profile via a switch expression. The `SentryAnalyzer` resolves the profile once per call (line 114), then passes it to every detector and later uses it for visibility filtering and finding caps.

---

## Key Metrics

| Metric | Value |
|---|---|
| Profile comparison coverage | Integration-tested across Low, Medium, and High |
| Detector enable flags | 13 |
| Numeric thresholds | 20+ |
| Shared policy lists | 2 (AdminPorts, DisallowedOutboundPorts) |
| Intensity levels | 3 (Low, Medium, High) |
| Profile resolution | O(1) — single switch expression |

---

## Why It Matters

- **Single source of truth** — every detection threshold originates from one profile object, making analysis reproducible
- **Progressive sensitivity** — Low catches only high-confidence threats; Medium adds deep inspection; High enables everything with aggressive thresholds
- **Analyst control** — profile selection lets analysts trade coverage for noise based on operational context
- **Override support** — custom profiles enable specialized analysis without modifying the factory
- **Immutable configuration** — sealed record with init-only properties prevents accidental mutation during analysis

---

## Key Evidence

- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — sealed record with all config knobs
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — factory mapping
- [IntensityLevel.cs](../../../../VulcansTrace.Linux.Engine/IntensityLevel.cs) — enum definition
- [SentryAnalyzer.cs](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs) — profile resolution and detector orchestration
- [ProfileComparisonTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/ProfileComparisonTests.cs) — cross-profile integration test

---

## Key Design Choices

1. **Sealed record over class** — guarantees immutability and value-based equality; `with` expressions create modified copies safely
2. **Switch expression over if/else chain** — compiler enforces exhaustive matching; adding a new IntensityLevel triggers a compile error until handled
3. **Shared policy lists across profiles** — AdminPorts and DisallowedOutboundPorts are identical in all three profiles, ensuring consistent policy enforcement
4. **MinSeverityToShow as output filter** — decouples detection sensitivity from result visibility; Low profile still runs detectors but only shows High-severity findings
5. **Override profile parameter** — SentryAnalyzer accepts an optional `overrideProfile` so operators can inject custom thresholds without modifying the factory
6. **Detector enable flags over conditional thresholds** — disabling a detector (e.g., EnableNovelty = false in Low) is cleaner than setting its threshold to infinity
