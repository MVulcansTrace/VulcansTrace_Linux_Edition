# Intensity Profiles — Why This Matters

## Security Problem

Security log analysis is a trade-off between coverage and noise. Run every detector at maximum sensitivity and analysts drown in findings — most of which are benign. Run only conservative detectors with high thresholds and sophisticated attacks slip through. The challenge is giving analysts a single, intuitive control that adjusts dozens of interdependent parameters in a coherent, tested way.

Without a profile system, every threshold is a separate configuration knob. An operator who lowers the port scan threshold from 30 to 15 ports must also consider whether beaconing, flood, and lateral movement thresholds should change proportionally. The cognitive load is enormous, the risk of misconfiguration is high, and reproducibility is lost.

Intensity profiles solve this by encoding expert tuning decisions into three named presets — Low, Medium, and High — that adjust every threshold, enable flag, and output filter as a coherent unit. The operator selects a single concept (sensitivity level) and the engine translates it into 20+ correctly balanced parameters.

---

## Implementation Overview

The profile subsystem consists of three files working together:

1. **IntensityLevel** — a three-valued enum (Low, Medium, High) representing the user-facing sensitivity concept
2. **AnalysisProfile** — a sealed record holding every configuration knob: 13 enable flags, 20+ thresholds, 2 policy lists, an output severity filter, and a per-category noise budget
3. **AnalysisProfileProvider** — a factory class with a single switch expression that maps each IntensityLevel to a fully populated AnalysisProfile

The `SentryAnalyzer` orchestrator resolves the profile once per analysis call (line 114: `overrideProfile ?? _profileProvider.GetProfile(intensity)`), then distributes it to all detectors and later uses it for output filtering and the noise budget. This ensures every detector reads from the same immutable configuration object for the duration of the detection run.

---

## Operational Benefits

| Benefit | Description |
|---|---|
| Single control point | One enum selection configures 20+ parameters coherently |
| Reproducible analysis | Same log + same intensity = identical results, every time |
| Progressive sensitivity | Low catches high-confidence threats only; Medium adds deep inspection; High enables everything |
| Analyst autonomy | Profile selection lets analysts trade coverage for noise without editing config files |
| Override support | Custom profiles enable specialized analysis without modifying the factory |
| Immutable during run | Sealed record prevents accidental mutation while detectors are executing |

---

## Security Principles Applied

| Principle | Application |
|---|---|
| Defense in depth | Three tiers provide layered detection — each tier adds detectors and lowers thresholds |
| Least privilege | Low profile reveals only high-confidence findings; more sensitive data requires explicit higher intensity |
| Separation of concerns | Profile resolution is independent of detection logic; detectors read but never modify profiles |
| Secure defaults | Low profile is conservative by default; operators must explicitly opt in to more aggressive analysis |
| Immutability | Sealed record with init-only properties prevents runtime mutation of detection parameters |

---

## Implementation Evidence

- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — sealed record with all config knobs
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — factory mapping
- [IntensityLevel.cs](../../../../VulcansTrace.Linux.Engine/IntensityLevel.cs) — enum definition
- [SentryAnalyzer.cs](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs) — profile resolution and distribution

---

> **Elevator Pitch:** Intensity profiles are the single knob that turns a raw detection engine into an analyst-friendly tool. One selection — Low, Medium, or High — configures 14 detectors, 20+ thresholds, an output filter, and the noise budget into a coherent, tested, reproducible analysis strategy. It's the difference between "configure 30 parameters correctly" and "pick a sensitivity level."

---

## Security Takeaways

- Profiles encode expert tuning knowledge into tested presets, eliminating operator misconfiguration risk
- The three-tier model (Low / Medium / High) maps to operational realities: triage, investigation, and deep forensic analysis
- MinSeverityToShow decouples detection sensitivity from output visibility — detectors can run at full sensitivity while the output filter gates what analysts see
- The sealed record model guarantees that once resolved, the profile cannot be mutated by any detector during analysis
- Override support enables specialized analysis without forking the codebase or modifying tested presets
