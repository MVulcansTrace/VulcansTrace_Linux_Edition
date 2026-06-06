# Technical Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **beaconing detection engine** for VulcansTrace Linux Edition that identifies command-and-control communication by analyzing the statistical regularity of public external network connections. It filters out non-public destinations, groups traffic by `(SourceIP, DestinationIP, DestinationPort)` channel, computes inter-arrival intervals, trims outliers symmetrically, and applies population standard deviation to distinguish automated C2-like behavior from human traffic.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Algorithm complexity | O(n log n) time, O(n) space |
| Pipeline steps | 9 (toggle, external filter/group, cap, events gate, duration gate, intervals, trim, mean-bounds, stdDev threshold) |
| Sensitivity profiles | Low / Medium / High presets |
| Default Medium std dev threshold | 5.0 seconds |
| C2 sweet spot (Medium) | 30s-900s mean interval (varies by profile: Low 60s-900s, High 10s-900s) |
| Configuration parameters | 8 per profile (1 toggle + 7 thresholds) |
| Test coverage | Unit coverage for timing gates, external filtering, trimming, sample caps, and format variants |
| Escalation | Time-correlated Beaconing + LateralMovement from same host -> participating findings become Critical; confidence recalculated via `FindingConfidenceCalculator` |

---

## Why It Matters

- Detects compromised hosts that are under active adversary control -- one of the highest-priority SOC signals
- Uses defensible statistics (population std dev) rather than heuristics
- Correlates with lateral movement findings for risk escalation
- Produces structured, explainable findings with quantitative evidence

---

## Key Evidence

- [BeaconingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/BeaconingDetector.cs): 9-step detection pipeline from tuple grouping through finding emission
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs): eight beaconing-specific configuration parameters (1 toggle + 7 thresholds) in an immutable record
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs): cross-correlation logic for Beaconing + LateralMovement escalation
- [BeaconingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/BeaconingDetectorTests.cs): regular beaconing, gating, trimming, sample-cap, mixed-traffic, and nftables format coverage

---

## Key Design Choices

- **External tuple-based grouping** so each public destination channel gets its own statistical verdict, preventing dilution from mixed traffic and reducing internal periodic false positives
- **Symmetric outlier trimming** so network jitter and occasional anomalies don't inflate std dev
- **Mean interval bounds** encoding domain knowledge -- C2 often lives in the 30-to-900-second sweet spot on Medium (60s-900s on Low, 10s-900s on High), screening out many very fast or very slow channels without semantically classifying them
- **Correlation-based escalation** -- Medium severity for uncorrelated beaconing (filtered from output on Low intensity), Critical when LateralMovement from the same host confirms active attack progression; confidence is recalculated via `FindingConfidenceCalculator` during escalation

---

## Security Takeaways

1. **Beaconing is a post-compromise signal** -- detecting it suggests the host may be under adversary control, making it one of the highest-priority alerts
2. **Statistical regularity is the fingerprint** -- automated tools produce timing patterns that standard deviation exposes reliably
3. **Correlation adds context** -- Beaconing + LateralMovement on the same host reflects real attack progression and warrants Critical severity; confidence is recalculated to reflect the combined evidence
4. **Interval bounds filter noise** -- the C2 sweet spot (30s-900s on the default Medium profile) screens out many very fast or very slow channels, but regular in-range software can still overlap; on the Low profile, uncorrelated beaconing is filtered from results entirely
5. **Documented limitations matter** -- jitter-tolerant malware can evade the std dev threshold, and compensating controls exist for that gap
