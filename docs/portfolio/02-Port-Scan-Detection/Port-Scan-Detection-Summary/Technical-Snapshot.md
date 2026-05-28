# Technical Snapshot: Port Scan Detection

> The port scan detector groups normalized firewall events by source IP, applies optional truncation with warnings, scans sliding time windows, and flags hosts that contact more distinct destination ports than a configurable threshold within a window. It implements `IDetector`, is cancellation-safe, and integrates with the `RiskEscalator` for correlated threat escalation.

---

## Implementation Overview

The detector operates on the unified event stream produced by the log normalization pipeline. Each event carries a source IP, destination IP, destination port, and timestamp. The detector groups by source IP, orders chronologically, optionally truncates per-source event counts to the latest events, and counts distinct destination ports within a sliding window. If the count meets or exceeds `PortScanMinPorts`, a Medium-severity finding is emitted.

---

## Key Metrics

| Metric | Value |
|---|---|
| Interfaces implemented | `IDetector` |
| Finding category | `PortScan` |
| Default severity | Medium |
| Threshold range | 8–30 distinct destination ports per window |
| Time window | 5 minutes (configurable) |
| Cancellation points | Outer per-source loop and inner sliding-window loop |
| Test coverage | Unit and integration coverage for thresholds, windows, truncation, and same-port false positives |
| Risk escalation | Time-correlated PortScan + FlagAnomaly findings escalate to Critical |

---

## Why It Matters

- Port scanning is the most common reconnaissance technique and appears in nearly every targeted attack
- Detecting scans early gives defenders a window to harden services before exploitation begins
- Time-windowed counting isolates aggressive sweeps from benign multi-port traffic
- Truncation with warnings ensures the detector remains performant even on heavily scanned networks
- The detector feeds the `RiskEscalator`, which escalates participating PortScan and FlagAnomaly findings to Critical severity when they are correlated

---

## Key Evidence

- [PortScanDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PortScanDetector.cs) — detector implementation
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold configuration record
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — intensity presets
- [PortScanDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) — test suite
- [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) — correlation escalation

---

## Key Design Choices

- **Sliding time window** — Start/end pointers track the active `PortScanWindowMinutes` span. This avoids fixed-boundary false negatives without O(n²) pairwise comparison.

- **Distinct destination-port counting** — Counting unique destination ports rather than raw event volume prevents a single noisy connection from inflating the signal. Repeated contacts to the same port across many hosts do not satisfy the port-scan threshold by themselves.

- **Optional truncation with warnings** — The `PortScanMaxEntriesPerSource` cap limits memory and CPU for sources that produce thousands of events. When truncation occurs, the detector emits a warning through `DetectionResult.Warnings` so analysts know data was dropped.

- **Guard check plus pre-window optimization gate** — The detector first checks `EnablePortScan` and empty input, then counts total distinct destination ports for a source before entering the sliding-window pass. If the total is below `PortScanMinPorts`, the source is skipped entirely, avoiding the cost of window analysis for low-activity sources.

- **Cooperative cancellation** — `ThrowIfCancellationRequested` is called in both the outer per-source loop and the inner per-window loop, allowing the analysis engine to cancel long-running scans without corrupting partial results.

---

## Security Takeaways

1. The detector addresses active reconnaissance (MITRE T1046), a prerequisite step in most network-based attacks
2. Time-windowed distinct-port counting balances sensitivity against false positives from repeated single-service traffic
3. The truncation-warning pattern maintains analyst visibility even when data volume forces approximations
4. Integration with `RiskEscalator` means port scans are not evaluated in isolation — when a host triggers correlated port scan and flag anomaly findings, those participating findings are escalated to Critical automatically
5. Profile-based thresholds allow defenders to tune sensitivity to their network baseline without code changes
