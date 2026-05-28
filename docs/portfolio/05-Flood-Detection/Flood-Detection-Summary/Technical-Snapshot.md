# Flood Detection — Technical Snapshot

> The flood detector identifies denial-of-service attacks by counting connection events per source IP within a sliding time window. In compact production C#, it transforms raw firewall logs into high-severity findings — flagging when a single IP generates 100–400+ events within 60 seconds, depending on the analysis profile. The implementation uses a two-pointer sliding window for O(n log n) efficiency, with focused test coverage validating threshold behavior, edge cases, and multi-source scenarios.
>
> This subsystem demonstrates skills in **time-series volume analysis**, **sliding-window algorithms**, **threshold-based anomaly detection**, and **profile-driven configuration**.

---

## Implementation Overview

The detector receives a pre-normalized `UnifiedEvent` list, groups events by source IP, sorts each group by timestamp, and runs a two-pointer sliding window counting events within `FloodWindowSeconds`. When the event count reaches `FloodMinEvents`, a finding is created; as long as the count stays above threshold, the same finding is extended. When the count drops below threshold, the finding is finalized. Separate time-separated bursts from the same source can produce separate findings.

---

## Key Metrics

| Metric | Value |
|---|---|
| Test coverage | Unit-tested across thresholds, burst behavior, and multi-source scenarios |
| Time complexity | O(n log n) per source (sort + linear scan) |
| Space complexity | O(n) per source |
| Configurable thresholds | 3 (Low / Medium / High) |
| Window duration | 60 seconds (all profiles) |
| MITRE ATT&CK coverage | T1498, T1499, TA0040 |

---

## Why It Matters

- Flood/DoS attacks are **among the most common** network attack categories, affecting availability of critical services
- Detection enables **rapid response** — blocking the source IP before downstream services are overwhelmed
- The sliding window approach correctly handles **bursty traffic patterns** — avoiding boundary artifacts that fixed-bin approaches suffer from
- Burst-aware design limits duplicate alerts from overlapping windows while capturing repeated attack episodes

---

## Key Evidence

- [FloodDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/FloodDetector.cs) — core detection logic with two-pointer window
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold configuration
- [FloodDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/FloodDetectorTests.cs) — comprehensive test suite

---

## Key Design Choices

1. **Two-pointer sliding window** — correctly handles temporal clustering without boundary artifacts
2. **Simple event counting** (not distinct hosts) — appropriate for DoS where volume, not variety, is the signal
3. **Burst-aware finding emission** — one finding per contiguous above-threshold burst; prevents duplicate findings from overlapping windows while capturing repeated episodes
4. **No IP classification filter** — floods can originate from both internal and external sources
5. **Profile-driven thresholds** — adjusts sensitivity from permissive (400 events) to aggressive (100 events)
