# Technical Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **C2 channel detection engine** for VulcansTrace Linux Edition that identifies command-and-control communication by clustering inter-arrival intervals using a greedy sliding window and looking for repeated patterns. It groups traffic by `{SourceIP}-{DestIP}:{DestPort}-{Protocol}` (deliberately excluding source port to catch ephemeral-port beaconing), computes consecutive time deltas, sorts them, clusters consecutive deltas within `tolerance * 2` into groups using the average as the interval, and reconstructs the pattern events to emit High-severity findings.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Algorithm complexity | O(n log n) time, O(n) space |
| Pipeline steps | 9 (toggle, guard, group, sort+deltas, cluster, min occurrences, interval range, reconstruct, min pattern events) |
| Sensitivity profiles | Disabled on Low, enabled on Medium / High |
| Default Medium tolerance | 5.0 seconds |
| C2 interval range (Medium) | 60s-1800s (Low: 120s-3600s, High: 30s-1800s) |
| Configuration parameters | 7 per profile (1 toggle + 6 thresholds) |
| Test coverage | 14 test methods in C2ChannelDetectorTests |
| Severity | High (emitted directly, no downstream escalation) |

---

## Why It Matters

- Detects compromised hosts that are under active adversary control using a complementary approach to the Beaconing detector
- Uses tolerance-based clustering instead of standard deviation -- catches patterns that vary within a tolerance window
- Excludes source port from grouping key to catch C2 channels that use ephemeral ports per connection
- Produces structured, explainable findings with interval and tolerance evidence

---

## Key Evidence

- [C2ChannelDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/C2ChannelDetector.cs): full 9-step detection pipeline from connection-key grouping through finding emission
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs): seven C2-specific configuration parameters (1 toggle + 6 thresholds) in an immutable record
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low (disabled), Medium, and High presets
- [C2ChannelDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/C2ChannelDetectorTests.cs): periodic pattern detection, disabled toggle, and no-pattern rejection coverage

---

## Key Design Choices

- **Source-port-excluded grouping** so C2 channels that rotate ephemeral ports per connection are still grouped together; Beaconing also excludes source port, while C2 additionally includes protocol in the grouping key
- **Tolerance-based clustering** using a greedy sliding window on sorted deltas (grouping consecutive values within `tolerance * 2`) to find natural interval clusters, catching patterns that vary slightly rather than requiring exact regularity
- **Pattern reconstruction** after bucket filtering -- the detector traces back from matching deltas to the original events, providing concrete evidence
- **High severity by default** because C2 channel detection indicates active adversary communication, warranting immediate attention
- **Disabled on Low profile** as a resource and noise trade-off -- Low profile focuses on the highest-confidence signals only

---

## Security Takeaways

1. **C2 channels are a post-compromise signal** -- detecting them means the host is already under adversary control, making it one of the highest-priority alerts
2. **Tolerance bucketization is the fingerprint** -- periodic communication that varies within a tolerance window is a strong indicator of automated C2
3. **Source port exclusion catches stealthier C2** -- many C2 frameworks use different ephemeral source ports per connection; excluding it from the grouping key prevents the pattern from being diluted
4. **High severity reflects urgency** -- unlike Beaconing (Medium), C2 channel findings start at High because the tolerance-based approach targets a more specific pattern
5. **Complementary to Beaconing** -- bucketization and std dev are different statistical lenses; together they provide broader C2 coverage
