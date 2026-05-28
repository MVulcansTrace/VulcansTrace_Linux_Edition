# Attack Scenario: Catching a C2 Channel with Ephemeral Ports

---

## The Attack

A compromised internal host (`192.168.1.100`) calls back to an attacker-controlled server (`10.0.0.50`) on port 443 every 30 seconds. Each connection uses a different ephemeral source port:

```
2024-01-15 10:00:00 ALLOW TCP 192.168.1.100:51001 10.0.0.50:443 SEND
2024-01-15 10:00:30 ALLOW TCP 192.168.1.100:51002 10.0.0.50:443 SEND
2024-01-15 10:01:00 ALLOW TCP 192.168.1.100:51003 10.0.0.50:443 SEND
2024-01-15 10:01:30 ALLOW TCP 192.168.1.100:51004 10.0.0.50:443 SEND
2024-01-15 10:02:00 ALLOW TCP 192.168.1.100:51005 10.0.0.50:443 SEND
```

**5 connections, 30 seconds apart, spanning 2 minutes.** Each uses a different source port -- a common C2 evasion technique.

---

## Detection Walkthrough (Medium Profile)

| Step | Action | Result |
|------|--------|--------|
| **A: Toggle** | EnableC2Detection = true | Proceed |
| **B: Tolerance Guard** | C2ToleranceSeconds = 5.0 > 0 | Proceed |
| **C: Group** | Group by `{192.168.1.100-10.0.0.50:443-TCP}` | 5 entries (source port ignored) |
| **D: Sort + Deltas** | Chronological sort; compute gaps | Deltas = [30, 30, 30, 30] |
| **E: Cluster** | Sort deltas; group within 10s span (tolerance*2) | Cluster 30: count = 4 |
| **F: Min Occurrences** | 4 >= 3 (Medium) | Proceed |
| **G: Interval Range** | 30s... wait: 30 < 60 (C2MinIntervalSeconds on Medium) | **SKIPPED** |

**This beacon at 30-second intervals is too fast for the Medium profile**, which requires intervals of at least 60 seconds. Let's switch to the High profile:

---

## Detection Walkthrough (High Profile)

| Step | Action | Result |
|------|--------|--------|
| **A: Toggle** | EnableC2Detection = true | Proceed |
| **B: Tolerance Guard** | C2ToleranceSeconds = 8.0 > 0 | Proceed |
| **C: Group** | Group by `{192.168.1.100-10.0.0.50:443-TCP}` | 5 entries |
| **D: Sort + Deltas** | Chronological sort; compute gaps | Deltas = [30, 30, 30, 30] |
| **E: Cluster** | Sort deltas; group within 16s span (tolerance*2) | Cluster 30: count = 4 |
| **F: Min Occurrences** | 4 >= 2 (High) | Proceed |
| **G: Interval Range** | 30s in [30, 1800] | Proceed |
| **H: Reconstruct** | All 4 deltas match -> 5 events | patternEvents.Count = 5 |
| **I: Min Pattern Events** | 5 >= 4 (High) | **C2 CHANNEL DETECTED** |

---

## The Finding

```csharp
new Finding
{
    Category = FindingCategories.C2Channel,
    Severity = Core.Severity.High,
    SourceHost = "192.168.1.100",
    Target = "10.0.0.50:443",
    TimeRangeStart = new DateTime(2024, 1, 15, 10, 0, 0),
    TimeRangeEnd = new DateTime(2024, 1, 15, 10, 2, 0),
    ShortDescription = "Potential C2 channel detected: 192.168.1.100-10.0.0.50:443-TCP",
    Details = "Detected 5 events with approximately 30s intervals (tolerance: +/-8s). This pattern suggests periodic communication that may indicate a C2 channel."
}
```

---

## Why the Beaconing Detector Might Miss This

With only 5 events, the Beaconing detector on the High profile requires at least 4 events (`BeaconMinEvents = 4`), so this pattern would pass the minimum events gate. However:

- If even one interval deviated significantly (e.g., a 45-second gap), the std dev would increase
- Like the C2 Channel detector, Beaconing excludes source port from its grouping key; C2 Channel additionally includes protocol
- The key difference is the **statistical method**: Beaconing measures overall spread (std dev), while C2 Channel measures clustering (bucketization)

The C2 Channel detector provides **complementary coverage** -- it catches patterns based on interval clustering that may not survive the std dev threshold.

---

## Profile Sensitivity

| Profile | Tolerance | Min Interval | Min Occurrences | Min Pattern Events | This Beacon |
|---------|-----------|-------------|----------------|-------------------|-------------|
| Low | 10s | 120s | 5 | 10 | **Disabled** (EnableC2Detection = false) |
| Medium | 5s | 60s | 3 | 6 | **Too fast** (30s < 60s min interval) |
| High | 8s | 30s | 2 | 4 | **DETECTED** (5 events >= 4) |

This illustrates the profile gradient: the same 30-second beacon is invisible at Low (disabled), filtered at Medium (below min interval), and caught at High (all gates pass).

---

## Implementation Evidence

- [C2ChannelDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/C2ChannelDetector.cs): the full 9-step pipeline
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs): Low, Medium, and High profile thresholds
- [C2ChannelDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/C2ChannelDetectorTests.cs): test method `C2ChannelDetector_Detect_WithPeriodicPattern_FindsC2Channel` covers a similar periodic pattern (5 events, 30s intervals)

---

## Security Takeaways

1. **C2 channels are a post-compromise signal** -- detecting them means the host is already under adversary control, making it one of the highest-priority alerts
2. **Tolerance bucketization is the fingerprint** -- periodic communication that varies within a tolerance window is a strong indicator of automated C2
3. **Source port exclusion catches stealthier C2** -- many C2 frameworks use different ephemeral source ports per connection; excluding it from the grouping key prevents the pattern from being diluted
4. **High severity reflects urgency** -- unlike Beaconing (Medium), C2 channel findings start at High because the tolerance-based approach targets a more specific pattern
5. **Complementary to Beaconing** -- bucketization and std dev are different statistical lenses; together they provide broader C2 coverage
