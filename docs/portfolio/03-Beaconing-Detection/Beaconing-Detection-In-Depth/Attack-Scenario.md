# Attack Scenario: Catching a C2 Beacon

---

## The Attack

A compromised internal host (`192.168.1.100`) calls back to an attacker-controlled public server (`8.8.8.8`) on port 8080 every 60 seconds:

```
2024-01-15 10:00:00 ALLOW TCP 192.168.1.100 8.8.8.8 51001 8080 SEND
2024-01-15 10:01:00 ALLOW TCP 192.168.1.100 8.8.8.8 51002 8080 SEND
2024-01-15 10:02:00 ALLOW TCP 192.168.1.100 8.8.8.8 51003 8080 SEND
2024-01-15 10:03:00 ALLOW TCP 192.168.1.100 8.8.8.8 51004 8080 SEND
2024-01-15 10:04:00 ALLOW TCP 192.168.1.100 8.8.8.8 51005 8080 SEND
2024-01-15 10:05:00 ALLOW TCP 192.168.1.100 8.8.8.8 51006 8080 SEND
2024-01-15 10:06:00 ALLOW TCP 192.168.1.100 8.8.8.8 51007 8080 SEND
2024-01-15 10:07:00 ALLOW TCP 192.168.1.100 8.8.8.8 51008 8080 SEND
2024-01-15 10:08:00 ALLOW TCP 192.168.1.100 8.8.8.8 51009 8080 SEND
2024-01-15 10:09:00 ALLOW TCP 192.168.1.100 8.8.8.8 51010 8080 SEND
```

**10 connections, 60 seconds apart, spanning 9 minutes.** Perfect metronome -- the hallmark of automated C2 beaconing.

---

## Detection Walkthrough

| Step | Action | Result |
|------|--------|--------|
| **A: Toggle** | EnableBeaconing = true | Proceed |
| **B: Filter + Group** | Destination is public; group by (192.168.1.100, 8.8.8.8, 8080) | 10 entries |
| **C: Order + Cap** | Sort chronologically; 10 < 200 max | All samples kept |
| **D: Min Events** | 10 >= 6 (Medium) | Proceed |
| **E: Min Duration** | 540s >= 120s | Proceed |
| **F: Intervals** | Compute consecutive gaps | [60, 60, 60, 60, 60, 60, 60, 60, 60] |
| **G: Trim** | Sort intervals -> trim 10% from each end | Remove 1 from each end of sorted array -> [60, 60, 60, 60, 60, 60, 60] |
| **H: Mean Bounds** | Mean = 60s (in 30-900 range) | Proceed |
| **I: StdDev Gate** | StdDev = 0.0 (<= 5.0) | **BEACON DETECTED** |

---

## The Finding

```csharp
new Finding
{
    Category = FindingCategories.Beaconing,
    Severity = Core.Severity.Medium,
    SourceHost = "192.168.1.100",
    Target = "8.8.8.8:8080",
    TimeRangeStart = new DateTime(2024, 1, 15, 10, 0, 0),
    TimeRangeEnd = new DateTime(2024, 1, 15, 10, 9, 0),
    ShortDescription = "Regular beaconing from 192.168.1.100",
    Details = "Average interval ~60.0s, std dev ~0.0s over 10 events."
}
```

---

## Escalation: What Happens When Lateral Movement Appears

If the same host (`192.168.1.100`) also shows time-correlated lateral movement findings, RiskEscalator raises the participating Beaconing and LateralMovement findings to Critical:

| Scenario | Severity | Rationale |
|----------|----------|-----------|
| Beaconing only | Medium | Compromised host, contained scope |
| Beaconing + LateralMovement | Critical | Compromised host actively probing the network |

---

## Profile Sensitivity

| Profile | StdDev Threshold | Min Events | Min Interval | Min Severity to Show | This Beacon (stdDev = 0, mean = 60s) | Detector Result | User-Visible? |
|---------|-----------------|------------|--------------|---------------------|--------------------------------------|-----------------|---------------|
| Low | 3.0 | 8 | 60s | High | 0.0 <= 3.0, 10 >= 8, mean 60 >= 60 (boundary) | **DETECTED** | No -- Medium < High threshold |
| Medium | 5.0 | 6 | 30s | Medium | 0.0 <= 5.0, 10 >= 6, mean 60 in 30-900 | **DETECTED** | Yes |
| High | 8.0 | 4 | 10s | Info | 0.0 <= 8.0, 10 >= 4, mean 60 in 10-900 | **DETECTED** | Yes |

This perfect beacon triggers the detector on all profiles. However, on the Low profile, `MinSeverityToShow = High` filters out Medium-severity Beaconing findings before they reach the user. Only if the finding is escalated to Critical (via correlated LateralMovement) would it appear in Low-profile output. A beacon with mean interval below 60s would fail the Low profile's `MinIntervalSeconds` gate entirely.

Jitter-tolerant malware that adds random delays would produce higher std dev and may evade Low but not High.

---

## Implementation Evidence

- [BeaconingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/BeaconingDetector.cs): the full detection pipeline
- [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs): Beaconing + LateralMovement escalation to Critical
- [BeaconingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/BeaconingDetectorTests.cs): test method `Detect_BeaconingRegularIntervals_ReturnsFinding` covers an equivalent beaconing pattern (same count and interval)

---

## Security Takeaways

1. **Beaconing is a post-compromise signal** -- detecting it suggests the host may be under adversary control, making it one of the highest-priority alerts
2. **Statistical regularity is the fingerprint** -- automated tools produce timing patterns that standard deviation exposes reliably
3. **Correlation adds context** -- Beaconing + LateralMovement on the same host reflects real attack progression and warrants Critical severity
4. **Interval bounds filter noise** -- the C2 sweet spot (30s-900s on the default Medium profile) screens out many very fast or very slow channels, but regular in-range software can still overlap; on the Low profile, uncorrelated beaconing is filtered from results entirely
5. **Documented limitations matter** -- jitter-tolerant malware can evade the std dev threshold, and compensating controls exist for that gap
