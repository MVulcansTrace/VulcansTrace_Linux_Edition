# Detection Algorithm: Port Scan Detection

## The Security Problem

Attackers use port scanning to map a target network's exposed services before launching exploits. A single source IP contacting many different destination ports in a short period is a strong indicator of reconnaissance. The challenge is distinguishing this behavior from legitimate traffic — a web crawler, a monitoring system, or a user accessing multiple services simultaneously can all produce multi-port connection patterns.

The detector solves this by counting distinct destination ports per source IP within a sliding time window. A scan targeting 50 different ports in 3 minutes produces a distinct-port count far above normal traffic patterns, regardless of whether the connections succeeded or failed.

---

## Implementation Overview

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Guard check │────▶│  GroupBy        │────▶│  OrderBy         │────▶│  Truncate      │
│  EnablePort? │     │  SourceIP       │     │  Timestamp       │     │  (optional)    │
└──────────────┘     └─────────────────┘     └──────────────────┘     └────────────────┘
                                                                              │
                                                                              ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Emit Finding│◀────│  Count distinct │◀────│  Slide window    │◀────│  Pre-window    │
│  if >= min   │     │  ports          │     │  by timestamp    │     │  gate          │
└──────────────┘     └─────────────────┘     └──────────────────┘     └────────────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnablePortScan || events.Count == 0)
    return DetectionResult.Empty;
```

The detector exits immediately if port scan detection is disabled or there are no events to analyze. This avoids allocating the heavier analysis data structures (grouped collections, sorted lists, findings) that the main loop would require.

---

### Step B — Group by Source IP

```csharp
var bySrc = events.GroupBy(e => e.SourceIP);
foreach (var srcGroup in bySrc)
```

Events are grouped by `SourceIP` because a port scan is defined per-scanner. Each source is analyzed independently.

---

### Step C — Order Chronologically and Truncate

```csharp
var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
if (profile.PortScanMaxEntriesPerSource is { } maxEntries && maxEntries > 0 && ordered.Count > maxEntries)
{
    ordered = ordered.TakeLast(maxEntries).ToList();
    warnings.Add($"Port scan analysis for {srcIp} truncated to {maxEntries} events out of {totalForSource}.");
}
```

Events within each source group are sorted by timestamp. If `PortScanMaxEntriesPerSource` is configured and the event count exceeds it, the list is truncated to the latest N entries and a warning is emitted. This bounds memory and CPU for sources under sustained attack while preserving the freshest evidence.

---

### Step D — Pre-Window Gate

```csharp
var distinctPortsForSource = ordered
    .Select(e => e.DestinationPort)
    .Distinct()
    .Count();

if (distinctPortsForSource < profile.PortScanMinPorts)
    continue;
```

Before the more expensive sliding-window pass, the detector checks whether the source IP contacted enough distinct destination ports across all analyzed events. If not, it skips to the next source. This avoids window computation for benign sources.

---

### Step E — Sliding Window Analysis

```csharp
var portCounts = new Dictionary<int, int>();
var distinctPorts = 0;
int start = 0;

for (int end = 0; end < ordered.Count; end++)
```

The detector advances an `end` pointer through the ordered events and keeps a `start` pointer at the beginning of the active window. As events enter and leave the window, a dictionary tracks how many events currently reference each destination port. This avoids fixed-boundary artifacts such as splitting a scan across 10:00 and 10:05 buckets.

---

### Step F — Count and Emit Finding

```csharp
if (distinctPorts >= profile.PortScanMinPorts)
{
    if (!inFinding)
    {
        peakDistinctPorts = distinctPorts;
        findings.Add(new Core.Finding
        {
            Category = "PortScan",
            Severity = Core.Severity.Medium,
            SourceHost = srcIp,
            Target = "multiple ports",
            TimeRangeStart = ordered[start].Timestamp,
            TimeRangeEnd = ordered[end].Timestamp,
            ShortDescription = $"Port scan detected from {srcIp}",
            Details = $"Detected {distinctPorts} distinct destination ports within {profile.PortScanWindowMinutes} minutes."
        });
        inFinding = true;
    }
    else if (distinctPorts > peakDistinctPorts)
    {
        peakDistinctPorts = distinctPorts;
    }
}
else if (inFinding)
{
    var idx = findings.Count - 1;
    findings[idx] = findings[idx] with
    {
        TimeRangeEnd = ordered[Math.Max(0, end - 1)].Timestamp,
        Details = $"Detected {peakDistinctPorts} distinct destination ports within {profile.PortScanWindowMinutes} minutes."
    };
    inFinding = false;
}
```

When the distinct-port count first meets or exceeds `PortScanMinPorts`, a finding is created. The detector tracks whether it is already `inFinding` so that overlapping windows above the threshold do not produce duplicate findings. As long as the count stays above the threshold, the same finding is extended. When the count drops below the threshold, the finding is finalized with the last valid timestamp and the peak distinct-port count seen during the burst. This produces **one finding per contiguous above-threshold burst** rather than one finding per window position.

> **Downstream visibility note:** Findings are emitted at `Severity.Medium`. The analysis engine applies severity filtering after risk escalation and before the per-category noise budget. On the **Low** intensity profile (`MinSeverityToShow = Severity.High`), uncorrelated PortScan findings are filtered from final results and will not be visible to the user. On **Medium** and **High** profiles, they appear normally. Additionally, if the same source IP also triggers a correlated `FlagAnomaly` finding, the `RiskEscalator` promotes the participating PortScan and FlagAnomaly findings to `Severity.Critical`, which passes all profile filters.

---

## Complexity And Behavior

| Aspect | Behavior | Rationale |
|---|---|---|
| Time complexity | O(N log N) per source | Dominated by `OrderBy` on timestamp |
| Pre-window gate | Skips sources with too few distinct destination ports | Avoids unnecessary window computation |
| Window alignment | Sliding window over event timestamps | Avoids fixed-boundary false negatives |
| Multiple findings | One finding per non-overlapping detected burst | Captures sustained or repeated scans without duplicating every overlapping window |
| Cancellation | Checked in both outer and inner loops | Allows graceful shutdown on large inputs |
| Truncation | Optional, per-source cap with warning | Bounds memory for high-volume sources |

---

## Implementation Evidence

- [PortScanDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/PortScanDetector.cs) — detector implementation
- [AnalysisProfile.cs](../../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold configuration record
- [AnalysisProfileProvider.cs](../../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — intensity presets
- [PortScanDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) — test suite

---

## Security Takeaways

1. The sliding-window approach avoids fixed-boundary false negatives while remaining deterministic for the same log data
2. The pre-window gate ensures only sources with sufficient distinct destination ports reach the windowing stage
3. Truncation with warnings maintains analyst trust by surfacing when data was dropped
4. Cancellation checks at both loop levels prevent the detector from blocking analysis engine shutdown
5. Finding details include the exact distinct-port count and window size, giving analysts immediate context for triage
6. Findings are emitted at Medium severity, but downstream severity filtering can hide them on the Low intensity profile unless participating PortScan findings are escalated to Critical via `RiskEscalator` correlation with FlagAnomaly findings from the same source
