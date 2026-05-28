# Code Patterns: Port Scan Detection

## The Security Problem

Security detectors must be both correct and resilient. A detector that crashes on malformed input, produces inconsistent results on re-runs, or silently drops data when under load is worse than no detector at all — it provides false confidence. The port scan detector uses several recurring code patterns that support reliability, transparency, and safe cancellation.

---

## Implementation Overview

| Pattern | Location in PortScanDetector.cs | Purpose |
|---|---|---|
| Guard clause | Detector implementation | Early exit on disabled/empty input |
| Source grouping | Source grouping in `Detect` | Per-scanner analysis |
| Sliding-window counters | Inner loop in `Detect` | Per-window threshold evaluation |
| Optional truncation with warning | Detector implementation | Bounded resource usage with transparency |
| Pre-computation gate | Detector implementation | Skip sources that cannot possibly trigger |
| Cooperative cancellation | Outer and inner loops | Safe shutdown on large inputs |

---

## How It Works (Technical)

### Guard Clause

```csharp
if (!profile.EnablePortScan || events.Count == 0)
    return DetectionResult.Empty;
```

The guard clause exits before allocating any data structures. This is a standard pattern across all VulcansTrace detectors — the first check is always whether the detector should run at all, and the second is whether there is data to process.

---

### Source Grouping

```csharp
var bySrc = events.GroupBy(e => e.SourceIP);
```

The detector groups by source IP because scan thresholds are evaluated per scanner. Each group is ordered by timestamp before the sliding-window pass.

---

### Optional Truncation with Warning

```csharp
if (profile.PortScanMaxEntriesPerSource is { } maxEntries && maxEntries > 0 && ordered.Count > maxEntries)
{
    ordered = ordered.TakeLast(maxEntries).ToList();
    warnings.Add($"Port scan analysis for {srcIp} truncated to {maxEntries} events out of {totalForSource}.");
}
```

The nullable pattern makes truncation optional. The warning message includes both the cap and the original count so the analyst can assess whether truncation may have affected results. Warnings are returned through `DetectionResult.Warnings` and ultimately surfaced by the analysis engine/UI.

---

### Pre-Computation Gate

```csharp
var distinctPortsForSource = ordered
    .Select(e => e.DestinationPort)
    .Distinct()
    .Count();

if (distinctPortsForSource < profile.PortScanMinPorts)
    continue;
```

This is a single-pass LINQ chain that counts distinct destination ports across all analyzed events for the source. If the total distinct count across all analyzed events is below the threshold, no individual time window can meet it. The `continue` statement skips directly to the next source group, avoiding the sliding-window pass entirely.

---

### Sliding Window Counters

```csharp
var portCounts = new Dictionary<int, int>();
var distinctPorts = 0;
int start = 0;

for (int end = 0; end < ordered.Count; end++)
```

The detector maintains counts for destination ports currently inside the active time window. As the `end` pointer advances, new ports are added. As the `start` pointer advances past events older than `PortScanWindowMinutes`, ports are decremented or removed. This keeps the window pass linear after sorting.

---

### Cooperative Cancellation

```csharp
cancellationToken.ThrowIfCancellationRequested();
```

Called in the outer per-source loop and the inner sliding-window loop. `ThrowIfCancellationRequested` throws `OperationCanceledException` if cancellation was requested. Because findings are accumulated in a local `List<Finding>`, a cancelled operation simply abandons partial results rather than returning incomplete or inconsistent data.

---

## Implementation Evidence

- [PortScanDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PortScanDetector.cs) — all patterns shown above
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — `PortScanMinPorts`, `PortScanWindowMinutes`, `PortScanMaxEntriesPerSource` properties
- [PortScanDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) — validates guard clause, threshold boundaries, truncation, same-port false positives, and finding properties

---

## Security Takeaways

1. Guard clauses avoid unnecessary allocation on disabled or empty analysis runs
2. Source grouping produces clear per-scanner analysis boundaries
3. The truncation-warning pattern maintains the chain of custody — analysts always know when data was dropped
4. Cooperative cancellation ensures partial results are never published, maintaining finding integrity
5. Sliding-window counters avoid fixed-boundary false negatives while keeping the window pass linear
