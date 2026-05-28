# Flood Detection — Detection Algorithm

## Security Problem

A flood attack is characterized by a single source IP generating an abnormally high number of connection events within a compressed timeframe. The detection challenge is counting events accurately within a sliding temporal window — ensuring that bursts at window boundaries are not missed. The v1 detector does not distinguish legitimate high-volume sources from malicious flooding; tuning `FloodMinEvents` and `FloodWindowSeconds` per environment is the operator's responsibility.

---

## Implementation Overview

```
         Raw Events
             |
             v
    ┌─────────────────────┐
    │ Step A: Guard Check  │  Skip if disabled or empty
    └────────┬────────────┘
             v
    ┌─────────────────────┐
    │ Step B: Group       │  Group by Source IP
    └────────┬────────────┘
             v
    ┌─────────────────────┐
    │ Step C: Sort        │  Order by timestamp ascending
    └────────┬────────────┘
             v
    ┌─────────────────────┐
    │ Step D: Slide       │  Two-pointer window per group
    │   & Count           │  Count events in window
    └────────┬────────────┘
             v
    ┌─────────────────────┐
    │ Step E: Report      │  Create / extend / finalize finding
    └─────────────────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnableFlood || events.Count == 0)
    return DetectionResult.Empty;
```

Returns immediately if the detector is disabled or the event list is empty. Zero allocations, zero computation.

---

### Step B — Group by Source IP

```csharp
var bySrc = events.GroupBy(e => e.SourceIP);
foreach (var srcGroup in bySrc)
{
    cancellationToken.ThrowIfCancellationRequested();
    var srcIp = srcGroup.Key;
```

Unlike LateralMovementDetector, the flood detector applies **no IP classification filter**. Floods can originate from any source — external DDoS, compromised internal hosts, or misconfigured services. Each group iteration checks `cancellationToken.ThrowIfCancellationRequested()`, enabling cooperative cancellation for large log analyses.

---

### Step C — Sort by Timestamp

```csharp
var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
if (ordered.Count == 0) continue;
```

Events for each source are sorted chronologically. The two-pointer window requires monotonic timestamps. The `Count == 0` guard is a defensive check (LINQ `GroupBy` never yields empty groups, but the guard protects against future refactoring).

---

### Step D — Two-Pointer Sliding Window

```csharp
var windowSeconds = profile.FloodWindowSeconds;
int start = 0;
for (int end = 0; end < ordered.Count; end++)
{
    while (start < end &&
           (ordered[end].Timestamp - ordered[start].Timestamp).TotalSeconds > windowSeconds)
    {
        start++;
    }

    int windowCount = end - start + 1;
    if (windowCount >= profile.FloodMinEvents)
    {
        // emit finding
    }
}
```

The window works as follows:

- `end` advances through each event in order
- `start` advances only when the time span between `ordered[start]` and `ordered[end]` exceeds `FloodWindowSeconds`
- The window count is simply `end - start + 1` — no LINQ, no allocation
- This is simpler than the lateral movement detector because it counts events, not distinct hosts

---

### Step E — Create, Extend, or Finalize Finding

```csharp
findings.Add(new Core.Finding
{
    Category = "Flood",
    Severity = Core.Severity.High,
    SourceHost = srcIp,
    Target = "multiple hosts/ports",
    TimeRangeStart = minTime,
    TimeRangeEnd = maxTime,
    ShortDescription = $"Flood detected from {srcIp}",
    Details = $"Detected {windowCount} events within {windowSeconds} seconds."
});
inFinding = true;
peakCount = windowCount;
```

The `inFinding` flag begins tracking the active burst. As long as the window count stays above threshold, `peakCount` is updated to the maximum observed count. When the count drops below threshold, the finding is finalized with its actual end time and peak count.

---

## Complexity And Behavior

| Aspect | Detail |
|---|---|
| Sort per group | O(n log n) where n = events for that source |
| Two-pointer scan | O(n) — each event visited at most twice |
| Window count | O(1) — simple integer arithmetic |
| Overall | O(N log n_max) total |
| Space | O(n) per group for the ordered list |
| Early exit | Guaranteed single finding per source |

---

## Implementation Evidence

- [FloodDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/FloodDetector.cs) — full algorithm implementation (98 lines)
- [AnalysisProfile.cs](../../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold configuration (195 lines)
- [FloodDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/FloodDetectorTests.cs) — test coverage (403 lines)
