# Flood Detection — Code Patterns

## Security Problem

Flood detection must process high-volume event streams efficiently, as the detector may be analyzing the very condition it is designed to detect — a log file swamped with thousands of events from a single source. The implementation must remain fast and memory-efficient even under pathological input.

---

## Implementation Overview

| Pattern | Location | Purpose |
|---|---|---|
| Guard clause | Detector implementation | Early return when disabled or empty |
| LINQ group | Detector implementation | Declarative partitioning by source |
| Sort-then-scan | Detector implementation | Chronological ordering followed by linear scan |
| Integer window count | Detector implementation | O(1) counting without allocation |
| Burst tracking with inFinding | Detector implementation | One finding per contiguous burst |

---

## How It Works

### Guard Clause Pattern

```csharp
if (!profile.EnableFlood || events.Count == 0)
    return DetectionResult.Empty;
```

Identical pattern to all detectors in the engine. The boolean flag is checked first (cheaper than `Count`). Returns `DetectionResult.Empty` — no allocation for findings.

---

### Group-Then-Sort Pattern

```csharp
var bySrc = events.GroupBy(e => e.SourceIP);
foreach (var srcGroup in bySrc)
{
    var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
```

Events are grouped by source IP using LINQ's deferred `GroupBy`, then materialized and sorted per group. This pattern isolates each source's timeline for independent analysis. The `ToList()` forces eager evaluation so the sort and subsequent index-based access are efficient.

---

### Two-Pointer Sliding Window with Integer Count

```csharp
int start = 0;
for (int end = 0; end < ordered.Count; end++)
{
    while (start < end &&
           (ordered[end].Timestamp - ordered[start].Timestamp).TotalSeconds > windowSeconds)
    {
        start++;
    }

    int windowCount = end - start + 1;
```

The two-pointer pattern is shared with LateralMovementDetector but simplified: instead of counting distinct hosts via LINQ, the window count is a pure integer computation. This makes the flood detector's inner loop allocation-free.

The `while` loop that advances `start` ensures the window never exceeds `FloodWindowSeconds`. Each event is visited at most twice — once by `end`, once by `start`.

When `windowCount >= profile.FloodMinEvents`, a flood finding is created if not already in an active burst (`inFinding == false`), or the `peakCount` is updated if the burst is ongoing. When the count drops below threshold while `inFinding == true`, the finding is finalized with its actual end time and peak count. The threshold is profile-configurable: 100 events (High intensity), 200 (Medium), or 400 (Low), all within a default 60-second window.

---

### Cancellation Token Propagation

```csharp
cancellationToken.ThrowIfCancellationRequested();
```

Placed at the top of the outer loop. For the flood detector, this is especially important because a flood attack may produce millions of events from a single source. The cancellation check ensures the UI remains responsive and batch jobs can enforce timeouts.

---

### Burst Tracking with State Machine

```csharp
if (windowCount >= profile.FloodMinEvents)
{
    if (!inFinding)
    {
        findings.Add(new Core.Finding { /* ... */ });
        inFinding = true;
        peakCount = windowCount;
    }
    else if (windowCount > peakCount)
    {
        peakCount = windowCount;
    }
}
else if (inFinding)
{
    // finalize finding with actual end time and peak count
    inFinding = false;
}
```

The `inFinding` flag tracks whether the detector is currently inside an active above-threshold window. This prevents duplicate findings from overlapping windows while still allowing separate time-separated bursts from the same source to produce independent findings. After the loop completes, any still-active finding is finalized with the last event's timestamp.

---

## Implementation Evidence

- [FloodDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/FloodDetector.cs) — all patterns in context
- [FloodDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/FloodDetectorTests.cs) — validates patterns across scenarios

---

## Security Takeaways

- The guard clause pattern ensures disabled detectors have near-zero cost and no allocation
- Integer-only window counting prevents the detector from allocating memory proportional to flood volume — critical when analyzing actual attack data
- Cancellation token propagation allows the analysis pipeline to remain responsive under DDoS-scale log files when the caller provides a cancellable token
- The burst-aware pattern is self-referentially important: a flood detector that floods the alert system would be counterproductive
- The sort-then-scan pattern provides O(n log n) performance with clear, auditable logic
