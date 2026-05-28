# Lateral Movement Detection — Code Patterns

## Security Problem

Lateral movement detection must process potentially millions of firewall log entries efficiently while maintaining precise temporal accuracy. The implementation uses several recurring patterns that balance performance with correctness.

---

## Implementation Overview

| Pattern | Location | Purpose |
|---|---|---|
| Guard clause | Lines 18-19 | Early return when detector is disabled or no data |
| HashSet lookup | Lines 23-24, 29 | O(1) membership testing for admin ports |
| LINQ group-and-sort | Lines 31-36 | Declarative grouping and ordering |
| Dictionary host counting | Lines 40-70 | O(1) add/remove per event, tracks distinct hosts |
| Two-pointer window | Lines 46-105 | Efficient temporal sliding window with finding state tracking |
| Post-loop finalization | Lines 107-114 | Updates TimeRangeEnd and Details for any active finding |

---

## How It Works

### Guard Clause Pattern

```csharp
if (!profile.EnableLateralMovement || events.Count == 0)
    return DetectionResult.Empty;
```

Every detector in the engine starts with a guard clause. This pattern ensures that disabled detectors consume negligible resources and that empty event lists short-circuit before any allocation. The check is deliberately ordered — if the detector is disabled, there is no need to access the events collection at all.

---

### HashSet for Hot-Path Filtering

```csharp
var adminSet = new HashSet<int>(adminPorts);
// ...
adminSet.Contains(e.DestinationPort)
```

Admin ports are stored in a `HashSet<int>` for O(1) lookup. The `Where` filter in Step B is the hottest path in the detector — it runs once for every event. Using a hash set instead of `Array.Contains()` reduces this from O(k) to O(1) per event, where k is the number of admin ports.

---

### Dictionary-Based Host Counting

```csharp
var hostCounts = new Dictionary<string, int>();
var distinctHosts = 0;
int start = 0;

for (int end = 0; end < ordered.Count; end++)
{
    var addHost = ordered[end].DestinationIP;
    if (hostCounts.TryGetValue(addHost, out var cnt))
    {
        hostCounts[addHost] = cnt + 1;
    }
    else
    {
        hostCounts[addHost] = 1;
        distinctHosts++;
    }

    while (start < end &&
           (ordered[end].Timestamp - ordered[start].Timestamp).TotalMinutes > windowMinutes)
    {
        var removeHost = ordered[start].DestinationIP;
        hostCounts[removeHost]--;
        if (hostCounts[removeHost] == 0)
        {
            hostCounts.Remove(removeHost);
            distinctHosts--;
        }
        start++;
    }
}
```

The two-pointer pattern avoids creating explicit sub-lists for every window position. Host counting is maintained incrementally via a `Dictionary<string, int>` — each new event increments its destination IP count (or adds it), and each evicted event decrements its count (or removes it when it reaches zero). A separate `distinctHosts` counter tracks the current number of unique destinations without recomputation. Both `start` and `distinctHosts` only move forward as the window slides, giving O(1) work per event in the common case.

---

### Cancellation Token Propagation

```csharp
cancellationToken.ThrowIfCancellationRequested();
```

Placed inside the outer loop, this gives the orchestration layer the ability to cancel long-running analyses. This is critical for UI responsiveness in the Avalonia application and for timeout enforcement in batch processing.

---

## Implementation Evidence

- [LateralMovementDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/LateralMovementDetector.cs) — all patterns visible in context (120 lines)
- [IpClassification.cs](../../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — `IsInternal()` used in the filter (157 lines)
- [LateralMovementDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/LateralMovementDetectorTests.cs) — validates guard clauses, thresholds, and window behavior (687 lines)

---

## Security Takeaways

- The guard clause pattern ensures disabled detectors short-circuit before any allocation or analysis, with negligible resource consumption
- HashSet-based filtering prevents admin-port checks from becoming a bottleneck on large log sets
- The two-pointer window eliminates a class of temporal false negatives that naive approaches would miss
- Cancellation token propagation ensures long-running analyses don't block incident response workflows
- Dictionary-based host counting provides O(1) add/remove per event, avoiding per-window recomputation
- Natural window eviction plus `inFinding` state tracking allows the detector to discover multiple lateral movement bursts from the same source
