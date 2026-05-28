# Code Patterns: Privilege Escalation Detection

## The Security Problem

Security detectors must be both correct and resilient. A detector that crashes on edge cases, produces inconsistent results on re-runs, or silently misses attacks undermines analyst confidence. The privilege escalation detector uses several recurring code patterns that support reliability, clear signal separation, and safe cancellation.

---

## Implementation Overview

| Pattern | Location in PrivilegeEscalationDetector.cs | Purpose |
|---|---|---|
| Guard clause | Lines 20–23 | Early exit on disabled/empty input |
| Baseline + profile merging | Lines 26–29 | Extensible admin port configuration |
| Admin port filtering | Lines 32–34 | Reduce dataset to relevant events only |
| Per-source grouping with ordering | Lines 36–40 | Isolate attacker activity chronologically |
| Sliding window spike detection | Lines 59–131 | Two-pointer sliding window with inFinding state machine for spike detection |
| Two-pointer dictionary sweep | Lines 133–232 | Dictionary-based two-pointer sweep with inFinding state machine |
| Cooperative cancellation | Line 38 | Safe shutdown on large inputs |
| Burst-aware finding emission | Lines 84–128 (spikes), 177–229 (sweeps) | Peak tracking and post-loop finalization for both sub-detectors |
| Early exit guards | Lines 62–65, 137–140 | Skip impossible detection paths |

---

## How It Works (Technical)

### Guard Clause

```csharp
if (!profile.EnablePrivilegeEscalationDetection || events.Count == 0)
{
    return DetectionResult.Empty;
}
```

The guard clause exits before allocating any data structures. Under the Low intensity profile, this check prevents the detector from running entirely. The empty event check avoids unnecessary computation when there is nothing to analyze. This is a standard pattern across all VulcansTrace detectors. The return type is `DetectionResult`, not `IEnumerable<Finding>` — the detector wraps its findings list in `new DetectionResult(findings)` at the end.

---

### Baseline + Profile Merging

```csharp
var baselineAdminPorts = new[] { 22, 2222, 2200, 22022, 3389, 5900, 5432, 3306 };
var adminPorts = profile.AdminPorts is { Count: > 0 }
    ? profile.AdminPorts.Concat(baselineAdminPorts).Distinct().ToArray()
    : baselineAdminPorts;
```

The pattern defines a hardcoded baseline and conditionally merges profile-supplied values. The `is { Count: > 0 }` pattern-match check avoids the `Concat` + `Distinct` overhead when no custom ports are provided (and safely handles null). The `Distinct()` call ensures no duplicate ports even if the profile includes ports already in the baseline. The result is always an array, providing O(1) lookup via `Contains` on the `IReadOnlyCollection<int>`.

---

### Admin Port Filtering

```csharp
var bySource = events
    .Where(e => IsAdminAccess(e, adminPorts))
    .GroupBy(e => e.SourceIP);
```

```csharp
private static bool IsAdminAccess(UnifiedEvent evt, IReadOnlyCollection<int> adminPorts)
{
    return adminPorts.Contains(evt.DestinationPort);
}
```

Events are filtered before grouping, reducing the dataset to only admin-port traffic. The `IsAdminAccess` helper is a separate static method for clarity and testability. The `IReadOnlyCollection<int>` parameter type ensures `Contains` is an O(n) scan on a small set (8–11 elements), which is faster than a `HashSet` for collections of this size.

---

### Per-Source Grouping with Ordering

```csharp
foreach (var sourceGroup in bySource)
{
    cancellationToken.ThrowIfCancellationRequested();
    var orderedEvents = sourceGroup.OrderBy(e => e.Timestamp).ToList();
```

Events are grouped by source IP and ordered chronologically within each group. The `ToList()` materializes the query, preventing multiple enumeration in the sub-detectors. Cancellation is checked once per source group, providing regular shutdown opportunities without checking on every event.

---

### Sliding Window Spike Detection

```csharp
var minAttempts = profile.PrivilegeSpikeMinAttempts > 0
    ? profile.PrivilegeSpikeMinAttempts : 5;

int start = 0;
bool inFinding = false;
int peakCount = 0;

for (int end = 0; end < events.Count; end++)
{
    while (start < end &&
           (events[end].Timestamp - events[start].Timestamp)
               .TotalMinutes > windowMinutes)
    {
        start++;
    }

    int windowCount = end - start + 1;
    if (windowCount >= minAttempts)
    {
        if (!inFinding)
        {
            peakCount = windowCount;
            // emit finding
            inFinding = true;
        }
        else if (windowCount > peakCount)
        {
            peakCount = windowCount;
        }
    }
    else if (inFinding)
    {
        // finalize finding with peakCount
        inFinding = false;
    }
}

// post-loop finalization
if (inFinding)
{
    // finalize finding with peakCount
}
```

The spike detector uses a two-pointer sliding window. `start` advances whenever the time span between `events[start]` and `events[end]` exceeds the configured window. When the count of events in the window (`end - start + 1`) meets the `PrivilegeSpikeMinAttempts` threshold, a finding is emitted and the window jumps past the match. The threshold is profile-dependent: 5 under Medium, 4 under High, with a fallback default of 5.

---

### Two-Pointer Dictionary Sweep (Sweeps)

```csharp
var portCounts = new Dictionary<int, int>();
var distinctPorts = 0;
int start = 0;

for (int end = 0; end < events.Count; end++)
{
    // Add the new event's port
    var addPort = events[end].DestinationPort;
    if (portCounts.TryGetValue(addPort, out var cnt))
        portCounts[addPort] = cnt + 1;
    else
    {
        portCounts[addPort] = 1;
        distinctPorts++;
    }

    // Shrink window from the front if it exceeds the time span
    while (start < end &&
           (events[end].Timestamp - events[start].Timestamp)
               .TotalMinutes > windowMinutes)
    {
        var removePort = events[start].DestinationPort;
        portCounts[removePort]--;
        if (portCounts[removePort] == 0)
        {
            portCounts.Remove(removePort);
            distinctPorts--;
        }
        start++;
    }

    if (distinctPorts >= minDistinctPorts)
    {
        if (!inFinding)
        {
            peakDistinctPorts = distinctPorts;
            peakPortList = portCounts.Keys.ToList();
            // emit finding
            inFinding = true;
        }
        else if (distinctPorts > peakDistinctPorts)
        {
            peakDistinctPorts = distinctPorts;
            peakPortList = portCounts.Keys.ToList();
        }
    }
    else if (inFinding)
    {
        // finalize finding with peakDistinctPorts and peakPortList
        inFinding = false;
    }
}

// post-loop finalization
if (inFinding)
{
    // finalize finding with peakDistinctPorts and peakPortList
}
```

The sweep detector uses a two-pointer sliding window with a `Dictionary<int, int>` to track per-port hit counts. As `end` advances, the new port is added to the dictionary. When the time span exceeds the window, `start` advances and port counts are decremented — ports dropping to zero are removed from the dictionary. When `distinctPorts` meets the `PrivilegeSweepMinDistinctPorts` threshold, a finding is created (if not already in one) or updated with the peak distinct-port count and port list. When distinct ports drop below threshold, the finding is finalized and `inFinding` resets. Post-loop finalization handles an above-threshold window extending to the last event. The threshold is profile-dependent: 3 under Medium, 2 under High, with a fallback default of 3.

---

### Early Exit Guards

```csharp
if (windowMinutes <= 0)
{
    return findings;
}
```

```csharp
if (events.Count < 3 || windowMinutes <= 0)
{
    return findings;
}
```

Both sub-detectors check for impossible conditions before processing. The `windowMinutes <= 0` check handles the case where the window is explicitly disabled. The `events.Count < 3` check in the sweep detector skips the scan when fewer than 3 events make a sweep impossible.

---

## Implementation Evidence

- [PrivilegeEscalationDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PrivilegeEscalationDetector.cs) — all patterns shown above (233 lines)
- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — `EnablePrivilegeEscalationDetection`, `PrivilegeSpikeWindowMinutes`, `AdminPorts` properties (195 lines)
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — Low/Medium/High profile presets (239 lines)
- [PrivilegeEscalationDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/PrivilegeEscalationDetectorTests.cs) — validates guard clause, threshold boundaries, and finding properties (679 lines)

---

## Security Takeaways

1. Guard clauses prevent the detector from running when disabled, avoiding both wasted computation and false positives
2. Baseline + profile merging ensures the detector is effective immediately while supporting environment-specific customization
3. Both sub-detectors use two-pointer sliding windows (O(N)) — the spike detector counts events in the window, the sweep detector tracks distinct ports via a dictionary
4. The sweep detector resets state and continues scanning after a match, enabling detection of multiple separate sweeps from the same source
5. Early exit guards in sub-detectors prevent impossible computation paths (zero-minute windows, too few events for a sweep)
