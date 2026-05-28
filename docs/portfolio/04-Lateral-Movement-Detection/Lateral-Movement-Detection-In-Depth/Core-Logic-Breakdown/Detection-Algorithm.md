# Lateral Movement Detection — Detection Algorithm

## Security Problem

Lateral movement is a time-bounded behavior: an attacker compromises one internal host and then rapidly connects to multiple other internal hosts on administrative ports. The detection challenge is distinguishing this pattern from legitimate admin activity (e.g., a monitoring server that regularly connects to many internal hosts) by requiring the connections to occur within a compressed time window.

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
    │ Step B: Filter      │  Internal→Internal + Admin Port
    └────────┬────────────┘
             v
    ┌─────────────────────┐
    │ Step C: Group       │  Group by Source IP
    └────────┬────────────┘
             v
     ┌─────────────────────┐
     │ Step D: Slide       │  Two-pointer window per group
     │   & Detect          │  Dictionary host counting
     └────────┬────────────┘
              v
     ┌─────────────────────┐
     │ Step E: Report      │  Emit Finding, reset state
     │          & Reset     │  Continue scanning
     └─────────────────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnableLateralMovement || events.Count == 0)
    return DetectionResult.Empty;
```

Returns immediately if the detector is disabled in the current analysis profile or the event list is empty. This avoids unnecessary computation and respects profile-based feature toggling.

---

### Step B — Filter to Admin-Port Internal Flows

```csharp
var adminPorts = profile.AdminPorts ?? Array.Empty<int>();
var adminSet = new HashSet<int>(adminPorts);
var filtered = events.Where(e =>
    IpClassification.IsInternal(e.SourceIP) &&
    IpClassification.IsInternal(e.DestinationIP) &&
    adminSet.Contains(e.DestinationPort));
```

Three conditions must be met:

1. **Source is internal** — `IpClassification.IsInternal()` checks RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), IPv4 loopback (127.0.0.0/8), link-local (169.254.0.0/16), CGNAT (100.64.0.0/10), and IPv6 ULA, loopback, and link-local (fe80::/10)
2. **Destination is internal** — same classification for the target
3. **Port is administrative** — destination port must be in the profile's `AdminPorts` list (profile default: `{445, 3389, 22}` for SMB, RDP, SSH)

The `HashSet<int>` provides O(1) membership testing on the hot path.

---

### Step C — Group by Source IP

```csharp
var bySrc = filtered.GroupBy(e => e.SourceIP);
foreach (var srcGroup in bySrc)
```

Groups filtered events by source IP so each potential attacker is analyzed independently. This ensures one host's lateral movement doesn't affect another's detection.

---

### Step D — Two-Pointer Sliding Window

```csharp
cancellationToken.ThrowIfCancellationRequested();

var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
if (ordered.Count == 0) continue;

var windowMinutes = profile.LateralWindowMinutes;
var hostCounts = new Dictionary<string, int>();
var distinctHosts = 0;
int start = 0;
for (int end = 0; end < ordered.Count; end++)
{
    // Add current event's destination to dictionary
    var addHost = ordered[end].DestinationIP;
    if (hostCounts.TryGetValue(addHost, out var cnt))
        hostCounts[addHost] = cnt + 1;
    else
    {
        hostCounts[addHost] = 1;
        distinctHosts++;
    }

    // Shrink window from the left
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

    if (distinctHosts >= profile.LateralMinHosts) { /* emit finding */ }
}
```

The two-pointer technique works as follows:

- `end` advances through the sorted events
- Each new event's destination IP is added to a `Dictionary<string, int>`, incrementing an O(1) distinct-host counter
- `start` advances only when the time gap between `ordered[start]` and `ordered[end]` exceeds `windowMinutes`, decrementing or removing the evicted event's host from the dictionary
- If the distinct host count reaches `LateralMinHosts`, a finding is emitted

---

### Step E — Emit Finding and Burst Tracking

```csharp
if (distinctHosts >= profile.LateralMinHosts)
{
    if (!inFinding)
    {
        peakDistinctHosts = distinctHosts;
        findings.Add(new Core.Finding
        {
            Category = "LateralMovement",
            Severity = Core.Severity.High,
            SourceHost = srcGroup.Key,
            Target = "multiple internal hosts",
            TimeRangeStart = ordered[start].Timestamp,
            TimeRangeEnd = ordered[end].Timestamp,
            ShortDescription = $"Lateral movement from {srcGroup.Key}",
            Details = $"Contacted {distinctHosts} internal hosts on admin ports."
        });
        inFinding = true;
    }
    else if (distinctHosts > peakDistinctHosts)
    {
        peakDistinctHosts = distinctHosts;
    }
}
else if (inFinding)
{
    var idx = findings.Count - 1;
    findings[idx] = findings[idx] with
    {
        TimeRangeEnd = ordered[Math.Max(0, end - 1)].Timestamp,
        Details = $"Contacted {peakDistinctHosts} internal hosts on admin ports."
    };
    inFinding = false;
}
```

When the distinct-host count first meets or exceeds `LateralMinHosts`, a finding is created. The detector tracks whether it is already `inFinding` so that overlapping windows above the threshold do not produce duplicate findings. As long as the count stays above the threshold, the same finding is extended and the `peakDistinctHosts` counter is updated. When the count drops below the threshold, the finding is finalized with the last valid timestamp and the peak host count seen during the burst. After the loop ends, any active finding is closed with the final event's timestamp.

This produces **one finding per contiguous above-threshold burst** rather than one per window position. Separate time-separated bursts from the same source can produce separate findings because natural window eviction clears old hosts, causing `distinctHosts` to drop below threshold and close the prior finding before a new burst crosses the threshold again.

> **Note:** The detector always emits findings at `Severity.High`, but the downstream `RiskEscalator` may promote them to `Severity.Critical` when correlated with Beaconing findings from the same source host.

---

## Complexity And Behavior

| Aspect | Detail |
|---|---|
| Sort per group | O(n log n) where n = events for that source |
| Two-pointer scan | O(n) — each event is visited at most twice (once by `end`, once by `start`) |
| Host counting | O(1) per event — dictionary add/remove |
| Overall | O(N · log(n_max)) worst-case where N = total events, n_max = largest group |
| Space | O(n) per group for the ordered list and host dictionary |
| Multiple findings | Possible — natural window eviction plus `inFinding` state tracking allow detection of separate lateral movement bursts per source |

---

## Implementation Evidence

- [LateralMovementDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/LateralMovementDetector.cs) — full algorithm implementation
- [IpClassification.cs](../../../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — internal/external classification used in Step B
- [AnalysisProfile.cs](../../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold and enable-flag configuration
- [LateralMovementDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/LateralMovementDetectorTests.cs) — test coverage validating each step
