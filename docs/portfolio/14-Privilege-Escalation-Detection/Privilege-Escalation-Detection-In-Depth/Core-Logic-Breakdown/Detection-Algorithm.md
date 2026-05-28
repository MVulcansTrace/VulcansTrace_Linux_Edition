# Detection Algorithm: Privilege Escalation Detection

## The Security Problem

Attackers escalate privileges by exploiting administrative services exposed on the network. Two dominant patterns emerge in firewall logs:

1. **Brute-force bursts** — Rapid, repeated attempts against a single admin port (typically SSH) as the attacker tries to guess credentials. These produce a spike in connection events from one source IP to one destination port within a short time window.

2. **Service enumeration sweeps** — Methodical probing across multiple admin ports (SSH, RDP, VNC, databases) as the attacker searches for the most vulnerable administrative interface. Each port may receive only one or two attempts, so volume-based detection misses this pattern entirely.

The challenge is distinguishing these attack patterns from legitimate administrative traffic — system administrators routinely connect to SSH, database admins connect to PostgreSQL and MySQL, and remote desktop sessions are normal in mixed-OS environments.

---

## Implementation Overview

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Guard check │────▶│  Build admin    │────▶│  Filter events   │────▶│  GroupBy       │
│  Enabled?    │     │  port set       │     │  by admin port   │     │  SourceIP      │
└──────────────┘     └─────────────────┘     └──────────────────┘     └────────────────┘
                                                                               │
                                                                               ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Collect     │◀────│  Sub-Detector 2 │     │  Sub-Detector 1  │◀────│  OrderBy       │
│  findings    │     │  Admin Port     │     │  Admin Spikes     │     │  Timestamp     │
│              │     │  Sweeps         │     │  (sliding window) │     │                │
└──────────────┘     └─────────────────┘     └──────────────────┘     └────────────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnablePrivilegeEscalationDetection || events.Count == 0)
{
    return DetectionResult.Empty;
}
```

The detector exits immediately if privilege escalation detection is disabled or there are no events. Under the Low intensity profile, this guard prevents the detector from running at all, avoiding false positives in environments where admin-port traffic is expected.

---

### Step B — Build Admin Port Set

```csharp
var baselineAdminPorts = new[] { 22, 2222, 2200, 22022, 3389, 5900, 5432, 3306 };
var adminPorts = profile.AdminPorts is { Count: > 0 }
    ? profile.AdminPorts.Concat(baselineAdminPorts).Distinct().ToArray()
    : baselineAdminPorts;
```

The baseline set contains 8 Linux-relevant admin ports covering SSH (standard and alternates), RDP, VNC, PostgreSQL, and MySQL. If the profile supplies additional `AdminPorts`, they are merged with the baseline and deduplicated. This ensures the detector works out of the box while supporting environment-specific customization.

---

### Step C — Filter and Group by Source

```csharp
var bySource = events
    .Where(e => IsAdminAccess(e, adminPorts))
    .GroupBy(e => e.SourceIP);

foreach (var sourceGroup in bySource)
{
    cancellationToken.ThrowIfCancellationRequested();
    var orderedEvents = sourceGroup.OrderBy(e => e.Timestamp).ToList();
```

Events are filtered to only those targeting admin ports, then grouped by source IP. Each source is analyzed independently — a privilege escalation attack is defined per-attacker. Events within each group are ordered chronologically for window-based analysis.

---

### Step D — Sub-Detector 1: DetectAdminSpikes

```csharp
private static List<Core.Finding> DetectAdminSpikes(
    List<UnifiedEvent> events, int windowMinutes, AnalysisProfile profile)
{
    var findings = new List<Core.Finding>();
    if (windowMinutes <= 0)
        return findings;

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
                findings.Add(new Core.Finding { ... });
                inFinding = true;
            }
            else if (windowCount > peakCount)
            {
                peakCount = windowCount;
            }
        }
        else if (inFinding)
        {
            findings[^1] = findings[^1] with
            {
                TimeRangeEnd = events[Math.Max(0, end - 1)].Timestamp,
                Details = $"Detected {peakCount} admin port access attempts ..."
            };
            inFinding = false;
        }
    }

    if (inFinding)
    {
        findings[^1] = findings[^1] with
        {
            TimeRangeEnd = events[^1].Timestamp,
            Details = $"Detected {peakCount} admin port access attempts ..."
        };
    }
}
```

The spike detector uses a two-pointer sliding window with an `inFinding` state machine, same as the sweep detector. `start` advances whenever the time span between `events[start]` and `events[end]` exceeds the configured window. When the event count meets `PrivilegeSpikeMinAttempts`, a finding is created (if not already in one) or updated with the peak count. When the count drops below threshold, the finding is finalized with the peak count and `inFinding` resets. Post-loop finalization handles an above-threshold window that extends to the last event. This catches brute-force attacks where an attacker rapidly retries credentials against a single service.

---

### Step E — Sub-Detector 2: DetectAdminPortSweeps

```csharp
private static List<Core.Finding> DetectAdminPortSweeps(
    List<UnifiedEvent> events, int windowMinutes, AnalysisProfile profile)
{
    if (events.Count < 3 || windowMinutes <= 0)
        return findings;

    var minDistinctPorts = profile.PrivilegeSweepMinDistinctPorts > 0
        ? profile.PrivilegeSweepMinDistinctPorts : 3;

    var portCounts = new Dictionary<int, int>();
    var distinctPorts = 0;
    int start = 0;
    bool inFinding = false;
    int peakDistinctPorts = 0;
    List<int>? peakPortList = null;

    for (int end = 0; end < events.Count; end++)
    {
        var addPort = events[end].DestinationPort;
        if (portCounts.TryGetValue(addPort, out var cnt))
            portCounts[addPort] = cnt + 1;
        else
        {
            portCounts[addPort] = 1;
            distinctPorts++;
        }

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
                findings.Add(new Core.Finding { ... });
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
            var portList = peakPortList ?? portCounts.Keys.ToList();
            findings[^1] = findings[^1] with
            {
                TimeRangeEnd = events[Math.Max(0, end - 1)].Timestamp,
                Target = $"ports {string.Join(", ", portList.Take(5))}...",
                Details = $"Detected access attempts across {peakDistinctPorts} admin ports ..."
            };
            inFinding = false;
        }
    }

    if (inFinding)
    {
        var portList = peakPortList ?? portCounts.Keys.ToList();
        findings[^1] = findings[^1] with
        {
            TimeRangeEnd = events[^1].Timestamp,
            Target = $"ports {string.Join(", ", portList.Take(5))}...",
            Details = $"Detected access attempts across {peakDistinctPorts} admin ports ..."
        };
    }
}
```

The sweep detector uses a two-pointer sliding window with a `Dictionary<int, int>` to track per-port counts within the window. As `end` advances, the new port is added to the dictionary. When the time span exceeds the window, `start` advances and ports are decremented or removed. When distinct ports reach `PrivilegeSweepMinDistinctPorts`, a finding is created (if not already in one) or updated with the peak distinct-port count and port list. When distinct ports drop below threshold, the finding is finalized and `inFinding` resets. Post-loop finalization handles an above-threshold window that extends to the last event. This allows detection of multiple separate sweeps from the same source.

---

## Complexity And Behavior

| Aspect | Behavior | Rationale |
|---|---|---|
| Time complexity (spikes) | O(N) per source | Two-pointer sliding window, single pass |
| Time complexity (sweeps) | O(N) per source | Two-pointer sliding window with dictionary tracking |
| Window alignment (spikes) | Sliding window within `PrivilegeSpikeWindowMinutes` | Uses exact timestamp deltas, same as sweeps |
| Window alignment (sweeps) | Continuous sliding within `PrivilegeSpikeWindowMinutes` | Same window size as spikes, tracks distinct ports via dictionary |
| Multiple spike findings | One finding per window that exceeds `PrivilegeSpikeMinAttempts` | Captures sustained or repeated brute-force attempts |
| Sweep reporting | Multiple findings possible — state resets and scanning continues | Detects separate sweeps from the same source |
| Cancellation | Checked in outer per-source loop | Allows graceful shutdown on large inputs |
| Early exit (sweeps) | Skipped if fewer than 3 events | Avoids scan when sweep is impossible |

---

## Implementation Evidence

- [PrivilegeEscalationDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/PrivilegeEscalationDetector.cs) — detector implementation (233 lines)
- [AnalysisProfile.cs](../../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — threshold configuration record (195 lines)
- [AnalysisProfileProvider.cs](../../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — intensity presets (239 lines)
- [PrivilegeEscalationDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/PrivilegeEscalationDetectorTests.cs) — test suite (679 lines)

---

## Security Takeaways

1. The sliding-window spike detector uses exact timestamp deltas for brute-force detection, avoiding quantization boundary artifacts
2. The sliding-window sweep detector catches multi-port enumeration with O(N) efficiency via dictionary-based port tracking
3. The sweep early-exit (skip if fewer than 3 events) avoids unnecessary computation
4. The sweep detector resets state and continues scanning after a match, enabling detection of multiple separate sweeps from the same source
5. Both sub-detectors operate on the same pre-filtered, per-source event stream, avoiding redundant data processing
