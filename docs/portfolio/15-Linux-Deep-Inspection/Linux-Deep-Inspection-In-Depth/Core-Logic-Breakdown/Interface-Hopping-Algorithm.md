# Interface Hopping Algorithm: Network Segmentation Enforcement

## The Security Problem

In multi-homed environments, network interfaces enforce segmentation — traffic from one segment should not appear on another without authorization. An attacker who gains access to a host with multiple network interfaces (e.g., eth0 for DMZ, eth1 for internal LAN, wlan0 for wireless) can pivot between segments, probing services that are otherwise isolated from their initial position.

Simply detecting that a source IP used multiple interfaces is insufficient — legitimate multi-homed servers (e.g., a gateway with eth0/eth1) would produce false positives. The detector uses a sliding window to find the time window with the most distinct interfaces used by a single source IP. The window duration is configurable via `profile.InterfaceHoppingWindowMinutes` (defaulting to 5 minutes), and the detector reports the window that contains the highest count of distinct interfaces — characteristic of active reconnaissance or attack pivoting rather than stable multi-homed configurations.

---

## Implementation Overview

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────────┐     ┌────────────────┐
│  Guard check │────▶│  GroupBy        │────▶│  Filter non-empty    │────▶│  ≥ 2 events    │
│  Enabled?    │     │  SourceIP       │     │  InterfaceIn,        │     │  for this IP?  │
└──────────────┘     └─────────────────┘     │  OrderBy Timestamp   │     └────────────────┘
                                               └──────────────────────┘           │
                                                                         ┌──────┴──────┐
                                                                         │ Yes         │ No
                                                                         ▼             ▼
                                                                ┌──────────────┐  ┌──────────┐
                                                                │ Sliding      │  │ Skip     │
                                                                │ window:      │  │ next IP  │
                                                                │ count        │  └──────────┘
                                                                │ distinct     │
                                                                │ interfaces   │
                                                                └──────┬───────┘
                                                                       │
                                                                ┌──────┴──────┐
                                                                │ bestDistinct│ bestDistinct
                                                                │ > 1         │ ≤ 1
                                                                ▼             ▼
                                                         ┌──────────┐  ┌──────────┐
                                                         │ Emit     │  │ Skip     │
                                                         │ Medium   │  │          │
                                                         └──────────┘  └──────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnableInterfaceHopping || events.Count == 0)
    return DetectionResult.Empty;
```

Immediate exit if interface hopping detection is disabled or no events exist. Returns `DetectionResult.Empty` rather than throwing or allocating a findings list.

---

### Step B — Group by Source IP

```csharp
var byIp = events.GroupBy(e => e.SourceIP);

foreach (var ipGroup in byIp)
{
    cancellationToken.ThrowIfCancellationRequested();

    var ip = ipGroup.Key;
```

Events are grouped by `SourceIP` because interface hopping is defined per-source — the question is whether a single source is switching between interfaces. Each group is processed with a cancellation check.

The sliding window duration is read from the profile:

```csharp
var windowMinutes = profile.InterfaceHoppingWindowMinutes > 0 ? profile.InterfaceHoppingWindowMinutes : 5;
```

This allows the window to be tuned per analysis profile (Low=10, Medium=5, High=10 minutes), defaulting to 5 minutes if not explicitly set.

---

### Step C — Filter and Order Events

```csharp
var ordered = ipGroup
    .Where(e => !string.IsNullOrEmpty(e.LinuxSpecific.GetValueOrDefault("InterfaceIn", "")))
    .OrderBy(e => e.Timestamp)
    .ToList();

if (ordered.Count < 2)
    continue;
```

Events with a non-empty `InterfaceIn` value are filtered and ordered chronologically. If fewer than 2 events have interface metadata for this source IP, the group is skipped — there is no hopping to detect with a single event.

---

### Step D — Sliding Window Distinct-Interface Count

```csharp
var interfaceCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
var distinctInterfaces = 0;
int start = 0;
var bestDistinct = 0;
var bestStart = 0;
var bestEnd = 0;
List<string> bestInterfaces = [];

for (int end = 0; end < ordered.Count; end++)
{
    cancellationToken.ThrowIfCancellationRequested();

    var addIface = ordered[end].LinuxSpecific.GetValueOrDefault("InterfaceIn", "");

    if (interfaceCounts.TryGetValue(addIface, out var cnt))
    {
        interfaceCounts[addIface] = cnt + 1;
    }
    else
    {
        interfaceCounts[addIface] = 1;
        distinctInterfaces++;
    }

    // Shrink window from the left
    while (start < end &&
           (ordered[end].Timestamp - ordered[start].Timestamp).TotalMinutes > windowMinutes)
    {
        var removeIface = ordered[start].LinuxSpecific.GetValueOrDefault("InterfaceIn", "");
        if (!string.IsNullOrEmpty(removeIface) && interfaceCounts.TryGetValue(removeIface, out var removeCnt))
        {
            interfaceCounts[removeIface] = removeCnt - 1;
            if (interfaceCounts[removeIface] == 0)
            {
                interfaceCounts.Remove(removeIface);
                distinctInterfaces--;
            }
        }
        start++;
    }

    if (distinctInterfaces > bestDistinct)
    {
        bestDistinct = distinctInterfaces;
        bestStart = start;
        bestEnd = end;
        bestInterfaces = interfaceCounts.Keys.OrderBy(i => i, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
```

The algorithm uses a sliding window over the chronologically ordered events to find the window with the most distinct interfaces. An `interfaceCounts` dictionary tracks how many events reference each interface within the current window, and `distinctInterfaces` tracks the count of distinct interfaces. As the right end of the window advances, the left side shrinks when the time span exceeds `windowMinutes`, decrementing counts and removing interfaces whose count drops to zero. The best window (highest `bestDistinct`) and its interface list are retained. This approach is O(N) per source IP group and evaluates the *densest* concentration of interface diversity rather than checking consecutive pairs.

---

### Step E — Emit Finding

```csharp
if (bestDistinct > 1)
{
    var minTime = ordered[bestStart].Timestamp;
    var maxTime = ordered[bestEnd].Timestamp;

    findings.Add(new Core.Finding
    {
        Category = FindingCategories.InterfaceHopping,
        Severity = Core.Severity.Medium,
        SourceHost = ip,
        Target = $"{bestInterfaces.Count} network interfaces",
        TimeRangeStart = minTime,
        TimeRangeEnd = maxTime,
        ShortDescription = $"Interface hopping detected from {ip}",
        Details = $"Source IP {ip} sent traffic through {bestInterfaces.Count} different network interfaces ({string.Join(", ", bestInterfaces)}) within {windowMinutes} minutes. ..."
    });
}
```

A Medium-severity finding is emitted when the best sliding window contains more than one distinct interface. The finding includes the interface count, the full interface list (alphabetically sorted), and the time range of the densest hopping window for analyst triage.

---

## Complexity And Behavior

| Aspect | Behavior | Rationale |
|---|---|---|
| Time complexity | O(N log N) per source | Dominated by `OrderBy` on timestamp; sliding window is O(N) |
| Space complexity | O(N) per source | Ordered event list and interface count dictionary stored per IP group |
| Sliding window duration | Configurable via `profile.InterfaceHoppingWindowMinutes` | Defaults to 5 minutes; tunable per sensitivity level (Low=10, Med=5, High=10) |
| Detection criterion | `bestDistinct > 1` — densest window wins | Reports the window with the most distinct interfaces, not just any pair |
| Cancellation | Checked per IP group and per sliding window iteration | Allows graceful shutdown on large inputs |
| Risk escalation | InterfaceHopping + MacSpoofing → Critical | Correlated L2/L3 anomalies |

---

## Implementation Evidence

- [InterfaceHoppingDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/InterfaceHoppingDetector.cs) — detector implementation
- [InterfaceHoppingDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Linux/InterfaceHoppingDetectorTests.cs) — test suite

---

## Security Takeaways

1. The sliding window finds the densest concentration of interface diversity — it reports the window with the most distinct interfaces, filtering out stable multi-homed servers that use different interfaces over hours or days
2. The window duration is configurable via `profile.InterfaceHoppingWindowMinutes`, defaulting to 5 minutes — environments with different network characteristics can tune the sensitivity (Low=10, Med=5, High=10)
3. The detector catches attackers pivoting between network segments to probe isolated services, a pattern invisible to IP-layer analysis
4. The `RiskEscalator` promotes InterfaceHopping+MacSpoofing to Critical — correlated L2 and L3 anomalies indicate a sophisticated multi-vector attack
5. The sliding window algorithm is O(N) per source (after the O(N log N) sort), making it efficient for large log volumes
