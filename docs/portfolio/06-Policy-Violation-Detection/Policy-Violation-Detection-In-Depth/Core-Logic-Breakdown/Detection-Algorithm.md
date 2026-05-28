# Policy Violation Detection — Detection Algorithm

## Security Problem

Organizations define acceptable outbound network protocols as part of their security policy. Connections on disallowed ports represent either a policy violation (misconfigured service), a potential data exfiltration attempt, or active command-and-control communication. The detection challenge is not algorithmic complexity but completeness — every violation must be caught, not just the most obvious ones.

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
    │ Step B: Build Set    │  HashSet from DisallowedOutboundPorts
    └────────┬────────────┘
             v
     ┌─────────────────────┐
     │ Step C: Iterate      │  For each event:
     │   & Filter & Group   │   - Internal source?
     │                      │   - External dest?
     │                      │   - Disallowed port?
     │                      │   Group by (SourceIP, DstPort)
     └────────┬────────────┘
              v
     ┌─────────────────────┐
     │ Step D: Report       │  Emit one finding per group
     └─────────────────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnablePolicy || events.Count == 0)
    return DetectionResult.Empty;
```

Returns immediately if the detector is disabled or the event list is empty. Identical pattern to all detectors.

---

### Step B — Build Disallowed Port Set

```csharp
var disallowed = new HashSet<int>(profile.DisallowedOutboundPorts ?? Array.Empty<int>());
```

Constructs a `HashSet<int>` from the profile's disallowed ports. The null coalescing (`?? Array.Empty<int>()`) handles the case where the profile does not define disallowed ports, defaulting to an empty set (which effectively disables detection).

Provider-configured disallowed ports (all intensity levels): 21 (FTP), 23 (Telnet), 445 (SMB). Note: the record default for `DisallowedOutboundPorts` is an empty list; these values apply only when using `AnalysisProfileProvider`.

---

### Step C — Iterate, Filter, and Group

```csharp
var groups = new Dictionary<(string SourceIP, int DstPort), List<UnifiedEvent>>();

foreach (var e in events)
{
    cancellationToken.ThrowIfCancellationRequested();

    if (!IpClassification.IsInternal(e.SourceIP))
        continue;

    if (!IpClassification.IsExternal(e.DestinationIP))
        continue;

    if (!disallowed.Contains(e.DestinationPort))
        continue;

    var key = (e.SourceIP, e.DestinationPort);
    if (!groups.TryGetValue(key, out var list))
    {
        list = new List<UnifiedEvent>();
        groups[key] = list;
    }
    list.Add(e);
}
```

Each event is evaluated against three independent conditions, then grouped:

1. **Source is internal** — `IpClassification.IsInternal()` checks RFC 1918 ranges (10.x, 172.16-31.x, 192.168.x) and IPv6 ULA (`fc00::/7`), link-local (`fe80::/10`), and loopback
2. **Destination is external** — `IpClassification.IsExternal()` ensures the target is outside the organization
3. **Port is disallowed** — `HashSet.Contains()` provides O(1) membership check
4. **Group by (SourceIP, DstPort)** — matching events are collected into a dictionary for aggregation

The `continue` pattern (guard clauses per event) keeps the nesting flat and the logic readable. Events that pass all three filters are grouped by `(SourceIP, DstPort)` using dictionary-based accumulation.

---

### Step D — Emit Findings Per Group

```csharp
var findings = new List<Core.Finding>();

foreach (var kvp in groups)
{
    cancellationToken.ThrowIfCancellationRequested();

    var evts = kvp.Value;
    var minEvents = profile.PolicyViolationMinEvents > 0 ? profile.PolicyViolationMinEvents : 1;
    if (evts.Count < minEvents)
        continue;
    var minTime = evts.Min(e => e.Timestamp);
    var maxTime = evts.Max(e => e.Timestamp);
    var distinctTargetIps = evts.Select(e => e.DestinationIP).Distinct().ToList();

    findings.Add(new Core.Finding
    {
        Category = FindingCategories.PolicyViolation,
        Severity = Core.Severity.High,
        SourceHost = kvp.Key.SourceIP,
        Target = distinctTargetIps.Count == 1
            ? $"{distinctTargetIps[0]}:{kvp.Key.DstPort}"
            : $"multiple hosts:{kvp.Key.DstPort}",
        TimeRangeStart = minTime,
        TimeRangeEnd = maxTime,
        ShortDescription = $"Disallowed outbound port {kvp.Key.DstPort} from {kvp.Key.SourceIP}",
        Details = $"{evts.Count} outbound connection(s) to {distinctTargetIps.Count} destination(s) on disallowed port {kvp.Key.DstPort} from {kvp.Key.SourceIP}."
    });
}

return new DetectionResult(findings);
```

Events are grouped by `(SourceIP, DstPort)` — each group produces a single finding that aggregates all matching events. The `minTime`/`maxTime` across the group provides the time range, and `distinctTargetIps.Count` counts how many unique external IPs were contacted.

The `Target` field shows the specific destination IP when only one was contacted, or `"multiple hosts:{port}"` when the source reached multiple external destinations on the same disallowed port. `Details` includes the total connection count and distinct destination count for forensic context.

---

## Complexity And Behavior

| Aspect | Detail |
|---|---|
| Time complexity | O(n) — single pass, constant-time checks per event |
| Space complexity | O(k) — k = number of violations found |
| Intermediate state | Dictionary grouping by (SourceIP, DstPort) |
| Port lookup | O(1) — HashSet |
| IP classification | O(1) — byte-based RFC 1918 check |

---

## Implementation Evidence

- [PolicyViolationDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/PolicyViolationDetector.cs) — full implementation (71 lines)
- [IpClassification.cs](../../../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — IP classification used in filter (157 lines)
- [AnalysisProfile.cs](../../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — disallowed port configuration (195 lines)
- [PolicyViolationDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PolicyViolationDetectorTests.cs) — test coverage (138 lines)
