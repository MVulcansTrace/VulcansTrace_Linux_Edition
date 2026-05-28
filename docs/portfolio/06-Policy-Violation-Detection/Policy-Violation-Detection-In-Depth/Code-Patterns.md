# Policy Violation Detection — Code Patterns

## Security Problem

Policy violation detection must evaluate every event with complete reliability — a missed violation could represent undetected data exfiltration or a compliance gap. The implementation uses minimal, straightforward patterns that are easy to audit and minimize the surface for implementation errors.

---

## Implementation Overview

| Pattern | Location | Purpose |
|---|---|---|
| Guard clause | Lines 10-11 | Early return when disabled or empty |
| Null-coalescing | Line 13 | Graceful handling of missing configuration |
| HashSet lookup | Line 27 | O(1) port membership check |
| Triple-continue filter | Lines 21-28 | Flat, readable three-condition check |
| Dictionary grouping | Lines 15, 30-36 | Group matching events by (SourceIP, DstPort) |
| Per-group finding | Lines 41-60 | Aggregated finding per group |

---

## How It Works

### Guard Clause Pattern

```csharp
if (!profile.EnablePolicy || events.Count == 0)
    return DetectionResult.Empty;
```

Follows the same pattern as all other detectors. Zero-cost when disabled.

---

### Null-Coalescing for Configuration Safety

```csharp
var disallowed = new HashSet<int>(profile.DisallowedOutboundPorts ?? Array.Empty<int>());
```

If `DisallowedOutboundPorts` is null, the `?? Array.Empty<int>()` provides an empty array. The resulting empty `HashSet` means no ports are disallowed, and the detector produces zero findings. This is fail-safe: misconfiguration produces no violations rather than all violations.

---

### Triple-Continue Filter

```csharp
if (!IpClassification.IsInternal(e.SourceIP))
    continue;

if (!IpClassification.IsExternal(e.DestinationIP))
    continue;

if (!disallowed.Contains(e.DestinationPort))
    continue;
```

Three independent conditions, each with its own `continue`. This flat structure avoids nested `if` blocks and makes each condition independently testable. The order matters for performance:

1. `IsInternal()` — eliminates most events (in typical network environments, where the majority of traffic has external sources)
2. `IsExternal()` — same cost as `IsInternal()`, eliminates internal-to-internal traffic
3. `Contains()` — O(1) but requires the HashSet lookup

---

### Per-Group Finding with Aggregated Details

```csharp
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

Each finding aggregates all matching events for a `(SourceIP, DstPort)` group. The `minTime`/`maxTime` across the group provides the time range, and `distinctTargetIps.Count` counts how many unique external IPs were contacted — everything an analyst needs to investigate the violation without cross-referencing other data.

The `Target` field shows the specific destination IP when only one was contacted, or `"multiple hosts:{port}"` when the source reached multiple external destinations on the same disallowed port.

---

### Cancellation Token in a Tight Loop

```csharp
foreach (var e in events)
{
    cancellationToken.ThrowIfCancellationRequested();
```

Even though the policy violation detector is O(n) with no expensive operations, the cancellation check is still present. On very large log files (millions of events), even a tight loop can take significant wall-clock time.

---

## Implementation Evidence

- [PolicyViolationDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/PolicyViolationDetector.cs) — all patterns in context (71 lines)
- [IpClassification.cs](../../../../VulcansTrace.Linux.Engine/Net/IpClassification.cs) — `IsInternal()` and `IsExternal()` used in filter (157 lines)
- [PolicyViolationDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PolicyViolationDetectorTests.cs) — validates filter conditions (138 lines)

---

## Security Takeaways

- The triple-continue filter pattern is a highly auditable structure for multi-condition checks — each condition is independently visible and testable
- Null-coalescing on configuration prevents crashes and ensures fail-safe behavior
- Per-group findings aggregate all matching events for a `(SourceIP, DstPort)` pair, providing both the event count and distinct destination count for forensic context
- The ordering of conditions (broadest filter first) short-circuits the hot path without sacrificing correctness
