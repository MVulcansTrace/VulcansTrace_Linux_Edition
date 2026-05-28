# Kernel Module Algorithm: Firewall Posture Assessment

## The Security Problem

Understanding a firewall's active capabilities is essential for risk assessment. An attacker who knows that conntrack (stateful inspection) is disabled, or that rate limiting is not configured, can tailor their attack to exploit those gaps. Conversely, analysts need to know which defensive modules are active to assess the network's security posture and identify potential weaknesses.

The KernelModuleDetector performs keyword-based posture assessment by scanning raw log lines for signatures of specific iptables/nftables kernel modules and extensions. This provides a quick inventory of firewall capabilities without requiring direct access to the firewall configuration.

---

## Implementation Overview

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Guard check │────▶│  Iterate events │────▶│  Scan RawLine    │────▶│  Match         │
│  Enabled?    │     │  + cancellation │     │  for signatures  │     │  signatures    │
└──────────────┘     └─────────────────┘     └──────────────────┘     └────────────────┘
                                                                                │
                                                                                ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Emit one    │────▶│  Emit finding   │◀────│  Record to       │◀────│  conntrack/CT  │
│  Info finding│     │  per module     │     │  Dictionary      │     │  limit/rate    │
│  per module  │     │  with time range│     │  (timestamps)    │     │  IPv6/l7/quota │
└──────────────┘     └─────────────────┘     └──────────────────┘     └────────────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnableKernelModule || events.Count == 0)
    return DetectionResult.Empty;
```

Immediate exit if kernel module detection is disabled or no events exist.

---

### Step B — Iterate Events and Scan Raw Lines

```csharp
var moduleTimestamps = new Dictionary<string, List<DateTime>>();

void RecordModule(string moduleName, DateTime timestamp)
{
    if (!moduleTimestamps.TryGetValue(moduleName, out var list))
    {
        list = new List<DateTime>();
        moduleTimestamps[moduleName] = list;
    }
    list.Add(timestamp);
}

foreach (var evt in events)
{
    cancellationToken.ThrowIfCancellationRequested();

    var rawLine = evt.RawLine ?? "";
```

A `Dictionary<string, List<DateTime>>` tracks detected modules and their timestamps across all events. Each event's `RawLine` is scanned for keyword signatures. The null-coalescing operator handles events without raw log data. The `RecordModule` helper lazily creates a timestamp list for each new module name and appends the current event's timestamp.

---

### Step C — Signature Matching

```csharp
// Connection Tracking
if (FirewallLogRegex.IsWholeToken(rawLine, "conntrack")
    || FirewallLogRegex.IsWholeToken(rawLine, "CT"))
    RecordModule("Connection Tracking (conntrack)", evt.Timestamp);

// Rate Limiting
if (FirewallLogRegex.IsWholeToken(rawLine, "limit")
    || FirewallLogRegex.IsWholeToken(rawLine, "rate"))
    RecordModule("Rate Limiting", evt.Timestamp);

// IPv6 Support
if (evt.SourceIP.Contains(":") || evt.DestinationIP.Contains(":"))
    RecordModule("IPv6 Support", evt.Timestamp);

// Layer 7 Filtering
if (FirewallLogRegex.IsWholeToken(rawLine, "layer7")
    || FirewallLogRegex.IsWholeToken(rawLine, "l7"))
    RecordModule("Layer 7 Filtering", evt.Timestamp);

// Quota/Bandwidth Limiting
if (FirewallLogRegex.IsWholeToken(rawLine, "quota")
    || FirewallLogRegex.IsWholeToken(rawLine, "hashlimit"))
    RecordModule("Quota/Bandwidth Limiting", evt.Timestamp);
```

Five independent signature checks run per event:

| Signature | Module Detected | Method |
|---|---|---|
| `"conntrack"` as whole token or `CT` as whole token | Connection Tracking | `IsWholeToken` |
| `"limit"` or `"rate"` as whole token | Rate Limiting | `IsWholeToken` |
| `":"` in SourceIP or DestIP | IPv6 Support | IP address format check |
| `"layer7"` as whole token or `l7` as whole token | Layer 7 Filtering | `IsWholeToken` |
| `"quota"` as whole token or `"hashlimit"` as whole token | Quota/Bandwidth Limiting | `IsWholeToken` |

Several signatures use `FirewallLogRegex.IsWholeToken` for whole-token matching rather than simple substring search — this prevents false positives from partial matches (e.g., `"limit"` matching inside `"unlimited"`). Others use `StringComparison.OrdinalIgnoreCase` for case-insensitive matching where log output may vary in casing. The IPv6 check uses IP address format rather than raw line content because IPv6 addresses contain colons, which are a reliable indicator of IPv6 traffic.

---

### Step D — Emit Findings

```csharp
foreach (var (module, timestamps) in moduleTimestamps)
{
    findings.Add(new Core.Finding
    {
        Category = FindingCategories.KernelModule,
        Severity = Core.Severity.Info,
        SourceHost = "Firewall Configuration",
        Target = module,
        TimeRangeStart = timestamps.Min(),
        TimeRangeEnd = timestamps.Max(),
        ShortDescription = $"Detected {module}",
        Details = $"Analysis of firewall logs indicates the use of {module}. ..."
    });
}
```

One Info-severity finding is emitted per detected module. The `SourceHost` is set to `"Firewall Configuration"` rather than a specific IP because this is a posture assessment, not a per-host detection. The time range is computed from the module's own timestamp list — `timestamps.Min()` and `timestamps.Max()` — reflecting when the module was actually observed, not the full event set. The severity is Info because detected modules are not threats — they are defensive capabilities (or the absence of which indicates gaps).

---

## Complexity And Behavior

| Aspect | Behavior | Rationale |
|---|---|---|
| Time complexity | O(N × S) | N events × S signatures per event (S = 5) |
| Space complexity | O(K) | K = detected modules (max 5) |
| Data structure | `Dictionary<string, List<DateTime>>` | Stores per-module timestamps for accurate time range reporting |
| Finding severity | Info | Posture assessment, not threat detection |
| Cancellation | Checked per event | Allows graceful shutdown on large inputs |
| Signature methods | `IsWholeToken` + `Contains` with `OrdinalIgnoreCase` | Whole-token matching prevents partial-match false positives; case-insensitive matching handles log format variation |

---

## Implementation Evidence

- [KernelModuleDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/KernelModuleDetector.cs) — detector implementation
- [KernelModuleDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Linux/KernelModuleDetectorTests.cs) — test suite

---

## Security Takeaways

1. Keyword-based posture assessment provides quick visibility into active firewall capabilities without requiring configuration file access
2. Whole-token matching via `IsWholeToken` prevents false positives from partial substring matches — e.g., `"limit"` won't match inside `"unlimited"`
3. Case-insensitive matching via `StringComparison.OrdinalIgnoreCase` handles log format variation across different iptables/nftables versions
4. Info severity reflects that detected modules are defensive indicators, not threats — but their absence may indicate gaps worth investigating
5. The IPv6 detection via IP address format is more reliable than raw line scanning because IPv6 addresses have a distinctive structure
6. The detector is most useful as part of a broader assessment — analysts should compare detected modules against expected baseline configurations
