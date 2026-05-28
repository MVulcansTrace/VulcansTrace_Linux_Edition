# Flag Anomaly Algorithm: TCP Flag Analysis

## The Security Problem

Attackers use non-standard TCP flag combinations to probe ports while evading basic detection. A FIN scan sends packets with only the FIN flag set — RFC-compliant hosts respond differently to FIN packets on open vs. closed ports, allowing the attacker to enumerate services without ever completing a TCP handshake. An XMAS scan sets FIN, PSH, and URG simultaneously, producing the same port-state discrimination with a different packet profile. Both techniques generate log entries in iptables, but the flag information is only available in Linux-specific metadata.

---

## Implementation Overview

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Guard check │────▶│  Iterate events │────▶│  Protocol filter │────▶│  Extract flags │
│  Enabled?    │     │  + cancellation │     │  TCP only        │     │  LinuxSpecific │
└──────────────┘     └─────────────────┘     └──────────────────┘     └────────────────┘
                                                                              │
                                                                               ▼
                                                ┌──────────────┐     ┌──────────────────┐
                                                │  XMAS check  │     │  FIN w/o SYN     │
                                                │  FIN+PSH+URG │────▶│  (else-if)       │
                                                │  (non-empty) │     │                  │
                                                └──────┬───────┘     └────────┬─────────┘
                                                       └──────┬──────────────┘
                                                              │
                                                              ▼
                                                ┌──────────────────────────────────────┐
                                                │  Aggregate by (SourceIP, AnomalyType)│
                                                └──────────────────┬───────────────────┘
                                                                   ▼
                                                          ┌──────────────┐
                                                          │  Emit one    │
                                                          │  finding per │
                                                          │  group       │
                                                          └──────────────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnableFlagAnomaly || events.Count == 0)
    return DetectionResult.Empty;
```

The detector exits immediately if flag anomaly detection is disabled or there are no events. No data structures are allocated.

---

### Step B — Iterate Events with Protocol Filter and Aggregation Dictionary

```csharp
var groups = new Dictionary<(string SourceIP, string AnomalyType), List<UnifiedEvent>>();

foreach (var evt in events)
{
    cancellationToken.ThrowIfCancellationRequested();

    if (evt.Protocol != "TCP")
        continue;

    var flags = evt.LinuxSpecific.GetValueOrDefault("Flags", "").ToUpper();
```

An aggregation dictionary keyed by `(SourceIP, AnomalyType)` is created before the loop. Each event is checked for cooperative cancellation. Only TCP events proceed — UDP, ICMP, and other protocols have no flag field. The `Flags` value from `LinuxSpecific` is extracted and uppercased for case-insensitive comparison.

---

### Step C — XMAS Check (FIN+PSH+URG) — Runs First

```csharp
if (!string.IsNullOrWhiteSpace(flags) && flags.Contains("FIN") && flags.Contains("PSH") && flags.Contains("URG"))
{
    Aggregate(evt, "XMAS-scan");
}
```

The XMAS check runs first and includes a non-empty guard (`!string.IsNullOrWhiteSpace(flags)`) as a prefix condition. The simultaneous presence of FIN, PSH, and URG is the XMAS scan signature. Each flag is checked independently via `string.Contains`, so the check matches regardless of flag ordering in the string. Matching events are aggregated by `(SourceIP, "XMAS-scan")`.

---

### Step D — FIN-without-SYN Check (Else-If)

```csharp
else if (flags.Contains("FIN") && !flags.Contains("SYN"))
{
    Aggregate(evt, "FIN-without-SYN");
}
```

Because this is an `else if`, it only runs when the XMAS check did not match. A packet with FIN but without SYN is anomalous — normal connection teardown sends FIN only after SYN established the session. This pattern is the hallmark of a FIN scan. Matching events are aggregated by `(SourceIP, "FIN-without-SYN")`.

---

### Step E — Emit One Finding Per Group

```csharp
foreach (var kvp in groups)
{
    var evts = kvp.Value;
    var distinctTargets = evts.Select(e => $"{e.DestinationIP}:{e.DestinationPort}").Distinct().ToList();
    var sampleTargets = distinctTargets.Take(5).ToList();
    var targetList = sampleTargets.Count < distinctTargets.Count
        ? $"{string.Join(", ", sampleTargets)}, ..."
        : string.Join(", ", sampleTargets);

    findings.Add(new Core.Finding
    {
        Category = FindingCategories.FlagAnomaly,
        Severity = Core.Severity.Medium,
        SourceHost = kvp.Key.SourceIP,
        Target = targetList,
        ...
    });
}
```

After all events are processed, one finding is emitted per `(SourceIP, AnomalyType)` group. The target list shows up to 5 distinct `DestIP:DestPort` targets, with a truncation indicator if there are more. Both the description and details vary based on whether the anomaly type is `FIN-without-SYN` or `XMAS-scan`.

---

## Complexity And Behavior

| Aspect | Behavior | Rationale |
|---|---|---|
| Time complexity | O(N) | Single pass over events with O(1) string operations per event |
| Protocol filter | Only TCP events are analyzed | UDP/ICMP have no flags — skipping avoids false negatives |
| Check ordering | XMAS checked first, FIN-without-SYN as else-if | FIN+PSH+URG without SYN is classified as XMAS, not FIN-without-SYN |
| One finding per group | Aggregated by (SourceIP, AnomalyType) | Analysts see one alert per source+type with target summary |
| Cancellation | Checked per event | Allows graceful shutdown on large inputs |

---

## Implementation Evidence

- [FlagAnomalyDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/FlagAnomalyDetector.cs) — detector implementation (86 lines)
- [FlagAnomalyDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Linux/FlagAnomalyDetectorTests.cs) — test suite (422 lines)

---

## Security Takeaways

1. The XMAS check detects a specific evasion technique used by tools like Nmap for OS fingerprinting and port state enumeration
2. The FIN-without-SYN check detects stealth scans that bypass port-counting detectors because each target is probed only once
3. The XMAS check includes a built-in non-empty guard (`!string.IsNullOrWhiteSpace(flags)`) to avoid matching events with no flag metadata
4. Events are aggregated by `(SourceIP, AnomalyType)` — one finding per source+type group, preventing alert fatigue from repeated scans
5. The detector integrates with `RiskEscalator` — when a FlagAnomaly finding is correlated with a PortScan finding from the same host, both are escalated to Critical severity
