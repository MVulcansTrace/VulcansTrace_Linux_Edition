# MAC Spoofing Algorithm: MAC-to-IP Integrity Verification

## The Security Problem

In switched Ethernet networks, the MAC address is the fundamental identifier at Layer 2. ARP poisoning attacks work by associating an attacker's MAC address with a legitimate IP address, causing switches to deliver traffic to the attacker instead of the intended host. Similarly, an attacker may cycle through multiple MAC addresses to evade MAC-based filtering or to impersonate multiple devices.

A single IP address that appears with multiple distinct MAC addresses in firewall logs is a strong indicator of ARP poisoning, MAC spoofing, or network masquerading — all of which undermine L2 trust assumptions.

---

## Implementation Overview

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────────┐
│  Guard check │────▶│  GroupBy        │────▶│  Normalize MACs  │────▶│  Order by      │
│  Enabled?    │     │  SourceIP       │     │  + filter empty  │     │  Timestamp     │
└──────────────┘     └─────────────────┘     └──────────────────┘     └────────────────┘
                                                                              │
                                                                               ▼
                                                      ┌──────────────┐     ┌──────────────┐
                                                      │  Sliding     │────▶│  Best window │
                                                      │  window scan │     │  > 1 MAC?    │
                                                      │  (N minutes) │     └──────┬───────┘
                                                      └──────────────┘            │
                                                                           ┌───┴───┐
                                                                           │ Yes   │ No
                                                                           ▼       ▼
                                                                  ┌──────────┐ ┌──────┐
                                                                  │Emit      │ │Skip  │
                                                                  │High sev. │ │next  │
                                                                  └──────────┘ └──────┘
```

---

### Step A — Guard Check

```csharp
if (!profile.EnableMacSpoofing || events.Count == 0)
    return DetectionResult.Empty;
```

Immediate exit if MAC spoofing detection is disabled or no events exist.

---

### Step B — Group by Source IP

```csharp
var windowMinutes = profile.MacSpoofingWindowMinutes > 0
    ? profile.MacSpoofingWindowMinutes
    : DefaultWindowMinutes; // 5

var byIp = events.GroupBy(e => e.SourceIP);

foreach (var ipGroup in byIp)
{
    cancellationToken.ThrowIfCancellationRequested();

    var ip = ipGroup.Key;
```

Events are grouped by `SourceIP` because MAC spoofing is defined per-IP — the question is whether a single IP is using multiple MAC addresses. A configurable time window (`MacSpoofingWindowMinutes`, default 5 minutes) controls how tightly the MAC changes must be spaced. Each IP group is processed independently with a cancellation check.

---

### Step C — Extract, Normalize, and Order MAC Addresses

```csharp
var ordered = ipGroup
    .Where(e => !string.IsNullOrEmpty(e.LinuxSpecific.GetValueOrDefault("MAC", "")))
    .Select(e => new
    {
        Event = e,
        Mac = FirewallLogRegex.NormalizeMacField(e.LinuxSpecific.GetValueOrDefault("MAC", ""))
    })
    .Where(e => !string.IsNullOrEmpty(e.Mac))
    .OrderBy(e => e.Event.Timestamp)
    .ToList();

if (ordered.Count < 2)
    continue;
```

The LINQ pipeline filters out events with empty or missing MAC values, normalizes each MAC address via `FirewallLogRegex.NormalizeMacField` to ensure consistent comparison (e.g., `aa:bb:cc:dd:ee:ff` vs. `AA:BB:CC:DD:EE:FF`), filters again to remove events whose normalized MAC is empty, and orders the results by timestamp. The second filter after normalization handles cases where the raw MAC value was present but not parseable. Events with fewer than 2 valid MAC entries are skipped.

---

### Step D — Sliding Window Scan for Maximum Distinct MACs

```csharp
var macCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
var distinctMacs = 0;
var start = 0;
var bestDistinctMacs = 0;
var bestStart = 0;
var bestEnd = 0;
List<string> bestMacAddresses = [];

for (var end = 0; end < ordered.Count; end++)
{
    // Add MAC at position end
    // Shrink window from left while time span > windowMinutes
    // Track best (maximum distinct MACs) window seen
}
```

A two-pointer sliding window scans the time-ordered events. As the `end` pointer advances, each MAC is added to the window's count dictionary. The `start` pointer advances to shrink the window whenever the time span exceeds `windowMinutes`, decrementing counts and removing MACs that fall to zero. The window with the most distinct MACs is tracked as `bestDistinctMacs` along with its boundaries and MAC list. This finds the tightest cluster of MAC diversity for the IP.

---

### Step E — Multi-MAC Check and Finding Emission

```csharp
if (bestDistinctMacs > 1)
{
    var minTime = ordered[bestStart].Event.Timestamp;
    var maxTime = ordered[bestEnd].Event.Timestamp;

    findings.Add(new Core.Finding
    {
        Category = FindingCategories.MacSpoofing,
        Severity = Core.Severity.High,
        SourceHost = ip,
        Target = "multiple MAC addresses",
        TimeRangeStart = minTime,
        TimeRangeEnd = maxTime,
        ShortDescription = $"Potential MAC spoofing from {ip}",
        Details = $"IP address {ip} is associated with {bestMacAddresses.Count} different MAC addresses within {windowMinutes} minutes: {string.Join(", ", bestMacAddresses)}. ..."
    });
}
```

If the best window found more than one distinct MAC address, a High-severity finding is emitted. The finding includes the MAC count, the full list of MAC addresses from the best window, and the time range of that window (not the entire IP group). The severity is High because MAC spoofing directly undermines L2 trust and often indicates active exploitation.

---

## Complexity And Behavior

| Aspect | Behavior | Rationale |
|---|---|---|
| Time complexity | O(N log N) | GroupBy + per-group OrderBy + linear sliding window scan |
| Space complexity | O(M) | M = distinct MACs per IP group within the window |
| MAC normalization | `FirewallLogRegex.NormalizeMacField` | Ensures format-consistent comparison (case, separators) |
| Time-bounded window | Configurable via `MacSpoofingWindowMinutes` (default 5) | Prevents false positives from legitimate MAC changes spread over hours |
| Best-window tracking | Reports the window with maximum MAC diversity | Finds the strongest spoofing signal rather than diluting across the full time range |
| Single finding per IP | One finding even if many MACs | Analysts see the full MAC list in one alert |
| Cancellation | Checked per IP group and per window step | Allows graceful shutdown on large inputs |
| Risk escalation | MacSpoofing + InterfaceHopping → Critical | Correlated L2/L3 anomalies indicate sophisticated attack |

---

## Implementation Evidence

- [MacSpoofingDetector.cs](../../../../../VulcansTrace.Linux.Engine/Detectors/MacSpoofingDetector.cs) — detector implementation (121 lines)
- [MacSpoofingDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Linux/MacSpoofingDetectorTests.cs) — test suite (643 lines)

---

## Security Takeaways

1. A single IP associated with multiple MAC addresses within a short time window is a strong L2 anomaly indicator — the detector flags this at High severity
2. MAC normalization via `FirewallLogRegex.NormalizeMacField` prevents the same MAC in different formats from being counted as distinct addresses
3. The sliding window algorithm finds the tightest cluster of MAC diversity, avoiding false positives from legitimate long-term MAC changes (e.g., VM migration)
4. The finding includes the full MAC address list from the best window, enabling analysts to identify which MACs are legitimate and which are suspicious
5. The `RiskEscalator` promotes MacSpoofing+InterfaceHopping to Critical — correlated L2 and L3 anomalies suggest a coordinated attack
