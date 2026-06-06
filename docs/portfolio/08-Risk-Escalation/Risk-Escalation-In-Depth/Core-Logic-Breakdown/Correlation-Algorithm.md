# Risk Escalation — Correlation Algorithm

A step-by-step walkthrough of how `RiskEscalator.Escalate` transforms raw detector findings into escalated results.

---

## Input

The method receives `IReadOnlyList<Finding>` — the combined output of all three detection layers (baseline, Linux deep inspection, advanced) collected by `SentryAnalyzer`.

---

## Step 1: Early Exit on Empty Input

```csharp
if (findings.Count == 0)
    return Array.Empty<Finding>();
```

If no detectors produced findings, return immediately with an empty array. This avoids allocating a `List` and running `GroupBy` on zero elements.

Source: [RiskEscalator.cs:28-29](../../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Step 2: Allocate Result Buffer

```csharp
var result = new List<Finding>(findings.Count);
```

The result list is pre-allocated to the exact count of input findings. Every input finding will appear in the output either unchanged or escalated — the count is always the same.

Source: [RiskEscalator.cs:31](../../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Step 3: Group Findings by Source Host

```csharp
var byHost = findings.GroupBy(f => f.SourceHost);
```

Findings are partitioned by `SourceHost` using LINQ `GroupBy`. Each group represents all findings attributed to a single source IP address. Correlation rules only fire within a group — cross-host escalation is not performed.

Findings with a null `SourceHost` are grouped together under the `null` key.

Source: [RiskEscalator.cs:33](../../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Step 4: Build Category Set Per Host

```csharp
var groupFindings = group.ToList();
var categories = groupFindings
    .Select(f => f.Category)
    .ToHashSet(StringComparer.OrdinalIgnoreCase);
```

For each host group, a case-insensitive `HashSet<string>` is built from the `Category` values of all findings on that host. This deduplicates categories (e.g., three PortScan findings on the same host produce a single "PortScan" entry in the set).

Source: [RiskEscalator.cs:36-37](../../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Step 5: Evaluate Correlation Rules

Three boolean flags are computed by checking whether both categories in each rule exist in the host's category set:

```csharp
var hasBeacon          = categories.Contains("Beaconing");
var hasLateral         = categories.Contains("LateralMovement");
var hasFlagAnomaly     = categories.Contains("FlagAnomaly");
var hasPortScan        = categories.Contains("PortScan");
var hasMacSpoofing     = categories.Contains("MacSpoofing");
var hasInterfaceHopping = categories.Contains("InterfaceHopping");
```

Category presence is necessary but **not sufficient** for escalation. Each rule also requires that at least one pair of findings (one from each category) have time ranges within 24 hours of each other. This is checked by `AreTimeRangesCorrelated`:

```csharp
var shouldEscalateBeaconLateral = hasBeacon && hasLateral
    && AreTimeRangesCorrelated(groupFindings, "Beaconing", "LateralMovement");
var shouldEscalateFlagPort = hasFlagAnomaly && hasPortScan
    && AreTimeRangesCorrelated(groupFindings, "FlagAnomaly", "PortScan");
var shouldEscalateMacInterface = hasMacSpoofing && hasInterfaceHopping
    && AreTimeRangesCorrelated(groupFindings, "MacSpoofing", "InterfaceHopping");
```

`AreTimeRangesCorrelated` sorts findings from both categories by `TimeRangeStart` and uses a two-pointer sliding window. For each finding in category A, it advances a pointer through category B to skip pairs that end more than 24 hours before A starts, and breaks early when B starts more than 24 hours after A ends. Only if a surviving pair has a gap ≤ 24 hours (computed by `GetTimeGapHours`) does the rule fire.

Source: [RiskEscalator.cs:39-54](../../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) and [RiskEscalator.cs:73-111](../../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Step 6: Escalate or Pass Through

```csharp
foreach (var f in group)
{
    var participates =
        (shouldEscalateBeaconLateral && (IsCategory(f, FindingCategories.Beaconing) || IsCategory(f, FindingCategories.LateralMovement)))
        || (shouldEscalateFlagPort && (IsCategory(f, FindingCategories.FlagAnomaly) || IsCategory(f, FindingCategories.PortScan)))
        || (shouldEscalateMacInterface && (IsCategory(f, FindingCategories.MacSpoofing) || IsCategory(f, FindingCategories.InterfaceHopping)));

    if (participates && f.Severity < Severity.Critical)
    {
        var correlationSignal = new EvidenceSignal
        {
            Name = "Cross-detector correlation",
            Source = EvidenceSignal.BehaviorSource,
            Explanation = $"Correlated {f.Category} with complementary threat pattern on same host within 24h"
        };
        var escalatedSignals = f.EvidenceSignals.Concat(new[] { correlationSignal }).ToList();
        result.Add(f with
        {
            Severity = Severity.Critical,
            Confidence = FindingConfidenceCalculator.Calculate(escalatedSignals),
            EvidenceSignals = escalatedSignals
        });
    }
    else
    {
        result.Add(f);
    }
}
```

For each finding in the host group:

- The `participates` check determines whether this finding's category is part of a correlation rule that fired. Only findings whose categories directly participate in a matched rule pair are eligible for escalation.
- If `participates` is true **and** the finding's severity is below Critical, a new `Finding` record is created with `Severity = Critical` using the C# `with` expression. A `Cross-detector correlation` evidence signal is appended, and confidence is recalculated via `FindingConfidenceCalculator`. All other properties (Id, Category, SourceHost, Target, TimeRangeStart, TimeRangeEnd, ShortDescription, Details) are preserved from the original.
- If the finding is already Critical, its category does not participate in any fired rule, or no rule fired, the original finding is added unchanged.

Key implication: only findings whose categories participate in a matched correlation rule are promoted to Critical. A Novelty finding on a host that also has Beaconing + LateralMovement will **not** be escalated — only the Beaconing and LateralMovement findings are promoted.

Source: [RiskEscalator.cs:56-78](../../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Step 7: Return Complete Result

```csharp
return result;
```

The `result` list contains exactly the same number of findings as the input. Every input finding is represented — either at its original severity or escalated to Critical.

Source: [RiskEscalator.cs:70](../../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Complexity Analysis

| Operation | Complexity |
|-----------|-----------|
| GroupBy | O(n) |
| HashSet construction per group | O(k) per host, O(n) total |
| Category lookups per group | O(1) per lookup (HashSet) |
| Time-range correlation (worst case) | O(a × b) per host, where a and b are findings counts for the two categories |
| Time-range correlation (typical) | O(a + b) with the two-pointer sliding window when findings are temporally distributed |
| Finding iteration | O(n) |
| **Total** | **O(n)** typical, **O(n + a × b)** worst case |

The algorithm is linear in the number of findings for typical workloads because the sliding-window correlation early-exits on the first match and skips large temporal gaps. Only when many findings from both categories cluster within a 48-hour window does the worst-case pairwise comparison occur.

---

## Security Takeaways

- The algorithm is deterministic: given the same input findings, it always produces the same escalated output
- Immutability is enforced at the type level — `Finding` is a `sealed record` with init-only setters, so the `with` expression is the only way to produce a modified copy
- The escalation decision is targeted (Critical or unchanged) and applies only to findings whose categories participate in a matched correlation rule — this reflects the principle that correlated threat signals on the same host elevate confidence for those specific categories without overgeneralizing to unrelated findings
- The 24-hour time-range gate prevents escalation from stale, unrelated findings that happen to share a host
