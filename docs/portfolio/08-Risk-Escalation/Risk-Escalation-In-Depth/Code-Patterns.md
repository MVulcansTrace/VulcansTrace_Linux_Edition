# Risk Escalation — Code Patterns

Recurring implementation patterns in the risk escalation subsystem and how they support reliability, testability, and forensic integrity.

---

## Pattern 1: Immutable Record with `with` Expression

The `Finding` type is a `sealed record` with init-only setters. Escalation uses the `with` expression to produce modified copies:

```csharp
// RiskEscalator.cs:64-78
var correlationSignal = new EvidenceSignal
{
    Name = "Cross-detector correlation",
    Source = EvidenceSignal.BehaviorSource,
    Explanation = $"Correlated {f.Category} with complementary threat pattern on same host within 24h"
};
var escalatedSignals = f.EvidenceSignals.Concat(new[] { correlationSignal }).ToList();
result.Add(f with
{
    Severity = Core.Severity.Critical,
    Confidence = FindingConfidenceCalculator.Calculate(escalatedSignals),
    EvidenceSignals = escalatedSignals
});
```

**Why it matters**: The original finding cannot be mutated after creation. This is a compile-time guarantee, not a runtime convention. For forensic analysis, this means the detector's original severity assessment is always preserved alongside the escalated version. Additionally, a `Cross-detector correlation` evidence signal is appended and confidence is recalculated via `FindingConfidenceCalculator`, so the escalated finding reflects the stronger combined evidence.

**Where it appears**: [RiskEscalator.cs:64](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs), [Finding.cs](../../../../VulcansTrace.Linux.Core/Finding.cs)

---

## Pattern 2: LINQ GroupBy for Host Partitioning

Findings are partitioned by source host using `GroupBy`:

```csharp
// RiskEscalator.cs:33
var byHost = findings.GroupBy(f => f.SourceHost);
```

**Why it matters**: `GroupBy` produces an `IEnumerable<IGrouping<string, Finding>>` that is lazy-evaluated. Each group is processed independently, and the correlation logic never needs to sort or index the full finding set. This keeps memory usage proportional to the number of unique hosts.

**Where it appears**: [RiskEscalator.cs:33](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Pattern 3: Case-Insensitive HashSet for Category Lookup

Category membership is checked via a case-insensitive `HashSet<string>`:

```csharp
// RiskEscalator.cs:37
var categories = groupFindings.Select(f => f.Category)
    .ToHashSet(StringComparer.OrdinalIgnoreCase);
```

**Why it matters**: Detector implementations define their own `Category` strings (e.g., "PortScan", "LateralMovement"). The case-insensitive comparison ensures that a detector returning "portscan" or "PORTSCAN" would still match the correlation rule. This is a defensive pattern that prevents false negatives from casing inconsistencies.

**Where it appears**: [RiskEscalator.cs:37](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Pattern 4: Pre-Allocated Result List

The result buffer is pre-allocated to the exact input count:

```csharp
// RiskEscalator.cs:31
var result = new List<Core.Finding>(findings.Count);
```

**Why it matters**: The escalator always produces exactly as many findings as it receives (no filtering, no deduplication). Pre-allocating avoids resize operations and reduces GC pressure for large finding sets.

**Where it appears**: [RiskEscalator.cs:31](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs)

---

## Pattern 5: Three-Layer Detection with Uniform Interface

All detectors implement the same `IDetector` interface:

```csharp
// IDetector.cs
DetectionResult Detect(
    IReadOnlyList<UnifiedEvent> events,
    AnalysisProfile profile,
    CancellationToken cancellationToken);
```

The three layers in `SentryAnalyzer` — baseline, Linux deep inspection, and advanced — iterate over their respective `IReadOnlyList<IDetector>` collections using identical try/catch logic:

```csharp
// SentryAnalyzer.cs:124-144 (Layer 1), 146-166 (Layer 2), 168-188 (Layer 3)
foreach (var detector in _baselineDetectors)
{
    cancellationToken.ThrowIfCancellationRequested();
    try
    {
        var detected = detector.Detect(normalized.Events, profile, cancellationToken);
        allFindings.AddRange(detected.Findings);
        warnings.AddRange(detected.Warnings);
    }
    catch (OperationCanceledException) { throw; }
    catch (Exception ex) when (ex is not OutOfMemoryException
                            && ex is not StackOverflowException
                            && ex is not AccessViolationException
                            && ex is not AppDomainUnloadedException
                            && ex is not ThreadAbortException)
    {
        warnings.Add($"Baseline detector {detector.GetType().Name} crashed ({ex.GetType().Name}).");
    }
}
```

**Why it matters**: The uniform interface means new detectors can be added to any layer without changing the orchestration logic. The identical fault-isolation pattern in each layer ensures consistent error handling. The `allFindings` accumulator collects findings from all three layers before escalation. The exception filter is inlined (not a separate method) to keep the logic visible at the call site.

**Where it appears**: [SentryAnalyzer.cs:117-193](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs)

---

## Pattern 6: Severity Comparison via Enum Values

The escalation condition compares against the numeric value of the `Severity` enum:

```csharp
// RiskEscalator.cs:58-64
var participates =
    (shouldEscalateBeaconLateral && (IsCategory(f, FindingCategories.Beaconing) || IsCategory(f, FindingCategories.LateralMovement)))
    || (shouldEscalateFlagPort && (IsCategory(f, FindingCategories.FlagAnomaly) || IsCategory(f, FindingCategories.PortScan)))
    || (shouldEscalateMacInterface && (IsCategory(f, FindingCategories.MacSpoofing) || IsCategory(f, FindingCategories.InterfaceHopping)));

if (participates && f.Severity < Core.Severity.Critical)
```

```csharp
// SentryAnalyzer.cs:198-199
var visibleFindings = deduped.Where(f => f.Severity >= profile.MinSeverityToShow).ToList();
var filteredFindings = ApplyFindingCap(visibleFindings, profile, warnings);
```

**Why it matters**: `Severity` is an `enum` with explicit numeric values (Info=0, Low=1, Medium=2, High=3, Critical=4). The `<` and `>=` operators work on the underlying integers. The `participates` check ensures that only findings whose categories are part of a fired correlation rule are escalated -- unrelated findings on the same host pass through unchanged. The severity filter runs after deduplication but before the per-category cap in `SentryAnalyzer`, so hidden low-severity findings cannot displace visible findings.

**Where it appears**: [RiskEscalator.cs:58-64](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs), [SentryAnalyzer.cs:198](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs), [Severity.cs](../../../../VulcansTrace.Linux.Core/Severity.cs)

---

## Pattern 7: Constructor Guard Clauses with ArgumentNullException

`SentryAnalyzer` validates all constructor parameters at creation time:

```csharp
// SentryAnalyzer.cs:54-66
_logNormalizer = logNormalizer ?? throw new ArgumentNullException(nameof(logNormalizer));
_profileProvider = profileProvider ?? throw new ArgumentNullException(nameof(profileProvider));
_baselineDetectors = baselineDetectors == null
    ? throw new ArgumentNullException(nameof(baselineDetectors))
    : baselineDetectors.ToList();
// ... same pattern for all parameters
```

**Why it matters**: This is fail-fast design. If a dependency is missing, the error surfaces at construction rather than during analysis when it would be harder to diagnose. The `ToList()` materialization ensures that each detector collection is owned by the analyzer and cannot be modified externally.

**Where it appears**: [SentryAnalyzer.cs:45-67](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs)

---

## Pattern 8: Non-Fatal Exception Filter

The catch clause uses an inlined exception filter to exclude truly fatal exceptions (there is no separate `IsNonFatal` method):

```csharp
// SentryAnalyzer.cs:138 (same pattern at lines 160, 182)
catch (Exception ex) when (ex is not OutOfMemoryException
                        && ex is not StackOverflowException
                        && ex is not AccessViolationException
                        && ex is not AppDomainUnloadedException
                        && ex is not ThreadAbortException)
```

**Why it matters**: Catching `OutOfMemoryException` or `StackOverflowException` would be dangerous because the application is in an undefined state. The exception filter ensures these propagate normally while all other detector failures are contained as warnings.

**Where it appears**: [SentryAnalyzer.cs:138](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs), [SentryAnalyzer.cs:160](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs), [SentryAnalyzer.cs:182](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs)

---

## Security Takeaways

- Immutable records with `with` expressions provide compile-time guarantees that original findings cannot be tampered with after creation — essential for forensic integrity
- Case-insensitive category matching prevents false negatives from inconsistent string casing across detectors
- Per-detector fault isolation with non-fatal exception filtering ensures that the escalation pipeline is resilient to individual detector bugs while still propagating truly fatal runtime errors
- Pre-allocated collections and lazy LINQ evaluation keep memory usage proportional to input size, preventing resource exhaustion on large log files
