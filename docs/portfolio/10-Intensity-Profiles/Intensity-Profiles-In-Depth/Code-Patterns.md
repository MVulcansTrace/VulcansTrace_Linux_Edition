# Intensity Profiles — Code Patterns

## Security Problem

The profile subsystem must produce a single, immutable configuration object that is shared across 14 detectors running in sequence. The implementation uses C# language features — sealed records, init-only properties, switch expressions, and ImmutableArray — to enforce correctness at compile time.

---

## Implementation Overview

| Pattern | Location | Purpose |
|---|---|---|
| Sealed record | AnalysisProfile.cs:12 | Immutability, value equality, `with` support |
| Init-only properties | AnalysisProfile.cs:17-182 | Compile-time write-once guarantee |
| IReadOnlyList for policy | AnalysisProfile.cs:135-138 | Prevents callers from mutating lists |
| Switch expression | AnalysisProfileProvider.cs:30-236 | Exhaustive matching with compiler enforcement |
| ImmutableArray.Create | AnalysisProfileProvider.cs:27-28 | Immutable shared policy lists |
| Null-coalescing override | SentryAnalyzer.cs:114 | Override profile or fall back to factory |
| Severity comparison | SentryAnalyzer.cs:198 | Output filtering via enum comparison |
| Shared array allocation | AnalysisProfileProvider.cs:27-28 | Identical policy lists across all profiles |

---

## How It Works

### Sealed Record with Init-Only Properties

```csharp
public sealed record AnalysisProfile
{
    public bool EnablePortScan { get; init; }
    public int PortScanMinPorts { get; init; }
    public Severity MinSeverityToShow { get; init; } = Severity.Medium;
}
```

The `sealed record` declaration combines three guarantees:

- **Sealed** — no subclassing, all instances are exactly `AnalysisProfile`
- **Record** — value-based equality and `with` expression support for creating modified copies
- **init** — properties can only be set during object initialization, not after

The `= Severity.Medium` default on `MinSeverityToShow` provides a safe fallback if a caller constructs a profile manually without specifying this field.

---

### IReadOnlyList for Policy Ports

```csharp
public IReadOnlyList<int> AdminPorts { get; init; } = Array.Empty<int>();
public IReadOnlyList<int> DisallowedOutboundPorts { get; init; } = Array.Empty<int>();
```

The properties are typed as `IReadOnlyList<int>` even though the provider assigns `int[]` (which implements `IReadOnlyList<int>`). This prevents consumers from casting to `List<int>` and mutating the contents. The default `Array.Empty<int>()` ensures the property is never null.

---

### Switch Expression for Exhaustive Matching

```csharp
return level switch
{
    IntensityLevel.Low => new AnalysisProfile { ... },
    IntensityLevel.Medium => new AnalysisProfile { ... },
    IntensityLevel.High => new AnalysisProfile { ... },
    _ => throw new ArgumentOutOfRangeException(nameof(level), level, null)
};
```

The C# 8+ switch expression evaluates `level` and returns the matching `AnalysisProfile`. Key properties:

- **Exhaustive** — the compiler warns if any enum value is unhandled
- **Expression** — returns a value directly, no break statements or variable assignment needed
- **Default arm** — the `_` pattern throws a descriptive exception for any unexpected value (defensive programming for future enum extensions)

---

### ImmutableArray for Shared Policy Lists

```csharp
var adminPorts = ImmutableArray.Create(445, 3389, 22);
var disallowedOutbound = ImmutableArray.Create(21, 23, 445);
```

`ImmutableArray.Create` allocates once per `GetProfile` call. Both arrays are assigned to all three profile instances via the shared `adminPorts` and `disallowedOutbound` variables. This is intentional: the same reference is shared across profiles, which is safe because immutable arrays cannot be mutated after creation.

---

### Null-Coalescing Override Pattern

```csharp
var profile = overrideProfile ?? _profileProvider.GetProfile(intensity);
```

The `??` operator resolves the override: if `overrideProfile` is not null, use it; otherwise, fall back to the factory. This one-liner implements the entire override strategy. The resolved `profile` variable is used for all subsequent operations — no further null checks needed.

---

### Severity Comparison for Output Filtering

```csharp
var visibleFindings = deduped.Where(f => f.Severity >= profile.MinSeverityToShow).ToList();
var filteredFindings = ApplyNoiseBudget(visibleFindings, profile, warnings);
```

The `Severity` enum values are ordered (Info < Low < Medium < High < Critical), so the `>=` comparison implements a threshold filter. With `MinSeverityToShow = Severity.High` (Low profile), only High and Critical findings pass. With `MinSeverityToShow = Severity.Info` (High profile), all findings pass. The noise budget is applied after severity filtering so hidden low-severity findings cannot consume the per-category group cap.

---

### Per-Detector Guard Clause Pattern

```csharp
if (!profile.EnableNovelty || events.Count == 0)
    return DetectionResult.Empty;
```

Every detector checks its enable flag first. When a detector is disabled (e.g., `EnableNovelty = false` in the Low profile), the guard clause returns immediately — zero computation, zero allocation, zero findings. This pattern ensures disabled detectors have negligible performance impact.

---

## Implementation Evidence

- [AnalysisProfile.cs](../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — sealed record definition
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — factory with switch expression
- [SentryAnalyzer.cs](../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs) — profile resolution, distribution, filtering, and noise budget
- [ProfileComparisonTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/ProfileComparisonTests.cs) — cross-profile test

---

## Security Takeaways

- The sealed record pattern eliminates an entire class of concurrent-mutation bugs at compile time
- Switch expressions with exhaustive matching ensure new intensity levels are handled everywhere or nowhere (compile error)
- IReadOnlyList-typed properties prevent downstream mutation of policy port lists
- The enable-flag guard clause pattern makes disabled detectors truly zero-cost
- The severity comparison filter preserves escalation fidelity while reducing analyst noise
