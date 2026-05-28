# Intensity Profiles — Profile Pipeline Algorithm

## Security Problem

Every detector in the engine needs consistent, coordinated configuration. Port scan thresholds must align with flood thresholds; beaconing sensitivity must match C2 tolerance; enable flags must be coherent across all layers. The profile pipeline must resolve a single intensity level into a complete, immutable configuration object and distribute it to every detector without any risk of inconsistency or mutation.

---

## Implementation Overview

```
  IntensityLevel (Low / Medium / High)
        |
        v
  ┌─────────────────────────────┐
  │ Step A: Validate level       │  Switch expression, compiler-enforced
  └──────────┬──────────────────┘
             v
  ┌─────────────────────────────┐
  │ Step B: Allocate shared      │  adminPorts, disallowedOutbound
  │          policy lists        │
  └──────────┬──────────────────┘
             v
  ┌─────────────────────────────┐
  │ Step C: Build profile        │  13 enable flags + 20+ thresholds
  │          (switch arm)        │  + policy lists + severity filter
  └──────────┬──────────────────┘
             v
  ┌─────────────────────────────┐
  │ Step D: Return sealed record │  Immutable, init-only properties
  └──────────┬──────────────────┘
             v
  ┌─────────────────────────────┐
  │ Step E: Override check       │  SentryAnalyzer line 114
  │          (optional)          │  overrideProfile ?? resolved
  └──────────┬──────────────────┘
             v
  ┌─────────────────────────────┐
  │ Step F: Distribute           │  Passed to all detectors;
  │          to all detectors    │  reused for filter and cap
  └─────────────────────────────┘
```

---

### Step A — Validate Level via Switch Expression

```csharp
return level switch
{
    IntensityLevel.Low => new AnalysisProfile { ... },
    IntensityLevel.Medium => new AnalysisProfile { ... },
    IntensityLevel.High => new AnalysisProfile { ... },
    _ => throw new ArgumentOutOfRangeException(nameof(level), level, null)
};
```

The C# switch expression provides compiler-enforced exhaustive matching. If a new `IntensityLevel` value is added to the enum, the compiler emits a warning (or error with exhaustive matching enabled) until a matching arm is added. The `_` discard pattern throws for any unexpected value at runtime.

---

### Step B — Allocate Shared Policy Lists

```csharp
var adminPorts = ImmutableArray.Create(445, 3389, 22);
var disallowedOutbound = ImmutableArray.Create(21, 23, 445);
```

Both lists are allocated once per `GetProfile` call via `ImmutableArray.Create` and shared across all three switch arms. This ensures identical policy enforcement regardless of intensity level. The ports represent:

- **AdminPorts (445, 3389, 22):** SMB, RDP, and SSH — the three most commonly brute-forced administrative ports
- **DisallowedOutboundPorts (21, 23, 445):** FTP, Telnet, and SMB — protocols that should never traverse the network perimeter in a modern environment

---

### Step C — Build Profile (Switch Arm)

Each switch arm creates a fully populated `AnalysisProfile` with init-only properties:

```csharp
IntensityLevel.High => new AnalysisProfile
{
    EnablePortScan = true,
    EnableFlood = true,
    EnableLateralMovement = true,
    EnableBeaconing = true,
    EnablePolicy = true,
    EnableNovelty = true,
    EnableFlagAnomaly = true,
    EnableMacSpoofing = true,
    EnableKernelModule = true,
    EnableInterfaceHopping = true,
    EnableUnusualPacketSize = true,
    EnableC2Detection = true,
    EnablePrivilegeEscalationDetection = true,

    PortScanMinPorts = 8,
    FloodMinEvents = 100,
    LateralMinHosts = 3,
    BeaconMinEvents = 4,
    BeaconStdDevThreshold = 8.0,
    C2ToleranceSeconds = 8.0,
    C2MinIntervalSeconds = 30,
    C2MaxIntervalSeconds = 1800,
    C2MinOccurrences = 2,
    C2MinPatternEvents = 4,
    C2MinGroupSize = 3,

    MaxFindingsPerDetector = 100,
    MinSeverityToShow = Severity.Info,
    // ... remaining thresholds
},
```

The key progression from Low to High:
- **Enable flags:** 6 detectors (Novelty, KernelModule, InterfaceHopping, UnusualPacketSize, C2Detection, PrivilegeEscalationDetection) activate at Medium and stay on
- **Thresholds:** decrease roughly 2x per tier (e.g., FloodMinEvents: 400 → 200 → 100)
- **Output filter:** MinSeverityToShow relaxes from High → Medium → Info

---

### Step D — Return Sealed Record

```csharp
public sealed record AnalysisProfile { ... }
```

The `sealed record` declaration provides:
- **Immutability** — all properties use `init` accessors, making the object read-only after construction
- **Value equality** — two profiles with identical values compare as equal (useful for testing)
- **Non-heritability** — `sealed` prevents subclassing, ensuring all profile instances are exactly `AnalysisProfile`
- **`with` expression support** — callers can create modified copies without mutating the original

---

### Step E — Override Check

```csharp
var profile = overrideProfile ?? _profileProvider.GetProfile(intensity);
```

`SentryAnalyzer.Analyze()` (line 114) checks for an optional `overrideProfile` parameter. If provided, it bypasses the factory entirely. This enables:
- Custom threshold tuning without modifying `AnalysisProfileProvider`
- Programmatic profile construction for specialized analysis pipelines
- Testing with synthetic profiles

---

### Step F — Distribute to All Detectors

```csharp
foreach (var detector in _baselineDetectors)
{
    var detected = detector.Detect(normalized.Events, profile, cancellationToken);
    allFindings.AddRange(detected.Findings);
}
```

The resolved profile is passed to every detector's `Detect` method. Each detector reads its own enable flag and thresholds from the shared profile object. No detector receives a different configuration — the profile is resolved once and distributed uniformly.

After all detectors run, the profile is used for output visibility and per-category caps after escalation and Beaconing/C2 overlap deduplication:

```csharp
var visibleFindings = deduped.Where(f => f.Severity >= profile.MinSeverityToShow).ToList();
var filteredFindings = ApplyFindingCap(visibleFindings, profile, warnings);
```

---

## Complexity And Behavior

| Aspect | Detail |
|---|---|
| Profile resolution | O(1) — single switch expression evaluation |
| Profile allocation | O(1) — one sealed record with fixed-size collections |
| Distribution | O(d) — d = number of detectors, each receives the same reference |
| Immutability guarantee | Compile-time enforced via `init` accessors |
| Exhaustiveness | Compiler-enforced via switch expression (warning on missing arms) |

---

## Implementation Evidence

- [AnalysisProfile.cs](../../../../../VulcansTrace.Linux.Engine/AnalysisProfile.cs) — sealed record definition
- [AnalysisProfileProvider.cs](../../../../../VulcansTrace.Linux.Engine/Configuration/AnalysisProfileProvider.cs) — factory with switch expression
- [SentryAnalyzer.cs](../../../../../VulcansTrace.Linux.Engine/SentryAnalyzer.cs) — profile resolution and distribution
- [ProfileComparisonTests.cs](../../../../../VulcansTrace.Linux.Tests/Integration/ProfileComparisonTests.cs) — cross-profile integration test
