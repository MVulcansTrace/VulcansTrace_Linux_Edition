# Testing Algorithm: Automated Tests

## The Quality Problem

A security analysis tool must correctly identify threats across 13+ detector types, parse two different log formats, package findings into forensically sound evidence bundles, and orchestrate everything through a pipeline that handles cancellation, errors, and risk escalation. Each of these components has edge cases that manual testing cannot systematically cover. The test algorithm defines how tests are organized, what inputs they use, and what they verify.

---

## Implementation Overview

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Test Input       │     │  Component Under │     │  Assertions      │     │  Side-Effect     │
│  Selection        │────▶│  Test            │────▶│  on Output       │────▶│  Verification    │
│  (synthetic /     │     │  (detector /     │     │  (findings,      │     │  (HMAC, ZIP,     │
│   raw / fixture)  │     │   analyzer /     │     │   events,        │     │   warnings,      │
│                   │     │   formatter)     │     │   result)        │     │   timing)        │
└──────────────────┘     └──────────────────┘     └──────────────────┘     └──────────────────┘
```

---

### Step A — Test Input Selection

```csharp
// Synthetic log via LogScenarioBuilder
var builder = new LogScenarioBuilder();
var log = builder
    .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(3))
    .Generate();

// Raw log text for parser tests
var logLine = "kernel: Jan 19 10:15:32 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

// Real-world fixture for integration tests
// Loaded from Data/Real/Samples/iptables-attack.log
```

Tests use three input strategies depending on what is being tested:

1. **Synthetic logs** (`LogScenarioBuilder`) — for detector tests where the test controls the exact attack parameters (target count, duration, interval)
2. **Raw log text** — for parser and formatter tests where the test needs exact field values in the input
3. **Real-world fixtures** — for integration tests that validate against actual iptables and nftables log captures

---

### Step B — Component Under Test Construction

```csharp
// Unit test: single detector in isolation
var detector = new PortScanDetector();
var profile = new AnalysisProfile
{
    EnablePortScan = true,
    PortScanMinPorts = 15,
    PortScanWindowMinutes = 5
};

// Integration test: full analyzer with all detectors
var baselineDetectors = new IDetector[]
{
    new PortScanDetector(),
    new FloodDetector(),
    new LateralMovementDetector(),
    new BeaconingDetector(),
    new PolicyViolationDetector(),
    new NoveltyDetector()
};
var linuxDetectors = new IDetector[]
{
    new FlagAnomalyDetector(),
    new MacSpoofingDetector(),
    new KernelModuleDetector(),
    new InterfaceHoppingDetector(),
    new UnusualPacketSizeDetector()
};
var advancedDetectors = new IDetector[]
{
    new C2ChannelDetector(),
    new PrivilegeEscalationDetector()
};
var analyzer = new SentryAnalyzer(
    logNormalizer, profileProvider,
    baselineDetectors, linuxDetectors,
    advancedDetectors, riskEscalator);
```

Unit tests construct a single component with its direct dependencies. Integration tests construct the full `SentryAnalyzer` with all detector types, the `RiskEscalator`, and the `AnalysisProfileProvider`.

---

### Step C — Test Execution (Act)

```csharp
// Detector unit test
var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

// Analyzer integration test
var result = _analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

// Cancellation test
using var cts = new CancellationTokenSource();
cts.Cancel();
Assert.Throws<OperationCanceledException>(() =>
{
    _analyzer.Analyze(largeLog, IntensityLevel.Medium, cts.Token);
});
```

The Act phase is always a single method call — the test invokes exactly one public method on the component under test. This keeps tests focused and makes failures easy to diagnose.

---

### Step D — Output Assertions

```csharp
// Finding count
Assert.Single(findings);
Assert.Empty(findings);

// Finding properties
Assert.Equal("PortScan", findings[0].Category);
Assert.NotEqual(Guid.Empty, findings[0].Id);
Assert.NotNull(finding.ShortDescription);

// Finding presence in result
Assert.Contains(result.Findings, f => f.Category == "Flood");

// Result structure
Assert.Equal(2, result.ParsedLines);
Assert.True(result.TimeRangeEnd >= result.TimeRangeStart);

// Severity range
Assert.True(result.Findings.All(f =>
    f.Severity == Severity.Info ||
    f.Severity == Severity.Low ||
    f.Severity == Severity.Medium ||
    f.Severity == Severity.High ||
    f.Severity == Severity.Critical));
```

Assertions verify both the presence/absence of findings and their structural properties. Tests never assert on implementation details — only on the public API contract.

---

### Step E — Side-Effect Verification

```csharp
// Evidence package: verify ZIP structure and HMAC
var names = zip.Entries.Select(e => e.FullName).ToArray();
Assert.Contains("findings.csv", names);
Assert.Contains("manifest.json", names);
Assert.Contains("manifest.hmac", names);

var expectedHmac = Convert.ToHexString(
    hasher.ComputeHmacSha256(manifestBytes, signingKey)).ToLowerInvariant();
Assert.Equal(expectedHmac, hmacText);

// Performance: time-bound assertion
var duration = DateTime.UtcNow - startTime;
Assert.True(duration.TotalSeconds < 10.0,
    $"Analysis took {duration.TotalSeconds:F2}s, should be under 10 seconds");

// Warnings on detector failure
Assert.Single(result.Warnings);
Assert.Contains(nameof(ThrowingDetector), result.Warnings[0]);
```

Side-effect assertions verify things beyond the primary return value — ZIP file contents, HMAC integrity, timing bounds, and warning messages.

---

## Test Organization Matrix

| Test Type | Input Source | Scope | Example |
|---|---|---|---|
| Unit (Core) | Raw log text | Single parser or normalizer | `LinuxIptablesParser_Parse_ValidLine_ParsesCorrectly` |
| Unit (Detector) | LogScenarioBuilder | Single detector with profile | `Detect_PortScanAboveMediumThreshold_ReturnsFinding` |
| Unit (Evidence) | Constructed AnalysisResult | Single formatter or builder | `Build_CreatesManifestAndValidHmac` |
| Unit (Avalonia) | Constructed ViewModel | ViewModel command binding | `AnalyzeCommand_RequiresLogText` |
| Integration | LogScenarioBuilder + raw text | Full SentryAnalyzer pipeline | `Analyze_PortScanDetectsCorrectly` |
| Scenario | Multi-attack synthetic logs | Attack pattern detection | `Analyze_RealWorld_Mixed_Attack_Scenario_DetectsMultiple` |
| Performance | Large synthetic logs | Time-bound execution | `Analyze_Performance_LargeLogCompletesInTime` |
| Cancellation | Pre-cancelled token | Safe interruption | `Analyze_CancellationToken_ThrowsOnCancel` |

---

## Complexity And Behavior

| Aspect | Behavior | Rationale |
|---|---|---|
| Test isolation | Each test constructs its own components | No shared mutable state between tests |
| Determinism | All inputs are deterministic | No random, no wall-clock dependency |
| Boundary coverage | At-threshold, below-threshold, above-threshold | Proves detection boundary is exact |
| Error injection | `ThrowingDetector` stub for error handling | Validates fail-safe behavior |
| Profile variation | Low, Medium, High intensity levels | Tests profile-dependent behavior |

---

## Implementation Evidence

- [LinuxIptablesParserTests.cs](../../../../../VulcansTrace.Linux.Tests/Core/LinuxIptablesParserTests.cs), [LinuxNftablesParserTests.cs](../../../../../VulcansTrace.Linux.Tests/Core/LinuxNftablesParserTests.cs), [LogNormalizerTests.cs](../../../../../VulcansTrace.Linux.Tests/Core/LogNormalizerTests.cs), and [UnifiedEventTests.cs](../../../../../VulcansTrace.Linux.Tests/Core/UnifiedEventTests.cs) — parser, normalizer, and event model unit tests
- [PortScanDetectorTests.cs](../../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) — detector boundary tests
- [SentryAnalyzerTests.cs](../../../../../VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs) — full-pipeline integration tests
- [RealWorldAttackScenarioTests.cs](../../../../../VulcansTrace.Linux.Tests/Integration/RealWorldAttackScenarioTests.cs) — attack scenario tests
- [EvidenceBuilderTests.cs](../../../../../VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs) — evidence integrity tests

---

## Security Takeaways

1. The three-tier input strategy (synthetic, raw, fixture) provides layered confidence — synthetic tests prove logic, raw tests prove parsing, fixtures prove real-world readiness
2. Each test constructs its own components with no shared state, eliminating test-ordering dependencies that could mask failures
3. The single-call Act phase keeps tests focused on one behavior, making failures immediately diagnostic
4. Side-effect assertions on HMAC, ZIP structure, timing, and warnings verify properties that finding-count assertions cannot
5. The `ThrowingDetector` error injection pattern proves the pipeline fails safely — emitting warnings instead of crashing silently
