# Code Patterns: Automated Tests

## The Quality Problem

Security detection tests must be both correct and maintainable. A test that is difficult to understand, modify, or extend is a liability — it will be disabled when it fails rather than fixed. The test suite uses several recurring code patterns that support readability, maintainability, and reliable failure diagnosis.

---

## Implementation Overview

| Pattern | Location | Purpose |
|---|---|---|
| Arrange-Act-Assert with comments | All test files | Three-phase structure with labeled sections |
| LogScenarioBuilder fluent API | Detector and integration tests | Decouple test intent from log format |
| Boundary-value triples | Detector tests | At-threshold, below-threshold, above-threshold |
| Constructor-per-fixture | Integration test classes | Fresh component instances per test class |
| Error injection stub | SentryAnalyzerTests | Verify graceful degradation |
| Property assertion chains | Detector tests | Verify finding structure, not just count |

---

## How It Works (Technical)

### Arrange-Act-Assert with Comments

```csharp
[Fact]
public void Detect_PortScanAboveMediumThreshold_ReturnsFinding()
{
    // Arrange
    var builder = new LogScenarioBuilder();
    var log = builder
        .BuildPortScan(targetCount: 20, duration: TimeSpan.FromMinutes(3))
        .Generate();
    var events = _normalizer.Normalize(log).Events;
    var profile = new AnalysisProfile
    {
        EnablePortScan = true,
        PortScanMinPorts = 15,
        PortScanWindowMinutes = 5
    };

    // Act
    var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

    // Assert
    Assert.Single(findings);
    Assert.Equal("PortScan", findings[0].Category);
}
```

Every test follows this structure. The Arrange section constructs the input and configuration. The Act section is a single method call. The Assert section verifies the output. The explicit comments make the three phases visually distinct and the test method name describes the scenario and expected outcome using the `MethodName_Scenario_Expectation` convention.

---

### LogScenarioBuilder Fluent API

```csharp
public LogScenarioBuilder BuildPortScan(int targetCount, TimeSpan duration)
{
    var startIp = "192.168.1.100";
    var dstIp = "10.0.0.1";
    var ports = GeneratePortSequence(targetCount);

    foreach (var (port, index) in ports.Select((p, i) => (p, i)))
    {
        var timestamp = _startTime.AddMilliseconds(index * 100);
        var logLine = FormatIptablesLine(timestamp, startIp, dstIp, port);
        _logBuilder.AppendLine(logLine);
    }
    return this;
}
```

`LogScenarioBuilder` encapsulates the iptables log format behind a fluent API. Tests specify high-level parameters — `targetCount: 20`, `duration: TimeSpan.FromMinutes(3)` — and the builder produces correctly formatted log text. The builder generates sequential port numbers starting at 1025 via `Enumerable.Range(1, count).Select(p => 1024 + p)`, providing distinct ports that reliably trigger scan detection thresholds.

---

### Boundary-Value Triples

```csharp
// At threshold — should trigger
[Fact]
public void Detect_PortScanAtThreshold_ReturnsFinding()
{
    var log = builder.BuildPortScan(targetCount: 15, ...).Generate();
    var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
    Assert.Single(findings);
}

// Just below threshold — should NOT trigger
[Fact]
public void Detect_PortScanJustBelowThreshold_ReturnsNoFindings()
{
    var log = builder.BuildPortScan(targetCount: 14, ...).Generate();
    var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
    Assert.Empty(findings);
}

// Well above threshold — should trigger
[Fact]
public void Detect_PortScanWithVeryLargePortCount_ReturnsMultipleFindings()
{
    var log = builder.BuildPortScan(targetCount: 100, ...).Generate();
    var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();
    Assert.True(findings.Count >= 1);
}
```

The three-test pattern for every threshold boundary proves the detection edge is exactly correct. The at-threshold test verifies the `>=` comparison includes the boundary value. The just-below test verifies it does not trigger early. The well-above test verifies it scales correctly.

---

### Constructor-per-Fixture Pattern

```csharp
public class SentryAnalyzerTests
{
    private readonly SentryAnalyzer _analyzer;
    private readonly LogNormalizer _logNormalizer;
    private readonly AnalysisProfileProvider _profileProvider;

    public SentryAnalyzerTests()
    {
        _logNormalizer = new LogNormalizer();
        _profileProvider = new AnalysisProfileProvider();
        var baselineDetectors = new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            // ... all detector types
        };
        _analyzer = new SentryAnalyzer(
            _logNormalizer, _profileProvider,
            baselineDetectors, linuxDetectors,
            advancedDetectors, riskEscalator);
    }
}
```

Integration test classes construct all dependencies once in the constructor. xUnit creates a new instance for each test, so every test gets fresh components with no shared mutable state. This eliminates test-ordering dependencies while keeping the Arrange section focused on test-specific configuration.

---

### Error Injection Stub

```csharp
[Fact]
public void Analyze_DetectorException_AddsWarningWithType()
{
    var analyzer = new SentryAnalyzer(
        new LogNormalizer(),
        new AnalysisProfileProvider(),
        new IDetector[] { new ThrowingDetector() },
        Array.Empty<IDetector>(),
        Array.Empty<IDetector>(),
        new RiskEscalator());

    var result = analyzer.Analyze(log, IntensityLevel.Medium, CancellationToken.None);

    Assert.Single(result.Warnings);
    Assert.Contains(nameof(ThrowingDetector), result.Warnings[0]);
    Assert.Contains(nameof(InvalidOperationException), result.Warnings[0]);
}

private sealed class ThrowingDetector : IDetector
{
    public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events,
        AnalysisProfile profile, CancellationToken cancellationToken)
    {
        throw new InvalidOperationException("boom");
    }
}
```

The `ThrowingDetector` is a minimal `IDetector` implementation that always throws. The test injects it as the only detector and verifies that the pipeline catches the exception, includes the detector type name and exception type in the warning, and continues without crashing.

---

### Property Assertion Chains

```csharp
[Fact]
public void Detect_PortScan_ReturnsFindingWithCorrectProperties()
{
    var findings = _detector.Detect(events, profile, CancellationToken.None).Findings.ToList();

    Assert.Single(findings);
    var finding = findings[0];
    Assert.Equal("PortScan", finding.Category);
    Assert.NotEqual(Guid.Empty, finding.Id);
    Assert.NotNull(finding.ShortDescription);
    Assert.NotNull(finding.Details);
}
```

Beyond finding count, tests assert on structural properties — category, non-empty GUID, non-null description and details. This catches bugs where a finding is created with the correct category but missing the fields an analyst needs for triage.

---

## Implementation Evidence

- [PortScanDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) — boundary-value triples and property assertions (514 lines)
- [SentryAnalyzerTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs) — constructor-per-fixture and error injection (977 lines)
- [LogScenarioBuilder.cs](../../../../VulcansTrace.Linux.Tests/Helpers/LogScenarioBuilder.cs) — fluent synthetic log generator (106 lines)
- [MainViewModelTests.cs](../../../../VulcansTrace.Linux.Tests/Avalonia/MainViewModelTests.cs) — UI command binding tests (210 lines)

---

## Security Takeaways

1. The AAA pattern with explicit comments makes test intent unambiguous, reducing the risk that reviewers miss untested edge cases
2. Boundary-value triples target the highest-risk region of the detection input space — the exact threshold edge
3. The LogScenarioBuilder fluent API decouples test logic from log format, making tests resilient to parser changes that should not affect detection behavior
4. Error injection via ThrowingDetector proves the pipeline degrades gracefully — a security requirement that cannot be verified without deliberate fault injection
5. Property assertion chains verify that findings carry enough context for triage, not just that they exist
