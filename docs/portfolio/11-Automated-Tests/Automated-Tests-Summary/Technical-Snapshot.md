# Technical Snapshot: Automated Tests

> The test suite is an xUnit-based suite of 40+ test files covering Core parsing, 13 detector types, evidence packaging, full-pipeline integration, real-world attack scenarios, performance bounds, and Avalonia ViewModels. Tests use the Arrange-Act-Assert pattern, synthetic log generation via `LogScenarioBuilder`, real log fixtures, boundary-value analysis, and cooperative cancellation validation to ensure every detection and packaging pathway behaves correctly.

---

## Implementation Overview

The test suite validates the VulcansTrace analysis pipeline end-to-end. Unit tests cover individual components — parsers, normalizers, detectors, and formatters — in isolation with controlled inputs. Integration tests exercise the `SentryAnalyzer` orchestration engine across all detector layers. Scenario tests use `LogScenarioBuilder` to synthesize realistic attack logs (port scans, beaconing, floods, lateral movement, C2 channels) and verify the correct findings are produced. Performance tests assert time bounds on large inputs. UI tests validate Avalonia ViewModel command bindings.

---

## Key Metrics

| Metric | Value |
|---|---|
| Test files | 40+ |
| Test categories | Core, Detectors (Baseline, Linux, Advanced), Evidence, Integration, Avalonia |
| Detector test files | 13 (6 baseline, 5 Linux, 2 advanced) |
| Integration test files | 7 (SentryAnalyzer, RealWorld, RealLog, Performance, ProfileComparison, ConfigurableThreshold, GoldenScenario) |
| Evidence test files | 6 (Builder, CSV, HTML, JSON, Markdown, STIX) |
| Test helper | LogScenarioBuilder |
| Real log fixtures | 5 (iptables-attack.log, nftables-traffic.log, large-portscan.log, iptables-mixed-prefixes.log, golden-compromise-timeline.log) |
| Assertion framework | xUnit Assert |
| Test runner command | `dotnet test` |
| Key patterns | Arrange-Act-Assert, boundary-value, synthetic scenarios, cancellation |

---

## Why It Matters

- Tests prove every detector correctly identifies its target threat pattern and correctly rejects benign traffic
- Boundary-value tests at exact thresholds prevent off-by-one detection errors that could cause false negatives or false positives
- Integration tests verify detector composition — multiple detectors running in parallel on the same event stream produce the correct combined findings
- Real-world log fixtures validate that the parsing pipeline handles actual iptables and nftables output, not just synthetic data
- Performance tests prevent regressions that would make the tool unusable on production log volumes

---

## Key Evidence

- [LinuxIptablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxIptablesParserTests.cs), [LinuxNftablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxNftablesParserTests.cs), [LogNormalizerTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LogNormalizerTests.cs), and [UnifiedEventTests.cs](../../../../VulcansTrace.Linux.Tests/Core/UnifiedEventTests.cs) — parser, normalizer, and event model unit tests
- [PortScanDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) — detector boundary tests
- [SentryAnalyzerTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs) — full-pipeline integration tests
- [RealWorldAttackScenarioTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/RealWorldAttackScenarioTests.cs) — attack scenario tests
- [EvidenceBuilderTests.cs](../../../../VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs) — evidence integrity tests
- [SecurityAgentTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/SecurityAgentTests.cs), [RuleTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/RuleTests.cs), [DefaultRulePolicyProviderTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/DefaultRulePolicyProviderTests.cs), and [JsonRulePolicyStoreTests.cs](../../../../VulcansTrace.Linux.Tests/Agent/JsonRulePolicyStoreTests.cs) — Security Agent orchestration, contextual rules, and local policy persistence tests
- [LogScenarioBuilder.cs](../../../../VulcansTrace.Linux.Tests/Helpers/LogScenarioBuilder.cs) — synthetic log generator
- [MainViewModelTests.cs](../../../../VulcansTrace.Linux.Tests/Avalonia/MainViewModelTests.cs) — UI ViewModel tests

---

## Key Design Choices

- **Arrange-Act-Assert (AAA) pattern** — Every test follows the same three-phase structure with explicit comments (`// Arrange`, `// Act`, `// Assert`), making test intent immediately clear to reviewers.

- **Boundary-value analysis** — Detector tests probe the exact threshold (e.g., `targetCount: 15` at threshold 15), one below (`targetCount: 14`), and well above (`targetCount: 20, 100`), ensuring the detection boundary is correct in both directions.

- **Synthetic log generation via `LogScenarioBuilder`** — A fluent builder produces realistic iptables log entries for common attack patterns, allowing tests to specify high-level parameters (`targetCount`, `duration`) rather than manually constructing raw log text.

- **Real-world log fixtures** — Test data under `Data/Real/Samples/` contains actual firewall logs, validating that the parsing pipeline handles real-world formatting quirks that synthetic tests may miss.

- **Integration tests with full detector composition** — `SentryAnalyzerTests` constructs the analyzer with all detector types and verifies findings from the complete pipeline, not just individual detectors.

- **Fail-safe cancellation tests** — Tests verify that `CancellationToken` triggers `OperationCanceledException` and that partial results are never published.

---

## Security Takeaways

1. The test suite validates every detection pathway from raw log input through finding output, ensuring no silent failures
2. Boundary-value tests at exact thresholds prevent the most dangerous class of detection bug — off-by-one errors at the detection boundary
3. Integration tests with full detector composition catch interaction bugs that unit tests cannot, such as findings being lost during risk escalation
4. Real-world log fixtures bridge the gap between synthetic test data and production iptables/nftables output
5. Cancellation tests ensure that analysis can be safely interrupted without producing incomplete or misleading findings
