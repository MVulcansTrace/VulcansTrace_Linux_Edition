# Quick Reference: Automated Tests

## Test Suite Structure

```
VulcansTrace.Linux.Tests/
├── UnifiedEventTests.cs, LinuxIptablesParserTests.cs, LinuxNftablesParserTests.cs, LogNormalizerTests.cs — UnifiedEvent, iptables parser, nftables parser, normalizer
├── Core/
│   ├── FindingTests.cs                       — finding model property validation
│   ├── LinuxIptablesParserTests.cs           — iptables field extraction and edge cases
│   ├── LinuxNftablesParserTests.cs           — nftables field extraction and action derivation
│   ├── LogNormalizerTests.cs                 — format detection and normalization pipeline
│   └── UnifiedEventTests.cs                  — event construction and connection key
├── Detectors/
│   ├── Baseline/
│   │   ├── PortScanDetectorTests.cs          — port scan threshold and multi-source tests
│   │   ├── BeaconingDetectorTests.cs         — beaconing interval detection tests
│   │   ├── FloodDetectorTests.cs             — flood volume detection tests
│   │   ├── LateralMovementDetectorTests.cs   — internal host-to-host movement tests
│   │   ├── PolicyViolationDetectorTests.cs   — policy breach detection tests
│   │   └── NoveltyDetectorTests.cs           — unseen pattern detection tests
│   ├── Linux/
│   │   ├── FlagAnomalyDetectorTests.cs       — TCP flag anomaly tests
│   │   ├── InterfaceHoppingDetectorTests.cs  — interface switching tests
│   │   ├── KernelModuleDetectorTests.cs      — kernel module activity tests
│   │   ├── MacSpoofingDetectorTests.cs       — MAC address change tests
│   │   └── UnusualPacketSizeDetectorTests.cs — packet size anomaly tests
│   ├── C2ChannelDetectorTests.cs             — C2 channel detection tests
│   └── PrivilegeEscalationDetectorTests.cs   — privilege escalation tests
├── Evidence/
│   ├── EvidenceBuilderTests.cs               — ZIP package and HMAC integrity tests
│   ├── CsvFormatterTests.cs                  — CSV output and injection defense tests
│   ├── HtmlFormatterTests.cs                 — HTML output and XSS prevention tests
│   ├── JsonFormatterTests.cs                 — JSON output and structure tests
│   ├── MarkdownFormatterTests.cs             — Markdown formatting tests
│   └── StixFormatterTests.cs                 — STIX format output tests
├── Agent/
│   ├── SecurityAgentTests.cs                 — agent orchestration, policy, coverage, capabilities, suppression, explanation, follow-up question tests, and CIS mapping flow-through tests (RunSingleRuleAsync, Crash, PolicyDisabled, IContextualRule)
│   ├── AuditDiffCalculatorTests.cs           — fingerprint-aware audit diff tests
│   ├── SuppressionStoreTests.cs              — expiry, retention, and fingerprint matching tests
│   ├── RuleTests.cs                          — posture rule and contextual rule behavior tests; CIS mapping presence and metadata validation for all 39 rules
│   ├── DefaultRulePolicyProviderTests.cs     — built-in role defaults and JSON override merge tests
│   ├── JsonRulePolicyStoreTests.cs           — policy persistence and hand-edited JSON lookup tests
│   └── ScannerParserFixtureTests.cs          — realistic command-output parser and capability fixtures
├── Integration/
│   ├── SentryAnalyzerTests.cs                — full-pipeline orchestration tests
│   ├── RealLogFileIntegrationTests.cs        — real sample log file tests
│   ├── RealWorldAttackScenarioTests.cs       — synthetic attack scenario tests
│   ├── ConfigurableThresholdIntegrationTests.cs — custom threshold integration tests
│   ├── GoldenScenarioIntegrationTests.cs     — golden scenario end-to-end tests
│   ├── PerformanceTests.cs                   — time-bound large-input tests
│   └── ProfileComparisonTests.cs             — intensity profile comparison tests
├── Avalonia/
│   ├── AsyncRelayCommandTests.cs             — async command execution tests
│   ├── MainViewModelTests.cs                 — main UI ViewModel command tests
│   ├── AgentViewModelTests.cs                — Security Agent chat and command tests
│   ├── AgentViewModelHistoryTests.cs         — persistent audit history tests
│   ├── RuleCoverageViewModelTests.cs         — rule coverage grouping tests
│   ├── SuppressionViewModelTests.cs          — suppression review queue tests
│   ├── FindingsViewModelTests.cs             — findings display ViewModel tests
│   └── EvidenceViewModelTests.cs             — evidence export ViewModel tests
├── Helpers/
│   └── LogScenarioBuilder.cs                 — synthetic log generation helper
└── Data/Real/Samples/
    ├── golden-compromise-timeline.log        — golden scenario compromise timeline
    ├── iptables-attack.log                   — real iptables attack capture
    ├── iptables-mixed-prefixes.log           — mixed prefix format iptables capture
    ├── nftables-traffic.log                  — real nftables traffic capture
    └── large-portscan.log                    — large-scale port scan capture
```

---

## Test Commands

| Command | Purpose |
|---|---|
| `dotnet test` | Run the full test suite |
| `dotnet test --filter "FullyQualifiedName~PortScan"` | Run tests matching a name pattern |
| `dotnet test --filter "FullyQualifiedName~Integration"` | Run only integration tests |
| `dotnet test --logger "console;verbosity=detailed"` | Run with detailed output |
| `dotnet run --project tools/TestAnalysis -- <logfile>` | Run CLI against a sample log |

---

## Test Categories

| Category | Files | Scope |
|---|---|---|
| Core | 5 | Parsing, normalization, event construction, field extraction |
| Detectors (Baseline) | 6 | Port scan, beaconing, flood, lateral movement, policy violation, novelty |
| Detectors (Linux) | 5 | Flag anomaly, interface hopping, kernel module, MAC spoofing, packet size |
| Detectors (Advanced) | 2 | C2 channel, privilege escalation |
| Evidence | 6 | Builder integrity, CSV/HTML/JSON/Markdown/STIX formatting |
| Integration | 7 | Full pipeline, real logs, attack scenarios, golden scenarios, thresholds, performance, profiles |
| Avalonia | 4 | ViewModel command bindings and display logic |

---

## Test Pipeline Flow

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Arrange          │    │  Act              │    │  Assert           │    │  Verify           │
│  Build test data  │───▶│  Execute detector │───▶│  Check findings   │───▶│  Check properties │
│  via builder or   │    │  or analyzer      │    │  count/severity   │    │  category, host,  │
│  raw log text     │    │  with profile     │    │  match expected   │    │  details, time    │
└──────────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘
```

---

## Assertion Patterns

| Assertion | Purpose | Example |
|---|---|---|
| `Assert.Single(collection)` | Exactly one finding | `Assert.Single(findings)` |
| `Assert.Empty(collection)` | No findings | `Assert.Empty(findings)` |
| `Assert.Contains(predicate)` | Finding present | `Assert.Contains(result.Findings, f => f.Category == "PortScan")` |
| `Assert.Equal(expected, actual)` | Exact match | `Assert.Equal("PortScan", findings[0].Category)` |
| `Assert.True(condition, message)` | Boolean check with context | `Assert.True(duration.TotalSeconds < 10.0, ...)` |
| `Assert.Throws<T>(action)` | Exception expected | `Assert.Throws<OperationCanceledException>(...)` |

---

## Key Test Files

| File | Role |
|---|---|
| [UnifiedEventTests.cs](../../../../VulcansTrace.Linux.Tests/Core/UnifiedEventTests.cs), [LinuxIptablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxIptablesParserTests.cs), [LinuxNftablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxNftablesParserTests.cs), [LogNormalizerTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LogNormalizerTests.cs) | Core parsing unit tests |
| [PortScanDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Baseline/PortScanDetectorTests.cs) | Detector boundary tests |
| [SentryAnalyzerTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/SentryAnalyzerTests.cs) | Full-pipeline integration |
| [RealWorldAttackScenarioTests.cs](../../../../VulcansTrace.Linux.Tests/Integration/RealWorldAttackScenarioTests.cs) | Attack scenario tests |
| [EvidenceBuilderTests.cs](../../../../VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs) | Evidence integrity tests |
| [LogScenarioBuilder.cs](../../../../VulcansTrace.Linux.Tests/Helpers/LogScenarioBuilder.cs) | Synthetic log generator |

---

## Real Log Fixtures

| File | Content | Purpose |
|---|---|---|
| `Data/Real/Samples/iptables-attack.log` | Actual iptables attack capture | Validates parser against real formatting |
| `Data/Real/Samples/nftables-traffic.log` | Actual nftables traffic capture | Validates nftables parser output |
| `Data/Real/Samples/large-portscan.log` | Large-scale port scan capture | Performance and scale testing |

---

## Security Takeaways

1. The test suite structure mirrors the production code structure — every production component has a corresponding test file
2. Three tiers of test fidelity — synthetic logs, boundary-value inputs, and real-world fixtures — provide layered confidence
3. xUnit's `[Fact]` attribute makes every test method self-documenting and independently runnable
4. The `LogScenarioBuilder` helper decouples test intent from log format details, making tests resilient to parser changes
5. Performance tests with explicit time bounds prevent regressions from silently degrading analysis speed
