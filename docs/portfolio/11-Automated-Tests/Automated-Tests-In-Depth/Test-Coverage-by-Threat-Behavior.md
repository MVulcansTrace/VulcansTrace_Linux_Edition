# Test Coverage by Threat Behavior

## Capability Mapping

| Capability | Verification Function | Relevant Framework |
|---|---|---|
| Log format detection (iptables/nftables) | `LinuxIptablesParserTests`, `LinuxNftablesParserTests`, `LogNormalizerTests` | xUnit `[Fact]` — field extraction, format discrimination, error handling |
| Event normalization and validation | `UnifiedEventTests` | xUnit `[Fact]` — connection key, IP validation, port validation |
| Port scan detection (T1046) | `PortScanDetectorTests` — boundary-value triples at threshold 15 | xUnit `[Fact]` — at/below/above threshold, multi-source, property validation |
| Beaconing detection (T1071.001) | `BeaconingDetectorTests` — interval regularity analysis | xUnit `[Fact]` — periodic communication, interval variance |
| Flood/DoS detection (T1498) | `FloodDetectorTests` — volume threshold analysis | xUnit `[Fact]` — event count per time window, single-source flood |
| Lateral movement detection (T1021) | `LateralMovementDetectorTests` — internal host-to-host patterns | xUnit `[Fact]` — multi-target internal scanning |
| Policy violation detection | `PolicyViolationDetectorTests` — rule breach identification | xUnit `[Fact]` — blocked traffic, unauthorized protocols |
| Novelty detection | `NoveltyDetectorTests` — unseen pattern identification | xUnit `[Fact]` — first-seen connections, statistical deviation |
| TCP flag anomaly detection | `FlagAnomalyDetectorTests` — non-standard TCP flag combinations | xUnit `[Fact]` — SYN/FIN, XMAS, NULL flags |
| MAC spoofing detection | `MacSpoofingDetectorTests` — MAC address inconsistency | xUnit `[Fact]` — same IP, different MAC |
| Interface hopping detection | `InterfaceHoppingDetectorTests` — network interface switching | xUnit `[Fact]` — same source across multiple interfaces |
| Kernel module activity | `KernelModuleDetectorTests` — kernel-level event detection | xUnit `[Fact]` — module load/unload patterns |
| Unusual packet size detection | `UnusualPacketSizeDetectorTests` — anomalous packet lengths | xUnit `[Fact]` — oversized/undersized packets |
| C2 channel detection (T1071) | `C2ChannelDetectorTests` — command-and-control communication | xUnit `[Fact]` — persistent external communication |
| Privilege escalation detection (T1068) | `PrivilegeEscalationDetectorTests` — elevation of access | xUnit `[Fact]` — escalation pattern identification |
| Risk escalation and correlation | `SentryAnalyzerTests.Analyze_RiskEscalator_EscalatesFindings` | xUnit `[Fact]` — multi-finding correlation, severity promotion |
| Evidence package integrity | `EvidenceBuilderTests` — ZIP structure and HMAC | xUnit `[Fact]` — manifest structure, file hashes, HMAC verification |
| CSV/HTML/Markdown formatting | `CsvFormatterTests`, `HtmlFormatterTests`, `MarkdownFormatterTests` | xUnit `[Fact]` — injection defense, content correctness |
| Full pipeline orchestration | `SentryAnalyzerTests` — 33 test methods | xUnit `[Fact]` — empty input, valid logs, cancellation, errors, performance |
| Real-world attack scenarios | `RealWorldAttackScenarioTests` — 12 attack patterns | xUnit `[Fact]` — DoS, port scan, C2, lateral movement, beaconing, mixed |
| Real log file integration | `RealLogFileIntegrationTests` — sample log fixtures | xUnit `[Fact]` — iptables-attack.log, nftables-traffic.log, large-portscan.log |
| Performance validation | `PerformanceTests`, `SentryAnalyzerTests.Analyze_Performance_LargeLogCompletesInTime` | xUnit `[Fact]` — time-bound execution under 10 seconds |
| Profile comparison | `ProfileComparisonTests` — Low/Medium/High intensity | xUnit `[Fact]` — threshold variation, severity filtering |
| UI ViewModel behavior | `MainViewModelTests`, `FindingsViewModelTests`, `EvidenceViewModelTests` | xUnit `[Fact]` — command enable/disable, data binding |

---

## Test Coverage by Threat Behavior

| Threat Behavior | Detector | Test File | Key Test Methods | Coverage Focus |
|---|---|---|---|---|
| Network reconnaissance (port scan) | `PortScanDetector` | `PortScanDetectorTests` | Above/Below/At threshold, multi-source, properties | Threshold boundary, finding structure |
| Denial of service (flood) | `FloodDetector` | `FloodDetectorTests` | Volume threshold, single-source, multi-target | Event count per window |
| Command and control (beaconing) | `BeaconingDetector` | `BeaconingDetectorTests` | Interval regularity, variance, long-duration | Timing analysis |
| Lateral movement | `LateralMovementDetector` | `LateralMovementDetectorTests` | Internal host-to-host, multi-service | Internal IP targeting |
| C2 channel communication | `C2ChannelDetector` | `C2ChannelDetectorTests` | Persistent external, periodic callback | External IP, persistence |
| Privilege escalation | `PrivilegeEscalationDetector` | `PrivilegeEscalationDetectorTests` | Access elevation patterns | Escalation indicators |
| Policy violation | `PolicyViolationDetector` | `PolicyViolationDetectorTests` | Rule breach, blocked traffic | Compliance checking |
| Novelty / zero-day indicators | `NoveltyDetector` | `NoveltyDetectorTests` | Unseen patterns, first-seen connections | Statistical deviation |
| TCP flag evasion | `FlagAnomalyDetector` | `FlagAnomalyDetectorTests` | SYN/FIN, XMAS, NULL, ACK-only | Non-standard flags |
| MAC address spoofing | `MacSpoofingDetector` | `MacSpoofingDetectorTests` | Same IP, different MAC | Layer 2 inconsistency |
| Interface hopping | `InterfaceHoppingDetector` | `InterfaceHoppingDetectorTests` | Multi-interface source | Network boundary crossing |
| Kernel module manipulation | `KernelModuleDetector` | `KernelModuleDetectorTests` | Module activity patterns | Kernel-level events |
| Unusual packet sizes | `UnusualPacketSizeDetector` | `UnusualPacketSizeDetectorTests` | Oversized/undersized packets | Length anomalies |
| Mixed attack scenarios | All detectors | `RealWorldAttackScenarioTests` | DoS+Scan+C2 combined | Multi-threat detection |

---

## Threat Behavior Coverage Matrix

```
                        ┌──────────────────────────────────────────────────────────────┐
                        │              Threat Behavior Coverage Matrix                  │
                        └──────────────────────────────────────────────────────────────┘

  Threat Behavior            Unit Tests    Integration    Scenario    Real Logs    Perf
  ─────────────────          ──────────    ───────────    ────────    ──────────   ────
  Port Scan (T1046)               ✓            ✓            ✓           ✓          ✓
  DoS/Flood (T1498)               ✓            ✓            ✓           ·          ✓
  Beaconing (T1071.001)           ✓            ✓            ✓           ·          ·
  Lateral Movement (T1021)        ✓            ✓            ✓           ·          ·
  C2 Channel (T1071)              ✓            ✓            ✓           ·          ·
  Privilege Escalation (T1068)    ✓            ✓            ·           ·          ·
  Policy Violation                ✓            ✓            ·           ·          ·
  Novelty/Zero-Day                ✓            ✓            ·           ·          ·
  Flag Anomaly                    ✓            ✓            ·           ·          ·
  MAC Spoofing                    ✓            ✓            ·           ·          ·
  Interface Hopping               ✓            ✓            ·           ·          ·
  Kernel Module                   ✓            ✓            ·           ·          ·
  Packet Size                     ✓            ✓            ·           ·          ·
  Mixed Attack                    ·            ✓            ✓           ·          ·

  Legend: ✓ = covered    · = not covered
```

---

## Verification Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          Test Verification Flow                              │
│                                                                              │
│  ┌─────────────────┐                                                         │
│  │  Test Input      │                                                        │
│  │  ┌─────────────┐ │  ┌─────────────────┐  ┌──────────────────┐            │
│  │  │ Synthetic   │ │  │  Arrange         │  │  Act              │            │
│  │  │ (Builder)   │─┼─▶│  Build input     │─▶│  Execute detector │            │
│  │  ├─────────────┤ │  │  Configure       │  │  or analyzer      │            │
│  │  │ Raw Text    │ │  │  profile         │  │                    │            │
│  │  ├─────────────┤ │  └─────────────────┘  └────────┬─────────┘            │
│  │  │ Real Logs   │ │                                 │                      │
│  │  └─────────────┘ │                                 ▼                      │
│  └─────────────────┘  ┌─────────────────────────────────────────────────┐    │
│                        │  Assert                                          │    │
│                        │  ┌────────────┐  ┌────────────┐  ┌───────────┐ │    │
│                        │  │ Finding    │  │ Result     │  │ Side      │ │    │
│                        │  │ count &    │  │ structure  │  │ effects   │ │    │
│                        │  │ properties │  │ (parsed,   │  │ (HMAC,    │ │    │
│                        │  │            │  │  errors,   │  │  timing,  │ │    │
│                        │  │            │  │  warnings) │  │  ZIP)     │ │    │
│                        │  └────────────┘  └────────────┘  └───────────┘ │    │
│                        └─────────────────────────────────────────────────┘    │
│                                                                              │
│  Verification Tiers:                                                         │
│  ───────────────────                                                         │
│  Tier 1: Unit — single detector, controlled input, exact threshold tests     │
│  Tier 2: Integration — full pipeline, all detectors, profile variation       │
│  Tier 3: Scenario — multi-attack logs, real-world attack patterns            │
│  Tier 4: Real Logs — actual iptables/nftables captures from production       │
│  Tier 5: Performance — time-bound execution on large inputs                  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Takeaways

1. The test suite covers all 13+ detector types with unit tests, and the 6 most critical threat behaviors (port scan, flood, beaconing, lateral movement, C2, mixed attacks) have dedicated scenario tests
2. Port scan detection has the deepest coverage — boundary-value triples, multi-source tests, property assertions, integration tests, real-log tests, and performance tests
3. The five verification tiers (unit, integration, scenario, real logs, performance) provide defense in depth — each tier catches bugs the previous tier misses
4. Evidence packaging integrity is verified end-to-end — ZIP structure, file hashes, and HMAC verification — ensuring forensically sound output
5. The threat behavior coverage matrix reveals that Linux-specific detectors (flag anomaly, MAC spoofing, interface hopping, kernel module, packet size) currently lack dedicated scenario and real-log tests, which is the highest-priority gap to address
