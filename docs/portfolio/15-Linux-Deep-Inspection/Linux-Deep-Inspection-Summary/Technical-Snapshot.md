# Technical Snapshot: Linux Deep Inspection

> The Linux Deep Inspection subsystem comprises five specialized detectors totaling 593 lines of implementation code and 2,913 lines of test coverage. Together they analyze Linux-specific metadata from iptables/nftables logs — TCP flags, MAC addresses, kernel module signatures, network interfaces, and packet sizes — to detect reconnaissance, L2/L3 integrity violations, defensive posture gaps, segmentation bypass, and covert channels. All five detectors implement `IDetector` and integrate with the `RiskEscalator` for correlated threat escalation.

---

## Implementation Overview

The subsystem operates on the unified event stream enriched with `LinuxSpecific` metadata extracted during log normalization. Each detector targets a distinct analytical dimension:

| Detector | Lines | Category | Severity | Purpose |
|---|---|---|---|---|
| FlagAnomalyDetector | 86 | FlagAnomaly | Medium | Detect FIN-without-SYN and XMAS (FIN+PSH+URG) scan patterns |
| MacSpoofingDetector | 121 | MacSpoofing | High | Flag IPs associated with multiple distinct MACs within a sliding window |
| KernelModuleDetector | 95 | KernelModule | Info | Enumerate firewall kernel modules from raw log signatures |
| InterfaceHoppingDetector | 116 | InterfaceHopping | Medium | Detect rapid interface switching via sliding window per source IP |
| UnusualPacketSizeDetector | 173 | UnusualPacketSize | Low–Medium | Identify oversized/undersized packets and statistical size anomalies |

---

## Key Metrics

| Metric | Value |
|---|---|
| Total implementation size | 591 lines (5 detectors) |
| Total test coverage | 2,913 lines (5 test classes) |
| Interfaces implemented | `IDetector` (all 5) |
| Finding categories | `FlagAnomaly`, `MacSpoofing`, `KernelModule`, `InterfaceHopping`, `UnusualPacketSize` |
| Severity range | Info → High |
| Risk escalation rules | FlagAnomaly+PortScan → Critical, MacSpoofing+InterfaceHopping → Critical |
| Cancellation points | Every per-event and per-group loop iteration |

---

## Why It Matters

- TCP flag anomalies reveal stealth scanning techniques (FIN, XMAS) that bypass basic port scan detection
- MAC spoofing detection identifies ARP poisoning and network masquerading — common L2 attack vectors — using time-bounded sliding windows to avoid false positives
- Kernel module posture assessment reveals defensive capabilities and potential gaps in firewall configuration
- Interface hopping detection catches attackers pivoting between network segments to evade monitoring, using the same sliding window pattern to find tightest clusters
- Unusual packet size analysis exposes covert channels and data exfiltration that would be invisible to port-based detection
- The `RiskEscalator` correlates findings across detectors, escalating independent Medium/High signals to Critical when they converge on the same host

---

## Key Evidence

- [FlagAnomalyDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/FlagAnomalyDetector.cs) — TCP flag analysis (86 lines)
- [MacSpoofingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/MacSpoofingDetector.cs) — MAC spoofing detection (121 lines)
- [KernelModuleDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/KernelModuleDetector.cs) — kernel module posture (95 lines)
- [InterfaceHoppingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/InterfaceHoppingDetector.cs) — interface hopping detection (117 lines)
- [UnusualPacketSizeDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/UnusualPacketSizeDetector.cs) — packet size analysis (173 lines)
- [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) — correlated severity escalation (130 lines)
- [FlagAnomalyDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/FlagAnomalyDetectorTests.cs) — test suite (422 lines)
- [MacSpoofingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/MacSpoofingDetectorTests.cs) — test suite (643 lines)
- [KernelModuleDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/KernelModuleDetectorTests.cs) — test suite (630 lines)
- [InterfaceHoppingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/InterfaceHoppingDetectorTests.cs) — test suite (553 lines)
- [UnusualPacketSizeDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/UnusualPacketSizeDetectorTests.cs) — test suite (665 lines)

---

## Key Design Choices

- **Independent detectors with shared escalation** — Each detector is a self-contained `IDetector` implementation. Correlation and severity escalation happen downstream in `RiskEscalator`, not inside individual detectors. This keeps each detector focused on a single analytical dimension.

- **Linux-specific metadata via `LinuxSpecific` dictionary** — All five detectors consume the `LinuxSpecific` key-value metadata extracted by the log normalizer (e.g., `Flags`, `MAC`, `InterfaceIn`, `Length`). This keeps the core `UnifiedEvent` schema clean while giving Linux detectors access to platform-specific fields.

- **Sliding window in MacSpoofing and InterfaceHopping** — Both detectors use a two-pointer sliding window to find the time-bounded window with maximum distinct values (MACs or interfaces). This avoids false positives from legitimate long-term changes while detecting tight clusters of diversity that indicate spoofing or hopping.

- **Two-phase analysis in UnusualPacketSizeDetector** — Per-packet threshold checks grouped by `(SrcIP, DstIP)` pairs run on every event, while aggregate statistical analysis (consistency, variance) grouped by `(SrcIP, DstIP, DstPort, Proto)` tuples runs only when sufficient packets are available (configurable via `PacketSizeMinForAnalysis`). This avoids noisy statistical signals on small samples.

- **Keyword-based posture in KernelModuleDetector** — The detector scans `RawLine` using a mix of `IsWholeToken` (for precise token matching) and case-insensitive `Contains` (for flexible substring matching). This is resilient to log format variations and provides a quick inventory of firewall capabilities without requiring schema knowledge.

---

## Security Takeaways

1. The five detectors address distinct attack dimensions — network reconnaissance (flags), L2 integrity (MAC), defensive posture (kernel modules), segmentation enforcement (interfaces), and data integrity (packet sizes)
2. Each detector is independently testable and deployable — no inter-detector dependencies exist at the detection stage
3. The `RiskEscalator` provides the correlation layer, escalating FlagAnomaly+PortScan and MacSpoofing+InterfaceHopping to Critical severity
4. The sliding window pattern in MacSpoofing and InterfaceHopping detectors prevents false positives from legitimate long-term MAC/interface changes while detecting tight clusters of diversity
5. The two-phase packet size analysis avoids false positives from small sample sizes while maintaining per-pair alerting for clear-cut anomalies
