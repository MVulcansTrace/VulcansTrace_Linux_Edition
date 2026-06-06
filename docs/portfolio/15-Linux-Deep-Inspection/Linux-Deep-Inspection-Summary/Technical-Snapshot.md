# Technical Snapshot: Linux Deep Inspection

> The Linux Deep Inspection subsystem comprises five specialized detectors spanning five implementation files and their focused test coverage. Together they analyze Linux-specific metadata from iptables/nftables logs — TCP flags, MAC addresses, kernel module signatures, network interfaces, and packet sizes — to detect reconnaissance, L2/L3 integrity violations, defensive posture gaps, segmentation bypass, and covert channels. All five detectors implement `IDetector` and integrate with the `RiskEscalator` for correlated threat escalation.

---

## Implementation Overview

The subsystem operates on the unified event stream enriched with `LinuxSpecific` metadata extracted during log normalization. Each detector targets a distinct analytical dimension:

| Detector | Category | Severity | Purpose |
|---|---|---|---|
| FlagAnomalyDetector | FlagAnomaly | Medium | Detect FIN-without-SYN and XMAS (FIN+PSH+URG) scan patterns |
| MacSpoofingDetector | MacSpoofing | High | Flag IPs associated with multiple distinct MACs within a sliding window |
| KernelModuleDetector | KernelModule | Info | Enumerate firewall kernel modules from raw log signatures |
| InterfaceHoppingDetector | InterfaceHopping | Medium | Detect rapid interface switching via sliding window per source IP |
| UnusualPacketSizeDetector | UnusualPacketSize | Low–Medium | Identify oversized/undersized packets and statistical size anomalies |

---

## Key Metrics

| Metric | Value |
|---|---|
| Interfaces implemented | `IDetector` (all 5) |
| Finding categories | `FlagAnomaly`, `MacSpoofing`, `KernelModule`, `InterfaceHopping`, `UnusualPacketSize` |
| Severity range | Info → High |
| Risk escalation rules | FlagAnomaly+PortScan → Critical, MacSpoofing+InterfaceHopping → Critical; confidence recalculated during escalation |
| Cancellation points | Every per-event and per-group loop iteration |

---

## Why It Matters

- TCP flag anomalies reveal stealth scanning techniques (FIN, XMAS) that bypass basic port scan detection
- MAC spoofing detection identifies ARP poisoning and network masquerading — common L2 attack vectors — using time-bounded sliding windows to avoid false positives
- Kernel module posture assessment reveals defensive capabilities and potential gaps in firewall configuration
- Interface hopping detection catches attackers pivoting between network segments to evade monitoring, using the same sliding window pattern to find tightest clusters
- Unusual packet size analysis exposes covert channels and data exfiltration that would be invisible to port-based detection
- The `RiskEscalator` correlates findings across detectors, escalating independent Medium/High signals to Critical when they converge on the same host and recalculating detection confidence

---

## Key Evidence

- [FlagAnomalyDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/FlagAnomalyDetector.cs) — TCP flag analysis
- [MacSpoofingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/MacSpoofingDetector.cs) — MAC spoofing detection
- [KernelModuleDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/KernelModuleDetector.cs) — kernel module posture
- [InterfaceHoppingDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/InterfaceHoppingDetector.cs) — interface hopping detection
- [UnusualPacketSizeDetector.cs](../../../../VulcansTrace.Linux.Engine/Detectors/UnusualPacketSizeDetector.cs) — packet size analysis
- [RiskEscalator.cs](../../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) — correlated severity escalation
- [FlagAnomalyDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/FlagAnomalyDetectorTests.cs) — test suite
- [MacSpoofingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/MacSpoofingDetectorTests.cs) — test suite
- [KernelModuleDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/KernelModuleDetectorTests.cs) — test suite
- [InterfaceHoppingDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/InterfaceHoppingDetectorTests.cs) — test suite
- [UnusualPacketSizeDetectorTests.cs](../../../../VulcansTrace.Linux.Tests/Detectors/Linux/UnusualPacketSizeDetectorTests.cs) — test suite

---

## Key Design Choices

- **Independent detectors with shared escalation** — Each detector is a self-contained `IDetector` implementation. Correlation and severity escalation happen downstream in `RiskEscalator`, not inside individual detectors. The escalator also recalculates detection confidence by appending a correlation evidence signal. This keeps each detector focused on a single analytical dimension.

- **Linux-specific metadata via `LinuxSpecific` dictionary** — All five detectors consume the `LinuxSpecific` key-value metadata extracted by the log normalizer (e.g., `Flags`, `MAC`, `InterfaceIn`, `Length`). This keeps the core `UnifiedEvent` schema clean while giving Linux detectors access to platform-specific fields.

- **Sliding window in MacSpoofing and InterfaceHopping** — Both detectors use a two-pointer sliding window to find the time-bounded window with maximum distinct values (MACs or interfaces). This avoids false positives from legitimate long-term changes while detecting tight clusters of diversity that indicate spoofing or hopping.

- **Two-phase analysis in UnusualPacketSizeDetector** — Per-packet threshold checks grouped by `(SrcIP, DstIP)` pairs run on every event, while aggregate statistical analysis (consistency, variance) grouped by `(SrcIP, DstIP, DstPort, Proto)` tuples runs only when sufficient packets are available (configurable via `PacketSizeMinForAnalysis`). This avoids noisy statistical signals on small samples.

- **Keyword-based posture in KernelModuleDetector** — The detector scans `RawLine` using a mix of `IsWholeToken` (for precise token matching) and case-insensitive `Contains` (for flexible substring matching). This is resilient to log format variations and provides a quick inventory of firewall capabilities without requiring schema knowledge.

---

## Security Takeaways

1. The five detectors address distinct attack dimensions — network reconnaissance (flags), L2 integrity (MAC), defensive posture (kernel modules), segmentation enforcement (interfaces), and data integrity (packet sizes)
2. Each detector is independently testable and deployable — no inter-detector dependencies exist at the detection stage
3. The `RiskEscalator` provides the correlation layer, escalating FlagAnomaly+PortScan and MacSpoofing+InterfaceHopping to Critical severity and recalculating detection confidence
4. The sliding window pattern in MacSpoofing and InterfaceHopping detectors prevents false positives from legitimate long-term MAC/interface changes while detecting tight clusters of diversity
5. The two-phase packet size analysis avoids false positives from small sample sizes while maintaining per-pair alerting for clear-cut anomalies
