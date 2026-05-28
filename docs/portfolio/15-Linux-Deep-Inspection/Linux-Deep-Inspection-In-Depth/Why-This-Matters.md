# Why This Matters: Linux Deep Inspection

## The Security Problem

Standard firewall log analysis focuses on connection-level metadata — source IP, destination IP:port, protocol, and action. But iptables and nftables logs on Linux contain far richer information: TCP flag combinations, MAC addresses, network interface identifiers, packet sizes, and kernel module signatures. This metadata is critical for detecting attacks that evade basic connection-pattern analysis.

Consider these real-world attack scenarios that basic detection misses:

- An attacker sends FIN packets without a preceding SYN to enumerate open ports — a technique invisible to port-counting detectors because each target is only probed once
- A compromised host spoofs its MAC address to impersonate a trusted device, enabling ARP poisoning and traffic interception at Layer 2
- An attacker pivots between network interfaces (eth0 → eth1 → wlan0) to probe segments with different security policies, bypassing segmentation controls
- A data exfiltration tool sends fixed-size packets on non-standard ports, creating a covert channel that blends into normal traffic volume
- A firewall's defensive capabilities are unknown — analysts cannot assess risk without knowing whether conntrack, rate limiting, or Layer 7 filtering are active

The five Linux Deep Inspection detectors address each of these gaps by analyzing platform-specific metadata that generic detectors cannot access.

---

## Implementation Overview

The subsystem comprises five independent `IDetector` implementations with each detector targeting a specific analytical dimension:

| Detector | Signal | Attack Addressed |
|---|---|---|
| FlagAnomalyDetector | TCP flag combinations | Stealth/XMAS scanning (T1046, T1595) |
| MacSpoofingDetector | MAC-to-IP mappings | ARP poisoning, L2 masquerading (T1200) |
| KernelModuleDetector | Raw log line signatures | Defensive posture gaps (T1562.001) |
| InterfaceHoppingDetector | Interface-per-IP switching | Segmentation bypass (T1046, T1595) |
| UnusualPacketSizeDetector | Packet length analysis | Covert channels, exfiltration (T1048, T1571) |

All detectors consume the `LinuxSpecific` metadata dictionary populated during log normalization, keeping the core `UnifiedEvent` schema clean while enabling Linux-specific analysis.

---

## Operational Benefits

| Benefit | How It Helps |
|---|---|
| Multi-dimensional detection | Five independent signals provide overlapping coverage — an attacker evading one detector is likely caught by another |
| Posture assessment | KernelModuleDetector reveals which firewall capabilities are active, informing risk assessment before an attack occurs |
| L2 integrity verification | MAC spoofing detection catches Layer 2 attacks that are invisible to IP-layer analysis |
| Covert channel identification | Packet size analysis detects data exfiltration that produces no abnormal connection patterns |
| Correlated escalation | `RiskEscalator` promotes FlagAnomaly+PortScan and MacSpoofing+InterfaceHopping to Critical severity automatically |
| Minimal configuration | Five boolean enable/disable flags — no threshold tuning required for default operation |

---

## Security Principles Applied

| Principle | Application |
|---|---|
| Defense in depth | Five detectors cover five distinct attack dimensions; the `RiskEscalator` correlates findings across all of them plus the baseline detectors |
| Separation of concerns | Each detector is a self-contained class implementing `IDetector` — no shared mutable state, no inter-detector dependencies |
| Least privilege | Detectors only read from the event stream; they never modify input events or shared state |
| Fail safe | Cooperative cancellation throws `OperationCanceledException`, ensuring partial results are never published |
| Transparency | Findings include the specific signal that triggered them (flag combination, MAC list, interface list, packet size) so analysts can verify quickly |

---

## Implementation Evidence

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

## Elevator Pitch

> The Linux Deep Inspection subsystem takes the Linux-specific metadata that iptables logs provide — TCP flags, MAC addresses, interface identifiers, packet sizes, and kernel module signatures — and, across five focused detectors, identifies stealth scanning, ARP poisoning, segmentation bypass, covert channels, and defensive posture gaps. The RiskEscalator then correlates these signals with baseline detectors, promoting independent Medium and High findings to Critical when they converge on the same host.

---

## Security Takeaways

1. Linux-specific metadata is a rich detection surface that generic firewall analyzers ignore — these five detectors exploit it fully
2. TCP flag analysis catches stealth scans (FIN, XMAS) that evade port-counting detectors because each target is probed only once
3. MAC spoofing detection provides L2 integrity verification — critical for networks where ARP poisoning enables traffic interception
4. Kernel module posture assessment gives analysts immediate visibility into which defensive capabilities are active
5. Interface hopping detection catches segmentation bypass attempts that are invisible to IP-layer analysis alone
6. Packet size analysis identifies covert channels and exfiltration through statistical anomaly detection — an attack vector with no connection-pattern signature
