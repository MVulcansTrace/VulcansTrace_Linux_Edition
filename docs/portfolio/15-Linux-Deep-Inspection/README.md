# Linux Deep Inspection

The Linux Deep Inspection subsystem provides five specialized detectors that analyze Linux-specific metadata in iptables/nftables logs — TCP flag anomalies, MAC address spoofing, kernel module posture assessment, interface hopping, and unusual packet sizes. Together they cover reconnaissance detection, L2/L3 integrity verification, defensive posture assessment, network segmentation enforcement, and data exfiltration/covert channel identification.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Linux-Deep-Inspection-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its five detectors, and where the proof lives
- [Quick Reference](./Linux-Deep-Inspection-Summary/Quick-Reference.md) — algorithm stages, configuration, output schema, and thresholds at a glance for all five detectors
- [Why This Matters](./Linux-Deep-Inspection-In-Depth/Why-This-Matters.md) — the security problems these detectors solve and the principles behind them
- [Flag Anomaly Algorithm](./Linux-Deep-Inspection-In-Depth/Core-Logic-Breakdown/Flag-Anomaly-Algorithm.md) — step-by-step walkthrough of the TCP flag anomaly detection pipeline
- [MAC Spoofing Algorithm](./Linux-Deep-Inspection-In-Depth/Core-Logic-Breakdown/MAC-Spoofing-Algorithm.md) — step-by-step walkthrough of the MAC address spoofing detection pipeline
- [Kernel Module Algorithm](./Linux-Deep-Inspection-In-Depth/Core-Logic-Breakdown/Kernel-Module-Algorithm.md) — step-by-step walkthrough of the kernel module posture assessment pipeline
- [Interface Hopping Algorithm](./Linux-Deep-Inspection-In-Depth/Core-Logic-Breakdown/Interface-Hopping-Algorithm.md) — step-by-step walkthrough of the interface hopping detection pipeline
- [Packet Size Algorithm](./Linux-Deep-Inspection-In-Depth/Core-Logic-Breakdown/Packet-Size-Algorithm.md) — step-by-step walkthrough of the unusual packet size detection pipeline
- [Design Decisions](./Linux-Deep-Inspection-In-Depth/Design-Decisions.md) — rationale for key architectural choices across all five detectors
- [Code Patterns](./Linux-Deep-Inspection-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Linux-Deep-Inspection-In-Depth/Attack-Scenario.md) — worked example showing a multi-signal Linux attack being detected
- [Evasion and Limitations](./Linux-Deep-Inspection-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [MITRE ATT&CK Mapping](./Linux-Deep-Inspection-In-Depth/MITRE-ATTACK-Mapping.md) — technique mapping and attack lifecycle context

## System Capabilities

- **Flag anomaly detection** — identifies FIN-without-SYN stealth scans and FIN+PSH+URG XMAS scans from TCP flag metadata
- **MAC spoofing detection** — groups by SourceIP and flags IPs associated with multiple distinct MAC addresses (ARP poisoning, masquerading)
- **Kernel module posture** — scans raw log lines for signatures of conntrack, rate limiting, IPv6, Layer 7 filtering, and quota/bandwidth modules
- **Interface hopping detection** — groups by SourceIP, detects rapid switching between multiple network interfaces within a configurable time window
- **Unusual packet size detection** — two-phase analysis: per-packet threshold checks for large/small packets, then aggregate statistical analysis for covert channels and fragmentation
- **Risk escalation integration** — `RiskEscalator` correlates FlagAnomaly+PortScan to Critical and MacSpoofing+InterfaceHopping to Critical

## Implementation Evidence

- [FlagAnomalyDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/FlagAnomalyDetector.cs) — TCP flag analysis detector
- [MacSpoofingDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/MacSpoofingDetector.cs) — MAC address spoofing detector
- [KernelModuleDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/KernelModuleDetector.cs) — kernel module posture detector
- [InterfaceHoppingDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/InterfaceHoppingDetector.cs) — interface hopping detector
- [UnusualPacketSizeDetector.cs](../../../VulcansTrace.Linux.Engine/Detectors/UnusualPacketSizeDetector.cs) — packet size anomaly detector
- [RiskEscalator.cs](../../../VulcansTrace.Linux.Engine/RiskEscalator.cs) — correlated severity escalation
- [FlagAnomalyDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Linux/FlagAnomalyDetectorTests.cs) — flag anomaly test suite
- [MacSpoofingDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Linux/MacSpoofingDetectorTests.cs) — MAC spoofing test suite
- [KernelModuleDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Linux/KernelModuleDetectorTests.cs) — kernel module test suite
- [InterfaceHoppingDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Linux/InterfaceHoppingDetectorTests.cs) — interface hopping test suite
- [UnusualPacketSizeDetectorTests.cs](../../../VulcansTrace.Linux.Tests/Detectors/Linux/UnusualPacketSizeDetectorTests.cs) — packet size test suite
