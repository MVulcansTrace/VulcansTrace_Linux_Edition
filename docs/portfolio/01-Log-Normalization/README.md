# Log Normalization

The log normalization subsystem ingests raw Linux firewall logs (iptables and nftables), auto-detects the format, and produces a unified, validated event stream that downstream detectors consume.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Log-Normalization-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its design, and where the proof lives
- [Quick Reference](./Log-Normalization-Summary/Quick-Reference.md) — algorithm stages, configuration, output schema, and format support at a glance
- [Why This Matters](./Log-Normalization-In-Depth/Why-This-Matters.md) — the security problem this subsystem solves and the principles behind it
- [Normalization Algorithm](./Log-Normalization-In-Depth/Core-Logic-Breakdown/Normalization-Algorithm.md) — step-by-step walkthrough of the parsing pipeline
- [Design Decisions](./Log-Normalization-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Log-Normalization-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Log-Normalization-In-Depth/Attack-Scenario.md) — worked example showing a real iptables attack log being parsed
- [Evasion and Limitations](./Log-Normalization-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [Log Management and Standards](./Log-Normalization-In-Depth/Log-Management-and-Standards.md) — NIST, FRE, and capability mapping

## System Capabilities

- **Format auto-detection** — inspects log lines to identify iptables vs. nftables format without user configuration
- **Dual-format parsing** — regex-based extraction of IPs, ports, protocol, interfaces, MAC addresses, TCP flags, and firewall action from both iptables and nftables kernel logs
- **Fail-soft error handling** — malformed lines are logged and skipped without halting the parse, preserving maximum event yield
- **Immutable validated events** — every `UnifiedEvent` enforces IP validation, port range validation, and required fields at construction time
- **Extensible metadata** — a `LinuxSpecific` dictionary carries format-specific fields (MAC, TTL, TOS, HOPLIMIT, TC, FLOWLBL, PREC, RES, URGP, DF, UID, GID, MARK, and more) without polluting the core schema

## Implementation Evidence

- [LogNormalizer.cs](../../../VulcansTrace.Linux.Core/LogNormalizer.cs) — orchestrator: size guard, format detection, mixed-format routing, parser delegation (227 lines)
- [LinuxIptablesParser.cs](../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs) — iptables regex extraction and action derivation (203 lines)
- [LinuxNftablesParser.cs](../../../VulcansTrace.Linux.Core/LinuxNftablesParser.cs) — nftables regex extraction and chain-based action derivation (227 lines)
- [UnifiedEvent.cs](../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) — immutable domain model with validation and `ConnectionKey` (205 lines)
- [LogNormalizerTests.cs](../../../VulcansTrace.Linux.Tests/Core/LogNormalizerTests.cs) — format detection and end-to-end normalization tests (300 lines)
- [LinuxIptablesParserTests.cs](../../../VulcansTrace.Linux.Tests/Core/LinuxIptablesParserTests.cs) — iptables parsing coverage (821 lines)
- [LinuxNftablesParserTests.cs](../../../VulcansTrace.Linux.Tests/Core/LinuxNftablesParserTests.cs) — nftables parsing coverage (854 lines)
- [UnifiedEventTests.cs](../../../VulcansTrace.Linux.Tests/Core/UnifiedEventTests.cs) — domain model and `ConnectionKey` tests (437 lines)
