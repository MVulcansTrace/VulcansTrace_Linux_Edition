## The Security Problem

Linux firewall logs — iptables and nftables — are the primary source of network perimeter telemetry on Linux servers. However, these logs are written by the kernel as unstructured, freeform text with key=value pairs embedded in varying positions. There is no standard schema, no consistent field ordering, and no native validation. Without a normalization layer, every downstream detector would need to implement its own ad-hoc parsing, leading to duplicated logic, inconsistent field interpretation, and gaps where malformed data silently corrupts analysis.

This is not a theoretical concern. In incident response, analysts routinely receive log files that span months, originate from multiple servers, and may contain lines from both iptables and nftables due to infrastructure migrations. A single misinterpreted port number or a silently dropped timestamp can cause a detector to miss a port scan, a beacon, or a lateral movement attempt.

---

## Implementation Overview

The log normalization subsystem solves this by providing a single, validated entry point:

- **`LogNormalizer.Normalize()`** accepts raw log text, enforces a 100M character safety cap, auto-detects the format (iptables or nftables), and delegates to the correct parser
- **`LinuxIptablesParser`** and **`LinuxNftablesParser`** each apply ~30 compiled regexes per line to extract every available field
- **`UnifiedEvent`** is an immutable, validated domain object that enforces IP validity, port range constraints, and required fields at construction time
- **`ParseResult`** returns both the successfully parsed events and a separate error collection, so no information is lost

---

## Operational Benefits

| Benefit | How It Is Achieved |
|---|---|
| Single entry point for all log types | `LogNormalizer` auto-detects format, callers never specify it |
| Maximum event yield from noisy logs | Fail-soft parsing skips bad lines without aborting |
| Validated downstream data | `UnifiedEvent` constructor rejects invalid IPs and ports |
| Forensic traceability | `RawLine` preserves the original log text for every event |
| Format-specific metadata | `LinuxSpecific` dictionary carries flags, TTL, and format-specific fields (e.g., MAC, Chain for nftables) |
| Protection against resource exhaustion | 100M character hard cap on input |

---

## Security Principles Applied

| Principle | Implementation |
|---|---|
| **Defense in depth** | Size cap, field validation, port range checks, IP address validation — multiple independent guards |
| **Fail safely** | Lines that throw during parsing produce errors rather than exceptions; the parse continues |
| **Preserve evidence** | `RawLine`, `Errors[]`, `Warnings[]`, and `SkippedLineCount` capture parseable events, exception-causing failures, kernel rate-limit suppressed callbacks, and lines that lacked basic firewall fields (SRC/DST/PROTO); a summary warning is emitted when lines are skipped |
| **Immutable data** | `UnifiedEvent` uses `init`-only setters and `IReadOnlyDictionary` |
| **Input sanitization** | Error messages contain sanitized 200-char snippets with control chars replaced |

---

## Implementation Evidence

- [LogNormalizer.cs](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs) — orchestrator with size guard and format detection
- [LinuxIptablesParser.cs](../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs) — iptables field extraction
- [LinuxNftablesParser.cs](../../../../VulcansTrace.Linux.Core/LinuxNftablesParser.cs) — nftables field extraction
- [UnifiedEvent.cs](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) — validated immutable event model
- [LogNormalizerTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LogNormalizerTests.cs) — format detection tests
- [LinuxIptablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxIptablesParserTests.cs) — iptables parsing tests
- [LinuxNftablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxNftablesParserTests.cs) — nftables parsing tests
- [UnifiedEventTests.cs](../../../../VulcansTrace.Linux.Tests/Core/UnifiedEventTests.cs) — domain model validation tests

---

> **Elevator Pitch:** Log normalization is the foundation of every detection in VulcansTrace. It turns unstructured Linux kernel firewall text into validated, immutable events — with fail-soft error handling that preserves maximum evidence and input guards that prevent resource exhaustion. Without it, no detector can trust its input.

---

## Security Takeaways

1. Every event is validated at construction — invalid IPs and out-of-range ports are caught before they reach any detector
2. The 100M character input cap prevents a single malformed or maliciously large file from exhausting memory
3. Fail-soft parsing ensures that one corrupted line cannot suppress the rest of the log, preserving forensic completeness
4. Original log lines are retained in `RawLine`, supporting chain-of-custody and manual verification
5. Error messages are sanitized to prevent log injection when displayed in downstream tools
