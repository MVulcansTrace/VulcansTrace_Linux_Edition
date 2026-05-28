> **1 page:** the log normalization subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

The log normalization subsystem is the entry point for all analysis in VulcansTrace Linux Edition. It takes raw firewall log text, detects iptables and nftables content, routes mixed-format files line-by-line when both formats are present, and delegates to the appropriate regex-based parser. Each parser extracts source/destination IPs, ports, protocol, interfaces, TCP flags, and other fields into a `UnifiedEvent` — an immutable, validated domain object. Malformed lines are captured as errors but never halt the parse, ensuring maximum event yield from noisy or partially corrupt log files. The subsystem caps input at 100 million characters to prevent resource exhaustion.

---

## Key Metrics

| Metric | Value |
|---|---|
| Core source files | 4 (LogNormalizer, LinuxIptablesParser, LinuxNftablesParser, UnifiedEvent) |
| Total lines of implementation | 862 |
| Per-format regex coverage | 34 iptables / 36 nftables patterns (33 shared + parser-specific fields) |
| Test files | 4 |
| Total test lines | 2,412 |
| Maximum input size | 100,000,000 characters |
| Supported log formats | iptables, nftables |
| Event fields extracted per line | Up to 35+ (IPs, ports, protocol, action, interfaces, MAC, flags, TTL, TOS, ID, Window, Length, HOPLIMIT, TC, FLOWLBL, PREC, RES, URGP, DF, UID, GID, MARK, PHYSIN, PHYSOUT, VPROTO, VID, SPI, FRAG, MTU) |

---

## Why It Matters

- **No analysis is possible without clean structured data** — every detector in the pipeline depends on the normalized `UnifiedEvent` stream
- **Linux firewalls produce unstructured kernel log text** — there is no standardized schema; the parser must reconstruct the event from key=value pairs embedded in freeform lines
- **Mixed-format environments are common** — production servers may migrate from iptables to nftables, producing logs in both formats that must be unified
- **Fail-soft parsing preserves evidence** — a corrupt line should not discard the remaining 99.9% of the log
- **Immutable validated events prevent downstream errors** — invalid IPs or out-of-range ports are caught at construction, not during detection

---

## Key Evidence

- [LogNormalizer.cs](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs) — auto-detection and orchestration
- [LinuxIptablesParser.cs](../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs) — iptables regex parsing
- [LinuxNftablesParser.cs](../../../../VulcansTrace.Linux.Core/LinuxNftablesParser.cs) — nftables regex parsing
- [UnifiedEvent.cs](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) — validated immutable event model
- [LogNormalizerTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LogNormalizerTests.cs) — end-to-end format detection tests
- [LinuxIptablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxIptablesParserTests.cs) — iptables parsing test suite
- [LinuxNftablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxNftablesParserTests.cs) — nftables parsing test suite
- [UnifiedEventTests.cs](../../../../VulcansTrace.Linux.Tests/Core/UnifiedEventTests.cs) — domain model validation tests

---

## Key Design Choices

- **Fail-soft parsing with error collection** — `ParseLine` returns `null` for unrecognizable lines and catches `FormatException`/`ArgumentException` for partially valid lines, logging each error without aborting. This maximizes event yield from noisy production logs.
- **Compiled regex fields** — 33 shared parsing regexes plus parser-specific timestamp/chain regexes are static and compiled, trading startup cost for faster per-line matching on large log files.
- **Action derivation from context, not explicit fields** — iptables logs lack a native action field; the parser inspects the log prefix for ACCEPT/DROP/REJECT tokens. Nftables derives action from the chain name (e.g., `INPUT_DROP` → DROP). Falls back to `UNKNOWN`.
- **`LinuxSpecific` dictionary for extensibility** — format-specific metadata (MAC, flags, TTL, TOS, HOPLIMIT, TC, FLOWLBL, PREC, RES, URGP, DF, UID, GID, MARK, PHYSIN, PHYSOUT, VPROTO, VID, SPI, FRAG, MTU, Window, Chain, and more) is stored in a `IReadOnlyDictionary<string, string>` rather than typed properties, allowing new fields without schema changes.
- **100M character input cap** — prevents runaway memory consumption from accidentally loaded binary files or corrupted inputs, returning an empty result with an error message instead.
- **Timestamp year inference with future/past correction** — iptables logs omit the year. The parser injects `DateTime.Now.Year` and adjusts by ±1 year if the resulting timestamp is more than 180 days in the future or past, handling year-boundary logs correctly.
