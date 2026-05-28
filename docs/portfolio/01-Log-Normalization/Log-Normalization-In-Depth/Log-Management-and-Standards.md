## Capability Mapping

| Capability | Implementation | Source |
|---|---|---|
| Log collection and ingestion | `LogNormalizer.Normalize()` accepts raw text, auto-detects format | [LogNormalizer.cs](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs) |
| Format identification | `Normalize()` distinguishes iptables and nftables by line markers and routes mixed-format files per line | [LogNormalizer.cs:75-82](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs), [LogNormalizer.cs:123-168](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs), [LogNormalizer.cs:170-212](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs) |
| Field extraction | 34 iptables and 36 nftables per-format regex patterns extract IPs, ports, protocol, interfaces, MAC, flags, TTL, TOS, HOPLIMIT, TC, FLOWLBL, PREC, RES, URGP, DF, UID, GID, MARK, PHYSIN, PHYSOUT, VPROTO, VID, SPI, FRAG, MTU | [LinuxIptablesParser.cs](../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs), [LinuxNftablesParser.cs](../../../../VulcansTrace.Linux.Core/LinuxNftablesParser.cs) |
| Event validation | `UnifiedEvent` validates IPs (strict IPv4 regex plus `IPAddress.TryParse`), ports (0-65535), required fields | [UnifiedEvent.cs:144-172](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |
| Error handling and logging | Fail-soft per-line parsing with `ILogSink` abstraction | [LinuxIptablesParser.cs:57-74](../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs) |
| Input size enforcement | 100M character hard cap with error result | [LogNormalizer.cs:51-61](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs) |
| Evidence preservation | `RawLine` field retains original log text on every event | [UnifiedEvent.cs:88-89](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |
| Immutable output | `init`-only setters, `IReadOnlyDictionary` metadata, defensive copy | [UnifiedEvent.cs:114-126](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |

---

## NIST SP 800-92 Alignment

> **Note:** These tables map implementation features to NIST SP 800-92 control categories as architectural alignment, not as a compliance certification.

| NIST SP 800-92 Control | Implementation | Evidence |
|---|---|---|
| **Log Generation** — ensure logs contain sufficient detail | Parser extracts 35+ fields per event including IPs, ports, protocol, interfaces, MAC, flags, TTL, TOS, HOPLIMIT, TC, FLOWLBL, PREC, RES, URGP, DF, UID, GID, MARK, PHYSIN, PHYSOUT, VPROTO, VID, SPI, FRAG, MTU | [FirewallLogRegex.cs:280-336](../../../../VulcansTrace.Linux.Core/Parsing/FirewallLogRegex.cs) |
| **Log Collection** — centralize logs from multiple sources | `LogNormalizer` provides a single entry point for both iptables and nftables formats | [LogNormalizer.cs:51-107](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs) |
| **Log Parsing and Normalization** — convert to common format | `UnifiedEvent` provides a consistent schema regardless of source format | [UnifiedEvent.cs:12-174](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |
| **Log Storage and Retention** — protect log integrity | `RawLine` preserves original text; immutable events prevent post-parse modification | [UnifiedEvent.cs:88-89](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |
| **Log Analysis** — support detection and investigation | `ParseResult` provides structured events and error reports for downstream analysis | [UnifiedEvent.cs:179-205](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |
| **Log Disposal** — manage log lifecycle | Input is processed in-memory; no persistent storage of raw logs | [LogNormalizer.cs](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs) |

---

## Federal Rules of Evidence (FRE) Mapping

> **Note:** These tables describe how implementation features support forensic principles. They represent architectural alignment, not legal advice or a determination of evidentiary admissibility.

| FRE Principle | Implementation | Evidence |
|---|---|---|
| **Rule 901 — Authentication** | `RawLine` retains the verbatim original log line on every parsed event, enabling comparison against the source log file | [UnifiedEvent.cs:88-89](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |
| **Rule 1001 — Original Writing** | `RawLine` constitutes a duplicate of the original log entry; the parsed `UnifiedEvent` is a derived analytical representation | [UnifiedEvent.cs:88-89](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |
| **Rule 1002 — Best Evidence** | Original log text is preserved unchanged; parsing does not modify or truncate the source line | [LinuxIptablesParser.cs:117](../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs) |
| **Rule 1003 — Admissibility of Duplicates** | `ParseResult` includes structured events whose `RawLine` fields retain original raw lines, supporting duplicate admissibility | [UnifiedEvent.cs:88-89](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs), [UnifiedEvent.cs:179-203](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |
| **Chain of Custody** | Immutable `UnifiedEvent` objects with `init`-only setters prevent post-construction modification of parsed data | [UnifiedEvent.cs:28-103](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) |

---

## Data Flow and Evidence Integrity

```
Original Log File (iptables / nftables)
         │
         │  Read into memory (max 100M chars)
         ▼
   ┌──────────────────────────┐
   │      LogNormalizer       │
   │  ┌────────────────────┐  │
   │  │   Size Guard       │  │  Enforces 100M char limit
   │  └────────┬───────────┘  │
   │           │              │
   │  ┌────────▼───────────┐  │
   │  │  Format Detection  │  │  iptables vs nftables
   │  └────────┬───────────┘  │
   │           │              │
   │  ┌────────▼───────────┐  │
   │  │  Parser Dispatch   │  │  Delegates to correct parser
   │  └────────┬───────────┘  │
   └───────────┼──────────────┘
               │
    ┌──────────▼──────────┐
    │  Per-Line Parsing   │
    │  ┌───────────────┐  │
    │  │ Regex Extract │  │  Extract fields, derive action
    │  └───────┬───────┘  │
    │          │          │
    │  ┌───────▼───────┐  │
    │  │ Validate &    │  │  IP validation, port validation
    │  │ Construct     │  │  Build UnifiedEvent (immutable)
    │  └───────┬───────┘  │
    │          │          │
    │  ┌───────▼───────┐  │
    │  │ Preserve      │  │  RawLine = original log line
    │  │ Evidence      │  │  LinuxSpecific = full metadata
    │  └───────────────┘  │
    └──────────┬──────────┘
               │
               ▼
        ParseResult
   ┌───────────────────────┐
   │ Events[] — validated  │  Immutable, typed events
   │ Errors[] — sanitized  │  200-char snippets, control chars replaced
   │ TotalLines — count    │  Full accounting
   │ RawLine per event     │  Original evidence preserved
   └───────────────────────┘
               │
               ▼
     Downstream Detectors & Evidence Packaging
```

---

## Security Takeaways

1. The normalization subsystem aligns with NIST SP 800-92 guidance for log generation, collection, parsing, normalization, and analysis
2. `RawLine` preservation on every event supports FRE authentication and best evidence requirements by retaining the verbatim original log entry
3. Immutable event construction (init-only setters, IReadOnlyDictionary) supports chain-of-custody by preventing post-parse modification
4. The `ILogSink` abstraction decouples logging from parsing, enabling custom logging implementations (e.g., SIEM integration) through a pluggable interface
5. Error sanitization (200-char limit, control character replacement) reduces log injection risk when error messages are displayed in downstream tools (note: IP addresses may still appear in error snippets)
