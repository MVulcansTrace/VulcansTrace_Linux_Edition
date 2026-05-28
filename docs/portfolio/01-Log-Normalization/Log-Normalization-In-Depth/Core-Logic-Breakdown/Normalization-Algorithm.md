## The Security Problem

Linux firewall logs arrive as unstructured kernel text with no schema, no field ordering guarantees, and no validation. An analyst receiving 500,000 lines of mixed iptables and nftables output cannot manually extract source IPs, destination ports, and TCP flags — and neither can downstream detectors. The normalization pipeline must transform this raw text into a consistent, validated event stream without losing information or introducing false data.

---

## Implementation Overview

```
Raw Log Text (up to 100M chars)
         │
         ▼
   ┌─────────────────┐
   │   Stage A       │  Size Guard
   │ MaxLogSizeChars │  Reject inputs > 100M characters
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │   Stage B       │  Format Detection
   │ DetectFormats() │  Scan lines for nftables and iptables markers
   └────────┬────────┘
            │
       ┌────┴────┐
       │         │
       ▼         ▼
  ┌─────────┐ ┌──────────┐
  │ Stage C │ │ Stage C  │  Regex Extraction
   │ Iptables│ │ Nftables │  Apply ~30 compiled regexes per line
   │ Parser  │ │ Parser   │  Extract: SRC, DST, SPT, DPT, PROTO,
   └────┬────┘ └────┬─────┘  IN, OUT, MAC, LEN, TOS, TTL, ID, Flags,
        │           │         HOPLIMIT, TC, FLOWLBL, PREC, RES, URGP,
        │           │         DF, UID, GID, MARK, PHYSIN, PHYSOUT,
        │           │         VPROTO, VID, SPI, FRAG, MTU
       │           │
       ▼           ▼
   ┌─────────────────┐
   │   Stage D       │  Event Construction
   │  UnifiedEvent   │  Validate IPs, ports, required fields
   │  (immutable)    │  Build LinuxSpecific dictionary
   └────────┬────────┘
            │
            ▼
   ┌─────────────────┐
   │   Stage E       │  Result Assembly
    │  ParseResult    │  Events[] + Errors[] + Warnings[] + TotalLines
    │                 │  ParsedCount + ErrorCount + WarningCount
   └─────────────────┘
            │
            ▼
     Downstream Detectors
```

---

## Stage A: Size Guard

`LogNormalizer.Normalize()` checks `logText.Length` against `MaxLogSizeChars` (100,000,000). If exceeded, it returns an empty `ParseResult` with an error message and logs at `LogLevel.Error`. This prevents binary files or corrupted inputs from consuming unbounded memory.

**Source:** [LogNormalizer.cs:51-61](../../../../../VulcansTrace.Linux.Core/LogNormalizer.cs)

---

## Stage B: Format Detection

`Normalize()` splits the input into non-empty lines and gathers the distinct log formats found across the file:

- If any line contains `nf_tables:` → `LogFormat.Nftables`
- If any line contains `PROTO=` AND `SRC=` AND `DST=` → `LogFormat.Iptables`
- Otherwise → `LogFormat.Unknown`

If exactly one format is found, the whole file is delegated to that parser. If both iptables and nftables lines are present, `NormalizeMixedFormats` routes each line to the parser matching that line and returns a warning that mixed formats were detected. Unknown lines in a mixed file are counted as skipped.

**Source:** [LogNormalizer.cs:75-82](../../../../../VulcansTrace.Linux.Core/LogNormalizer.cs), [LogNormalizer.cs:123-168](../../../../../VulcansTrace.Linux.Core/LogNormalizer.cs), [LogNormalizer.cs:170-212](../../../../../VulcansTrace.Linux.Core/LogNormalizer.cs)

---

## Stage C: Regex Extraction

Each parser applies a battery of compiled regexes to every line:

**iptables (34 regex patterns):** `SourceIpRegex`, `DestinationIpRegex`, `SourcePortRegex`, `DestinationPortRegex`, `ProtocolRegex`, `InInterfaceRegex`, `OutInterfaceRegex`, `MacRegex`, `FlagRegex`, `WindowRegex`, `LengthRegex`, `TosRegex`, `TtlRegex`, `IdRegex`, `HoplimitRegex`, `TcRegex`, `FlowlblRegex`, `PrecRegex`, `ResRegex`, `UrgpRegex`, `UidRegex`, `GidRegex`, `MarkRegex`, `PhysInRegex`, `PhysOutRegex`, `VprotoRegex`, `VidRegex`, `SpiRegex`, `FragRegex`, `MtuRegex`, `DfRegex`, `SuppressedRegex`, `PrefixFieldRegex`, `TimestampRegex`

**nftables (36 regex patterns):** `SourceIpRegex`, `DestinationIpRegex`, `SourcePortRegex`, `DestinationPortRegex`, `ProtocolRegex`, `InInterfaceRegex`, `OutInterfaceRegex`, `MacRegex`, `FlagRegex`, `WindowRegex`, `LengthRegex`, `TosRegex`, `TtlRegex`, `IdRegex`, `HoplimitRegex`, `TcRegex`, `FlowlblRegex`, `PrecRegex`, `ResRegex`, `UrgpRegex`, `UidRegex`, `GidRegex`, `MarkRegex`, `PhysInRegex`, `PhysOutRegex`, `VprotoRegex`, `VidRegex`, `SpiRegex`, `FragRegex`, `MtuRegex`, `DfRegex`, `SuppressedRegex`, `PrefixFieldRegex`, `ChainRegex`, `NftablesTimestampRegex`, `TimestampOffsetRegex`

Lines without both SRC/DST and PROTO return `null` (counted in `SkippedLineCount` with a summary warning emitted). Kernel rate-limit suppressed-callback lines (e.g., `net_ratelimit: 42 callbacks suppressed`) are detected before the SRC/DST/PROTO check and tracked in `Warnings[]`. Lines that match SRC/DST/PROTO but have **invalid** port values or **missing** timestamps throw `FormatException`, which is caught and added to `Errors[]`.

**Port parsing:** `SourcePortRegex` and `DestinationPortRegex` are matched independently. A present but malformed port value (negative, non-numeric, or overflow) is rejected with a parse error rather than silently defaulting to 0. When a port field is genuinely absent (e.g., ICMP without ports), it defaults to 0.

**Source:** [LinuxIptablesParser.cs:94-121](../../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs), [LinuxNftablesParser.cs:102-153](../../../../../VulcansTrace.Linux.Core/LinuxNftablesParser.cs)

---

## Stage D: Event Construction

Each successfully parsed line constructs a `UnifiedEvent`:

- **IP validation:** A strict IPv4 regex validates dotted-decimal addresses before falling back to `IPAddress.TryParse()` for IPv6 and edge-case formats. This prevents `IPAddress.TryParse` from accepting non-standard representations such as overflow octets (`999.999.999.999`) or short forms (`1.2.3`).
- **Port validation:** range check 0–65535
- **Protocol:** uppercased (any PROTO= value — TCP, UDP, ICMP, ICMPv6, UDPLITE, numeric, etc.)
- **Action:** derived from log prefix (iptables) or chain name (nftables); defaults to `"UNKNOWN"`
- **LinuxSpecific:** dictionary populated with format-specific keys:
  - *iptables:* InterfaceIn, InterfaceOut, MAC, Flags, Window, Length, TOS, TTL, ID, HOPLIMIT, TC, FLOWLBL, PREC, RES, URGP, DF, UID, GID, MARK, PHYSIN, PHYSOUT, VPROTO, VID, SPI, FRAG, MTU
  - *nftables:* Chain, InterfaceIn, InterfaceOut, MAC, Flags, Window, Length, TOS, TTL, ID, HOPLIMIT, TC, FLOWLBL, PREC, RES, URGP, DF, UID, GID, MARK, PHYSIN, PHYSOUT, VPROTO, VID, SPI, FRAG, MTU
- **ConnectionKey:** computed as `{src}:{sport}-{dst}:{dport}-{proto}`

All setters are `init`-only, making the event immutable after construction.

**Source:** [UnifiedEvent.cs:12-172](../../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs)

---

## Stage E: Result Assembly

The parser returns a `ParseResult`:

| Field | Type | Description |
|---|---|---|
| `Events` | `UnifiedEvent[]` | All successfully constructed events |
| `Errors` | `string[]` | Sanitized error messages for failed lines |
| `Warnings` | `string[]` | Kernel rate-limit suppressed-callback and other non-error warnings |
| `TotalLines` | `int` | Number of non-empty lines in the input |
| `ParsedCount` | `int` | `Events.Length` (computed) |
| `ErrorCount` | `int` | `Errors.Length` (computed) |
| `WarningCount` | `int` | `Warnings.Length` (computed) |

**Source:** [UnifiedEvent.cs:179-203](../../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs)

---

## Complexity And Behavior

| Dimension | Value |
|---|---|
| Time complexity | O(N × R) where N = lines, R = regexes per line |
| Space complexity | O(N) for events + O(E) for errors |
| Regex compilation | Once at class load (static fields) |
| Error handling | Per-line try/catch, fail-soft |
| IPv6 support | Yes (regex pattern `[0-9a-fA-F:.]+`) |

---

## Implementation Evidence

- [LogNormalizer.cs](../../../../../VulcansTrace.Linux.Core/LogNormalizer.cs) — Stages A and B
- [LinuxIptablesParser.cs](../../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs) — Stages C, D, E (iptables path)
- [LinuxNftablesParser.cs](../../../../../VulcansTrace.Linux.Core/LinuxNftablesParser.cs) — Stages C, D, E (nftables path)
- [UnifiedEvent.cs](../../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) — Stage D validation model
- [LogNormalizerTests.cs](../../../../../VulcansTrace.Linux.Tests/Core/LogNormalizerTests.cs) — format detection verification
- [LinuxIptablesParserTests.cs](../../../../../VulcansTrace.Linux.Tests/Core/LinuxIptablesParserTests.cs) — iptables extraction verification
- [LinuxNftablesParserTests.cs](../../../../../VulcansTrace.Linux.Tests/Core/LinuxNftablesParserTests.cs) — nftables extraction verification

---

## Security Takeaways

1. The size guard prevents resource exhaustion attacks from oversized inputs
2. Per-line error handling ensures a single malformed line cannot abort parsing of the entire log
3. Immutable event construction prevents downstream mutation of parsed data
4. IP validation at construction catches address injection before detectors consume the data
5. Sanitized error snippets (max 200 chars + `...` truncation indicator, control chars neutralized, whitespace control chars replaced with spaces) prevent log injection through error messages
