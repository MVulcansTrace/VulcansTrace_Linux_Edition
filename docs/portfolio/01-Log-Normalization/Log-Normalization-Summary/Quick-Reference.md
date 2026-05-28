## Algorithm Stages

1. **Size Guard** — reject inputs exceeding 100,000,000 characters
2. **Format Detection** — scan lines for nftables markers or `PROTO=` + `SRC=` + `DST=` for iptables
3. **Line Splitting** — split on `\r\n` and `\n` with `StringSplitOptions.RemoveEmptyEntries`
4. **Regex Extraction** — apply ~30 compiled regexes per line to extract SRC, DST, SPT, DPT, PROTO, IN, OUT, MAC, LEN, TOS, TTL, ID, WINDOW, Flags, HOPLIMIT, TC, FLOWLBL, PREC, RES, URGP, DF, UID, GID, MARK, PHYSIN, PHYSOUT, VPROTO, VID, SPI, FRAG, MTU, and more
5. **Minimum Field Check** — lines without both SRC/DST and PROTO return `null` (counted in `SkippedLineCount`, summary warning emitted); kernel rate-limit suppressed-callback lines are tracked as warnings
6. **Action Derivation** — inspect log prefix (iptables) or chain name (nftables) for ACCEPT/DROP/REJECT; default to UNKNOWN
7. **Timestamp Parsing** — iptables: `MMM dd HH:mm:ss` with year inference; nftables: ISO 8601 with offset support
8. **Event Construction** — build `UnifiedEvent` with IP validation, port range validation, and `LinuxSpecific` dictionary
9. **Error Collection** — `FormatException`/`ArgumentException` caught per line, sanitized snippet appended to error list
10. **Result Assembly** — return `ParseResult` with `Events[]`, `Errors[]`, `Warnings[]`, `TotalLines`, `ParsedCount`, `ErrorCount`, `WarningCount`, `SkippedLineCount`

---

## Configuration Parameters

| Parameter | Value | Source |
|---|---|---|
| Max input size | 100,000,000 chars | `LogNormalizer.MaxLogSizeChars` |
| Error snippet length | 200 chars | `FirewallLogRegex.ErrorSnippetMaxLength` |
| Max valid port | 65535 | `UnifiedEvent.MaxPort` / parser constants |
| Future timestamp threshold | ±180 days | `LinuxIptablesParser.FutureTimestampThresholdDays` |
| Default action | `"UNKNOWN"` | Both parsers |
| IPv6 support | Yes | Regex `[0-9a-fA-F:.]+` |

---

## Downstream Pipeline

```
Raw Log Text
     │
     ▼
┌──────────────┐
│ LogNormalizer│  Size guard + format detection
│  │
└──────┬───────┘
       │
        ├── Iptables ──► LinuxIptablesParser
       │                      │
       │                      ▼
       │               UnifiedEvent (LogFormat.Iptables)
       │
        └── Nftables ──► LinuxNftablesParser
                              │
                              ▼
                       UnifiedEvent (LogFormat.Nftables)
                              │
                              ▼
                       ParseResult
                    ┌─────────────────────┐
                    │ Events[]            │
                    │ Errors[]            │
                    │ TotalLines          │
                    │ ParsedCount         │
                    │ ErrorCount          │
                    └─────────────────────┘
                              │
                              ▼
                    Downstream Detectors
              (Port Scan, Beaconing, Lateral, etc.)
```

---

## Output Structure

### UnifiedEvent Fields

| Field | Type | Validation | Description |
|---|---|---|---|
| `Timestamp` | `DateTime` | Required, non-default | Firewall event time |
| `SourceIP` | `string` | Required, valid IP (v4/v6) | Source address |
| `DestinationIP` | `string` | Required, valid IP (v4/v6) | Destination address |
| `SourcePort` | `int` | 0–65535 | Source port (0 if N/A) |
| `DestinationPort` | `int` | 0–65535 | Destination port (0 if N/A) |
| `Protocol` | `string` | Required, non-empty | Upper-cased (any PROTO= value) |
| `Action` | `string` | Non-empty | ACCEPT/DROP/REJECT/UNKNOWN |
| `RawLine` | `string?` | None | Original log line |
| `LogFormat` | `LogFormat` | Required, non-Unknown | Iptables or Nftables |
| `LinuxSpecific` | `IReadOnlyDictionary<string,string>` | Non-null | Format-specific metadata |
| `ConnectionKey` | `string` | Computed | `{src}:{sport}-{dst}:{dport}-{proto}` |

### ParseResult Fields

| Field | Type | Description |
|---|---|---|
| `Events` | `UnifiedEvent[]` | Successfully parsed events |
| `Errors` | `string[]` | Sanitized error messages |
| `TotalLines` | `int` | Non-empty lines inspected |
| `ParsedCount` | `int` | `Events.Length` |
| `ErrorCount` | `int` | `Errors.Length` |
| `Warnings` | `string[]` | Kernel rate-limit and other non-error warnings |
| `WarningCount` | `int` | `Warnings.Length` |
| `SkippedLineCount` | `int` | Lines skipped (missing required fields) |

---

## Complexity

| Dimension | Analysis |
|---|---|
| **Time** | O(N × R) where N = number of lines and R = number of regex fields applied per line |
| **Space** | O(N) for the events list plus O(E) for error messages, where E = number of malformed lines |

---

## Supported Formats

| Format | Detection Signal | Timestamp Format | Action Source |
|---|---|---|---|
| iptables | `PROTO=` + `SRC=` + `DST=` | `MMM dd HH:mm:ss` (year inferred) | Log prefix token |
| nftables | `nf_tables:` with ISO 8601 timestamp prefix | ISO 8601 with optional offset | Chain name token |

---

## Evasion Summary

| Evasion Vector | Current Handling | Risk Level |
|---|---|---|
| Malformed log lines (missing SRC/DST/PROTO) | Tracked in `SkippedLineCount`, summary warning emitted; suppressed-callback lines tracked separately in warnings | Low |
| Invalid port numbers (>65535) | `FormatException` caught, error logged | Low |
| Invalid timestamps | `FormatException` caught, error logged | Low |
| Mixed-format log files | Line-by-line routing to matching parser | Medium |
| Missing year in iptables logs | Year inferred with future correction (±180 days) | Low |
| Deliberate field injection in log prefix | Regex anchors on known key=value boundaries | Low |
| Very large inputs (>100M chars) | Hard cap with empty result and error | Low |

---

## File References

| File | Role |
|---|---|
| [LogNormalizer.cs](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs) | Orchestrator and format detector |
| [LinuxIptablesParser.cs](../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs) | iptables regex parser |
| [LinuxNftablesParser.cs](../../../../VulcansTrace.Linux.Core/LinuxNftablesParser.cs) | nftables regex parser |
| [UnifiedEvent.cs](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs) | Immutable validated event model |
| [LogNormalizerTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LogNormalizerTests.cs) | Format detection and normalization tests |
| [LinuxIptablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxIptablesParserTests.cs) | iptables parsing test coverage |
| [LinuxNftablesParserTests.cs](../../../../VulcansTrace.Linux.Tests/Core/LinuxNftablesParserTests.cs) | nftables parsing test coverage |
| [UnifiedEventTests.cs](../../../../VulcansTrace.Linux.Tests/Core/UnifiedEventTests.cs) | Domain model and ConnectionKey tests |

---

## Security Takeaways

1. Input size is hard-capped at 100M characters to prevent denial-of-service through memory exhaustion
2. Every `UnifiedEvent` is validated at construction — invalid IPs, out-of-range ports, and missing required fields throw immediately
3. Fail-soft parsing ensures that one corrupted or maliciously crafted line cannot suppress parsing of the remaining log
4. Error messages contain sanitized line snippets (200 char max, control characters replaced) to prevent log injection in downstream displays
5. The `RawLine` field preserves the original log line for forensic review, supporting chain-of-custody requirements
