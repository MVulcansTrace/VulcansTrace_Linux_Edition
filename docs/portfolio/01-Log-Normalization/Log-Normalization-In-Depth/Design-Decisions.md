> Every design choice in the log normalization subsystem was made to maximize evidence preservation, prevent silent data loss, and produce validated events that downstream detectors can trust without defensive re-checking.

---

## Decision 1: Fail-Soft Parsing Over Fail-Fast

**Decision:** Malformed lines that throw parse exceptions are logged and skipped; lines that don't match the minimum field signature (SRC, DST, PROTO) are tracked in `SkippedLineCount` with a summary warning. Kernel rate-limit suppressed-callback lines are also tracked as warnings. In neither case does parsing halt.

**Rationale:** Production firewall logs are noisy. A single corrupt line — caused by log rotation artifacts, kernel buffer overflows, or deliberate evasion — should not prevent parsing of the remaining 499,999 lines. The parser catches `FormatException` and `ArgumentException` per line, appends a sanitized error, and continues.

**Security Rationale:** In incident response, losing even a single valid event could mean missing the one connection that reveals lateral movement. Fail-soft maximizes event yield.

**Business Value:** Analysts receive the maximum possible number of events from every log file, reducing the need for manual re-runs or format-specific preprocessing.

---

## Decision 2: Compiled Regex With Static Fields

**Decision:** Common parsing regexes are centralized in `FirewallLogRegex`, while parser-specific timestamp and chain regexes live in the iptables and nftables parsers. These regex fields are static and compiled with `RegexOptions.Compiled`.

**Rationale:** The parsers process thousands to hundreds of thousands of lines. Compiled regexes trade a one-time JIT cost for faster per-match execution, which is the dominant cost in large log files.

**Security Rationale:** Deterministic, predictable parsing performance prevents timing-based attacks and ensures the system can process large incident logs within acceptable time windows.

**Business Value:** Faster analysis turnaround on large log files directly improves incident response speed.

---

## Decision 3: Action Derivation From Context

**Decision:** Firewall action (ACCEPT/DROP/REJECT) is derived from the log prefix in iptables and the chain name in nftables, not from an explicit field. If no action token is found, the action is set to `"UNKNOWN"`.

**Rationale:** iptables logs do not natively include an action field — the action is typically encoded in the log prefix (e.g., `IPTABLES-DROP` or `[ACCEPT]`). Nftables exposes the chain name, which may include the action (e.g., `INPUT_DROP`). Attempting to parse a non-existent field would produce false negatives.

**Security Rationale:** Returning `"UNKNOWN"` rather than guessing ensures downstream detectors do not make incorrect assumptions about whether traffic was allowed or blocked.

**Business Value:** Analysts can filter on action with confidence: DROP and REJECT events are parsed as blocked based on the log prefix or chain name; UNKNOWN events are flagged for manual review.

---

## Decision 4: LinuxSpecific Dictionary Over Typed Properties

**Decision:** Format-specific metadata (e.g., MAC, TTL, TOS, Window, Chain, Flags) is stored in `IReadOnlyDictionary<string, string>` rather than individual typed properties on `UnifiedEvent`.

**Rationale:** Both parsers share most metadata fields (MAC, WINDOW, TTL, TOS, HOPLIMIT, TC, FLOWLBL, etc.); nftables additionally includes `Chain`. Adding typed properties for each would bloat the schema and require changes every time a new field is discovered in the wild.

**Security Rationale:** The dictionary is `IReadOnlyDictionary` — immutable after construction. Downstream code can read metadata but cannot modify or remove it.

**Business Value:** New metadata fields can be extracted and consumed without schema migrations, keeping the event model stable across releases.

---

## Decision 5: 100M Character Input Cap

**Decision:** `LogNormalizer.Normalize()` rejects any input exceeding 100,000,000 characters.

**Rationale:** The input is a single in-memory string. A 100M character string consumes approximately 200 MB of heap space (UTF-16). Without a cap, a misconfigured log source or a deliberately large file could exhaust memory.

**Security Rationale:** Prevents denial-of-service through resource exhaustion. This is the first line of defense before any parsing begins.

**Business Value:** Predictable memory usage ensures the application remains responsive even when processing logs from shared storage or network mounts.

---

## Decision 6: Timestamp Year Inference With Future/Past Correction

**Decision:** iptables timestamps omit the year. The parser injects `DateTime.Now.Year` and adjusts by ±1 year if the resulting timestamp is more than 180 days in the future or past.

**Rationale:** iptables kernel log format (`MMM dd HH:mm:ss`) does not include a year. Simply using the current year works for recent logs but fails for logs from December analyzed in January. The 180-day threshold handles this boundary condition.

**Security Rationale:** Incorrect timestamps would cause time-based detectors (beaconing, flood) to misfire or miss events entirely. The correction ensures temporal ordering is preserved.

**Business Value:** Analysts can process logs from any time of year without manual timestamp adjustment.

---

## Summary

| Decision | Tradeoff | Benefit |
|---|---|---|
| Fail-soft parsing | Slightly more complex error handling | Maximum event yield from noisy logs |
| Compiled regex | Higher startup cost | Faster parsing on large files |
| Context-derived actions | UNKNOWN when prefix is ambiguous | No false action assignments |
| LinuxSpecific dictionary | Untyped metadata values | Extensible without schema changes |
| 100M input cap | Rejects very large files | Prevents memory exhaustion |
| Year inference + correction | Not perfectly accurate for old logs | Handles year boundaries correctly |

---

## Security Takeaways

1. Fail-soft parsing prevents a single corrupted line from suppressing the rest of the log
2. The input size cap prevents denial-of-service through memory exhaustion
3. Immutable events and read-only metadata prevent downstream tampering with parsed data
4. UNKNOWN action values ensure detectors never incorrectly assume traffic was allowed or blocked
5. Year inference with future correction prevents time-based detector misfires on year-boundary logs
