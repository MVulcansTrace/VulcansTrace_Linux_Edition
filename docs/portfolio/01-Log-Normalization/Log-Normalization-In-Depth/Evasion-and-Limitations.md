## Known Limitations

| Limitation | Impact | Severity |
|---|---|---|
| Unknown lines in mixed-format logs are skipped | Non-firewall lines interleaved with iptables/nftables data are not parsed into events | Low |
| iptables year inference is approximate | Events near year boundaries may be assigned the wrong year | Low |
| Action derivation depends on naming conventions | Custom log prefixes without ACCEPT/DROP/REJECT produce UNKNOWN | Low |
| No support for non-firewall Linux logs | syslog, journalctl, and application logs are not parsed | Low |
| No streaming/incremental parsing | Entire log must fit in memory (up to 100M chars) | Medium |
| Regex-only parsing has no grammar validation | Malformed lines with valid-looking fields may produce incorrect events | Low |
| No deduplication during parsing | Identical log lines produce duplicate events | Low |
| UDP/ICMP/ICMPv6 parsing loses protocol-specific fields | ICMP type/code not extracted; UDP length not extracted separately; protocol-specific sub-fields (e.g., ICMPv6 MTU, SPI for IPsec) extracted to LinuxSpecific but not typed | Low |

---

### Unknown Lines in Mixed-Format Log Files

`LogNormalizer.Normalize()` gathers all detected formats before parsing. If a file contains both iptables and nftables lines, `NormalizeMixedFormats` routes each line to the matching parser and emits a warning that mixed formats were detected. Lines that do not match either firewall format are tracked in `SkippedLineCount`; kernel rate-limit suppressed-callback lines are tracked separately in `Warnings[]`.

**Mitigation:** Review `SkippedLineCount` and warnings after analyzing migration-period logs. Non-firewall syslog or application lines should be filtered out before analysis if they are expected noise.

**Source:** [LogNormalizer.cs:75-82](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs), [LogNormalizer.cs:123-168](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs), [LogNormalizer.cs:170-212](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs)

---

### iptables Year Inference

iptables kernel log timestamps omit the year (`MMM dd HH:mm:ss`). The parser injects `DateTime.Now.Year` and adjusts by ±1 year if the result is more than 180 days in the future or past. This handles the common December-to-January boundary but is not perfectly accurate for logs that are more than one year old.

**Mitigation:** Logs older than one year should have their timestamps corrected manually or through a pre-processing step. The 180-day threshold covers the most common operational scenario.

**Source:** [LinuxIptablesParser.cs:170-201](../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs)

---

### Action Derivation Ambiguity

iptables does not include an explicit action field. The parser inspects the log prefix (text before the first key=value pair) for ACCEPT/DROP/REJECT tokens. If the administrator uses a custom log prefix that does not contain one of these tokens (e.g., `LOGGING:` or `[FW]`), the action defaults to `UNKNOWN`. Similarly, nftables chains with neutral names (e.g., `FORWARD`, `INPUT`) produce `UNKNOWN` because no action token is present.

**Mitigation:** Downstream detectors should treat `UNKNOWN` actions conservatively — assume neither blocked nor allowed. Administrators should include action tokens in their log prefix naming convention.

**Source:** [LinuxIptablesParser.cs:143-168](../../../../VulcansTrace.Linux.Core/LinuxIptablesParser.cs), [LinuxNftablesParser.cs:175-199](../../../../VulcansTrace.Linux.Core/LinuxNftablesParser.cs)

---

### No Streaming/Incremental Parsing

`LogNormalizer.Normalize()` accepts a single `string` argument. The entire log text must be loaded into memory before parsing begins. For the 100M character cap, this requires approximately 200 MB of heap space (UTF-16 encoding). Very large log files from long-running servers may approach this limit.

**Mitigation:** The 100M cap prevents memory exhaustion. Files exceeding this size should be split before analysis. A future streaming API could process files line-by-line with bounded memory.

**Source:** [LogNormalizer.cs:51-61](../../../../VulcansTrace.Linux.Core/LogNormalizer.cs)

---

### Regex-Only Parsing

The parsers rely entirely on regex matching without a formal grammar or state machine. A line that contains valid-looking but semantically incorrect key=value pairs (e.g., `SRC=999.999.999.999`) would pass the regex but fail the strict IPv4 validation in `UnifiedEvent.ValidateIp` before `IPAddress.TryParse()` is reached. However, more subtle semantic errors (e.g., TTL=0, LEN=0) are not validated.

**Mitigation:** `UnifiedEvent` validates IPs and ports. Downstream detectors should perform additional validation on metadata fields (TTL, TOS, Length) if they depend on semantic correctness.

**Source:** [UnifiedEvent.cs:144-173](../../../../VulcansTrace.Linux.Core/UnifiedEvent.cs)

---

### No Deduplication

Identical log lines produce identical `UnifiedEvent` instances. Kernel log buffering or log forwarding misconfigurations can produce duplicate lines. The parser does not deduplicate.

**Mitigation:** Downstream detectors can use `ConnectionKey` to identify duplicate events. A deduplication pass could be added between normalization and detection.

---

## Improvement Roadmap

| Enhancement | Description | Priority |
|---|---|---|
| Streaming API | Process log files line-by-line with bounded memory | Medium |
| ICMP type/code extraction | Parse ICMP-specific fields for protocol coverage | Low |
| Semantic metadata validation | Validate TTL > 0, LEN > 0, reasonable Window values | Low |
| Deduplication pass | Collapse identical events after parsing | Low |
| Configurable action mapping | Allow users to define custom prefix-to-action rules | Low |
| Multi-year log support | Allow specifying a reference year for old logs | Low |

---

## Security Takeaways

1. Mixed-format firewall logs are routed per line, but unknown interleaved lines are still skipped and should be reviewed through `SkippedLineCount`
2. Year inference errors could cause time-based detectors (beaconing, flood) to misfire on year-boundary logs
3. UNKNOWN actions are the safe default — detectors should treat them as ambiguous rather than assuming allowed or blocked
4. The 100M memory cap is a deliberate tradeoff: it prevents resource exhaustion but requires log splitting for very large files
5. Semantic validation of metadata fields (TTL, TOS, Length) is deferred to downstream consumers, which should validate when these fields affect detection logic
