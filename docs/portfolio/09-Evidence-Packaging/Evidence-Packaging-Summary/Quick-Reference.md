> **At-a-glance reference** for the evidence packaging subsystem: archive contents, formatter capabilities, integrity chain, and key configuration.

---

## Archive Contents

| File | Formatter | Description |
|---|---|---|
| `findings.csv` | `CsvFormatter` | RFC 4180 CSV with formula injection defense and warnings section |
| `report.html` | `HtmlFormatter` | Self-contained dark-themed HTML report with XSS-safe encoding |
| `summary.md` | `MarkdownFormatter` | GitHub-Flavored Markdown with severity grouping and table escaping |
| `findings.json` | `JsonFormatter` | SIEM-compatible JSON: metadata + findings + errors + warnings |
| `findings.stix.json` | `StixFormatter` | STIX 2.1 bundle with identity, observed-data, notes, IP observables, malware SDO |
| `log.txt` | (passthrough) | Original raw log file content |
| `suppressions.csv` | `CsvFormatter` | Active accepted-risk suppressions, included only when present |
| `manifest.json` | (generated) | Per-file SHA-256 hashes, byte lengths, warnings, and creation timestamp |
| `manifest.hmac` | (generated) | HMAC-SHA256 hex signature of `manifest.json` |

---

## Integrity Chain

```
AnalysisResult + rawLog
        |
        v
   5 formatters + raw-log passthrough render content
        |
        v
   SHA-256 per file  -->  manifest.json
                             |
                             v
                        HMAC-SHA256  -->  manifest.hmac
        |
        v
   ZIP archive (standard entries + optional suppressions.csv)
```

**Verification steps (recipient-side):**

1. Read `manifest.hmac` — the HMAC hex string
2. Read `manifest.json` — recompute HMAC-SHA256 with the shared key
3. Compare — if the HMACs match, the manifest has not been tampered with
4. For each file listed in the manifest, recompute SHA-256 and compare to the stored hash

---

## Formatter Capabilities

| Formatter | Key Security Feature | Output Standard |
|---|---|---|
| `CsvFormatter` | Formula injection defense (prepend `'` to `=+-@`) | RFC 4180 |
| `HtmlFormatter` | `HtmlEncode` on all user content | HTML5 |
| `JsonFormatter` | camelCase naming, null-omission | JSON (SIEM-compatible) |
| `MarkdownFormatter` | Pipe/backtick/bracket escaping, newline-to-`<br>` | GFM |
| `StixFormatter` | IP validation via `IPAddress.TryParse`, deduplication | STIX 2.1 |

---

## JSON Export Schema

```json
{
  "metadata": {
    "toolName": "VulcansTrace Linux Edition",
    "version": "1.0.0",
    "exportTimestamp": "2024-01-15T10:30:00Z",
    "originalLogLines": 5000,
    "parsedEvents": 4872,
    "analysisTimeRange": { "start": "...", "end": "..." }
  },
  "findings": [
    {
      "id": "guid",
      "category": "PortScan",
      "severity": "High",
      "sourceHost": "192.168.1.100",
      "target": "10.0.0.1",
      "timeRangeStart": "...",
      "timeRangeEnd": "...",
      "shortDescription": "...",
      "details": "..."
    }
  ],
  "parseErrors": [],
  "warnings": []
}
```

---

## STIX 2.1 Object Types

| SDO Type | Condition | Purpose |
|---|---|---|
| `identity` | Always | Identifies VulcansTrace as the producing tool |
| `observed-data` | Per finding with valid IPs | Captures source/target IPs with time range |
| `note` | Per `observed-data` | Attaches category, severity, description, and details |
| `ipv4-addr` | Per unique IPv4 address | Reusable IPv4 observable objects, deduplicated |
| `ipv6-addr` | Per unique IPv6 address | Reusable IPv6 observable objects, deduplicated |
| `malware` | When any finding has category `C2Channel` | Flags potential malware C2 activity |

---

## Manifest Schema

```json
{
  "createdUtc": "2024-01-15T10:30:00Z",
  "files": [
    { "file": "findings.csv", "sha256": "abcdef...", "length": 1234 },
    { "file": "findings.json", "sha256": "fedcba...", "length": 5678 },
    { "file": "findings.stix.json", "sha256": "...", "length": 9012 },
    { "file": "log.txt", "sha256": "...", "length": 3456 },
    { "file": "report.html", "sha256": "...", "length": 7890 },
    { "file": "summary.md", "sha256": "...", "length": 2345 }
  ],
  "parseErrors": ["..."],
  "warnings": ["..."],
  "skippedLineCount": 0
}
```

---

## Security Takeaways

- Every file in the archive is individually SHA-256 hashed — file-level tampering is detectable without verifying the HMAC
- The HMAC-SHA256 manifest signature provides cryptographic proof that the entire evidence package was produced by someone holding the signing key
- CSV formula injection defense prevents macro execution when the archive is opened in spreadsheet applications
- HTML output is XSS-safe: all finding content passes through `System.Net.WebUtility.HtmlEncode`
- STIX IP addresses are validated with `IPAddress.TryParse` — invalid IPs are silently skipped rather than producing malformed STIX objects
- ZIP entry timestamps are clamped to the ZIP specification range (1980-01-01 through 2107-12-31), preventing `ArgumentOutOfRangeException` that could corrupt the archive
