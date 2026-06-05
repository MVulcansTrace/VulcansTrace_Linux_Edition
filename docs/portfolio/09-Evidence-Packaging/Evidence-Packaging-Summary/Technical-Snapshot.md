> **1 page:** the evidence packaging subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

The evidence packaging subsystem is the final stage of the VulcansTrace analysis pipeline. It takes an `AnalysisResult` and the original raw log, renders findings through configured report formatters, includes the raw log as `log.txt`, optionally includes active suppression notes, guarded remediation plans, scorecards, Trace Map artifacts, MITRE Navigator layers, and Log Diff reports, computes a SHA-256 hash for every archive file, assembles a JSON manifest listing each file's hash and length, signs the manifest with HMAC-SHA256, and packs everything into a single ZIP archive. The result is a self-contained, tamper-evident evidence package that an investigator can verify without any VulcansTrace-specific tooling.

---

## Key Metrics

| Metric | Value |
|---|---|
| Core source files | EvidenceBuilder, IntegrityHasher, IEvidenceFormatter, and formatter/builder classes under `VulcansTrace.Linux.Evidence/Formatters` |
| Output formats per archive | Core findings reports, raw log, manifest/signature, optional suppressions/remediation, optional scorecards, optional Trace Map/MITRE artifacts, and optional Log Diff reports |
| Cryptographic primitives | SHA-256 (per-file) + HMAC-SHA256 (manifest) |
| Test files | 12 evidence test files covering builder, core formatters, scorecards, MITRE/Trace Map, and Log Diff reports |
| ZIP archive entries | Core report entries plus conditional `suppressions.csv`, `remediation.md`, scorecards, Trace Map/MITRE artifacts, and Log Diff reports |
| STIX 2.1 object types produced | 6 (identity, observed-data, note, ipv4-addr, ipv6-addr, malware) |

---

## Why It Matters

- **Analysis results are only useful if they can be shared and verified** — the ZIP archive is a portable, self-contained evidence bundle that requires no special viewer
- **Tamper evidence is essential for incident response handoff** — the HMAC-SHA256 manifest signature lets the recipient verify that no file in the archive was modified after creation
- **Multi-format output maximizes downstream compatibility** — CSV for spreadsheets, HTML for browser review, Markdown for Git-based workflows, JSON for SIEM ingestion, STIX 2.1 for threat intelligence platforms
- **Formula injection and XSS defense protect the recipient** — the CSV formatter neutralizes spreadsheet macro attacks, and the HTML formatter encodes all user content
- **STIX 2.1 export enables automated threat intelligence sharing** — findings map to observed-data with IP observables and optional malware SDOs for C2 activity
- **CIS Benchmark mapping preservation** — agent audit findings carry dual-layer CIS Controls v8 + CIS Ubuntu 24.04 LTS Benchmark references that flow through the evidence export path, giving auditors precise compliance traceability
- **Compliance scorecard export** — formal Pass/Warn/Fail per control family, overall percentage, and trend are rendered as self-contained HTML and Markdown reports for manager handoff
- **Risk scorecard export** — aggregate letter grade, numeric score, summary status, and per-category breakdown are rendered as self-contained HTML and Markdown reports for manager handoff

---

## Key Evidence

- [EvidenceBuilder.cs](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs) — builder orchestration, file rendering, manifest, HMAC, ZIP
- [CsvFormatter.cs](../../../../VulcansTrace.Linux.Evidence/Formatters/CsvFormatter.cs) — RFC 4180 CSV with formula injection defense
- [HtmlFormatter.cs](../../../../VulcansTrace.Linux.Evidence/Formatters/HtmlFormatter.cs) — dark-themed HTML with XSS prevention
- [JsonFormatter.cs](../../../../VulcansTrace.Linux.Evidence/Formatters/JsonFormatter.cs) — SIEM-compatible JSON export
- [MarkdownFormatter.cs](../../../../VulcansTrace.Linux.Evidence/Formatters/MarkdownFormatter.cs) — GFM tables with severity grouping
- [StixFormatter.cs](../../../../VulcansTrace.Linux.Evidence/Formatters/StixFormatter.cs) — STIX 2.1 bundle construction
- [IntegrityHasher.cs](../../../../VulcansTrace.Linux.Core/Security/IntegrityHasher.cs) — SHA-256 and HMAC-SHA256 primitives
- [EvidenceBuilderTests.cs](../../../../VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs) — end-to-end archive verification

---

## Key Design Choices

- **Builder pattern with dependency injection** — `EvidenceBuilder` accepts an `IntegrityHasher` and all formatters via constructor injection, enabling test-time substitution and single-responsibility separation
- **Deterministic file ordering** — manifest entries and ZIP entries are sorted alphabetically by filename (`OrderBy` with `StringComparer.OrdinalIgnoreCase`), supporting bitwise-reproducible archives for the same input and normalized timestamp
- **HMAC over SHA-256 hashes, not raw files** — signing the manifest JSON (which already contains per-file SHA-256 hashes) creates a two-layer integrity chain without requiring the verifier to re-hash every file independently
- **Timestamp clamping to ZIP spec range** — `NormalizeTimestamp` clamps `DateTimeOffset` values to the 1980-2107 range supported by the ZIP format, preventing `ArgumentOutOfRangeException` from `ZipArchiveEntry.LastWriteTime`
- **Formula injection defense in CSV** — the `Escape` method prepends a single quote to any cell value starting with `=`, `+`, `-`, or `@`, neutralizing CSV macro injection attacks (CVE-2021-23368 class)
- **STIX deduplication of IP objects** — `EnsureIpObject` maintains a dictionary of IP addresses already added to the bundle, preventing duplicate `ipv4-addr` SDOs when the same IP appears in multiple findings
- **Cancellation-aware build** — `CancellationToken.ThrowIfCancellationRequested()` is called between every major phase (file rendering, hashing, manifest creation, ZIP writing), allowing clean abort of long-running builds
