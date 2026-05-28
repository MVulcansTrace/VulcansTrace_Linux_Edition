# Evidence Packaging

The evidence packaging subsystem transforms raw analysis results into a cryptographically signed, multi-format evidence archive suitable for investigator review, SIEM ingestion, and threat intelligence sharing.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, algorithmic details, and test evidence

## Start Here

- [Technical Snapshot](./Evidence-Packaging-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its design, and where the proof lives
- [Quick Reference](./Evidence-Packaging-Summary/Quick-Reference.md) — archive contents, formatter capabilities, integrity chain, and output schema at a glance
- [Why This Matters](./Evidence-Packaging-In-Depth/Why-This-Matters.md) — the security problem this subsystem solves and the principles behind it
- [Packaging Algorithm](./Evidence-Packaging-In-Depth/Core-Logic-Breakdown/Packaging-Algorithm.md) — step-by-step walkthrough of the build pipeline
- [Design Decisions](./Evidence-Packaging-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Evidence-Packaging-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Evidence-Packaging-In-Depth/Attack-Scenario.md) — worked example showing evidence package construction from a real analysis result
- [Evasion and Limitations](./Evidence-Packaging-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [Evidence Integrity and Standards](./Evidence-Packaging-In-Depth/Evidence-Integrity-and-Standards.md) — NIST, FRE, and capability mapping

## System Capabilities

- **Six-format evidence output** — CSV, HTML, Markdown, JSON, STIX 2.1, and raw log in a single ZIP archive
- **Cryptographic integrity chain** — SHA-256 per-file hashes in a manifest, HMAC-SHA256 signature over the manifest, written as `manifest.json` + `manifest.hmac`
- **RFC 4180 CSV with formula injection defense** — cells starting with `=`, `+`, `-`, or `@` are prefixed with a single quote to prevent spreadsheet macro injection
- **XSS-safe HTML reports** — all user-provided content passes through `HtmlEncode` before rendering; self-contained dark-themed document
- **SIEM-compatible JSON** — camelCase output with metadata, findings, parse errors, and warnings sections
- **STIX 2.1 threat intelligence** — bundle with identity, observed-data, notes, IP observables, and optional malware SDO for C2 findings
- **Timestamp normalization** — ZIP entry timestamps are clamped to the ZIP spec range (1980-01-01 to 2107-12-31) to avoid archive corruption

## Implementation Evidence

- [EvidenceBuilder.cs](../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs) — builder pattern: renders 6 files, hashes, manifest, HMAC, ZIP archive
- [CsvFormatter.cs](../../../VulcansTrace.Linux.Evidence/Formatters/CsvFormatter.cs) — RFC 4180 CSV with formula injection defense
- [HtmlFormatter.cs](../../../VulcansTrace.Linux.Evidence/Formatters/HtmlFormatter.cs) — dark-themed HTML report with XSS prevention
- [JsonFormatter.cs](../../../VulcansTrace.Linux.Evidence/Formatters/JsonFormatter.cs) — SIEM-compatible JSON export with metadata
- [MarkdownFormatter.cs](../../../VulcansTrace.Linux.Evidence/Formatters/MarkdownFormatter.cs) — GFM tables with severity grouping and escaping
- [StixFormatter.cs](../../../VulcansTrace.Linux.Evidence/Formatters/StixFormatter.cs) — STIX 2.1 bundle with identity, observed-data, IP observables, and deterministic IDs
- [IntegrityHasher.cs](../../../VulcansTrace.Linux.Core/Security/IntegrityHasher.cs) — SHA-256 and HMAC-SHA256 wrapper
- [EvidenceBuilderTests.cs](../../../VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs) — end-to-end build, manifest, reproducibility, and HMAC verification tests
