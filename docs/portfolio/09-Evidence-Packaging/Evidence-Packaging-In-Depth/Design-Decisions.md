> **Rationale for the key architectural and security decisions** in the evidence packaging subsystem.

---

## Builder Pattern with Constructor Injection

**Decision:** `EvidenceBuilder` receives all formatters and the `IntegrityHasher` via constructor parameters.

**Rationale:** The builder does not own the formatter lifecycle or the cryptographic key material. Constructor injection allows:

- Test doubles for any formatter (e.g., verify the builder calls `ToCsv` without depending on CSV formatting logic)
- `JsonFormatter` and `StixFormatter` are optional (`JsonFormatter?` / `StixFormatter?`), defaulting to `new` instances — this preserves backward compatibility for callers that only need the core formats
- The `IntegrityHasher` abstraction allows future algorithm changes (e.g., SHA-3) without modifying the builder

**Trade-off:** The builder has a 6-parameter constructor. This is acceptable because the builder is constructed once per application lifecycle (typically in DI configuration) and never re-created per analysis.

---

## HMAC-SHA256 Over the Manifest (Not Over Individual Files)

**Decision:** Sign `manifest.json` with HMAC-SHA256 rather than signing each file independently.

**Rationale:**

- The manifest already contains SHA-256 hashes for every file, so signing the manifest implicitly covers all files
- A single HMAC signature is faster to verify than 6+ individual signatures
- The manifest is the single source of truth for file metadata — if someone adds, removes, or reorders a file, the HMAC breaks
- HMAC (symmetric) was chosen over digital signatures (asymmetric) because evidence packages are verified within a trusted team that shares the signing key

**Trade-off:** HMAC does not provide non-repudiation — anyone with the key can produce a valid signature. For scenarios requiring non-repudiation, an asymmetric signature (e.g., RSA-PSS over the manifest) would be needed. This is noted as a future enhancement.

---

## Deterministic File Ordering

**Decision:** Files are sorted alphabetically (`StringComparer.OrdinalIgnoreCase`) in both the manifest and the ZIP archive.

**Rationale:**

- Two `Build` calls with identical inputs produce byte-identical manifest JSON, which produces an identical HMAC
- Alphabetical ordering is a simple, stable sort that does not depend on `Dictionary` enumeration order (which is undefined in .NET)
- Forensic corroboration benefits from reproducibility — two independent verifiers can confirm they received the same package

---

## Timestamp Clamping to ZIP Range

**Decision:** `NormalizeTimestamp` clamps the output timestamp to `[1980-01-01, 2107-12-31]`.

**Rationale:**

- The ZIP format stores timestamps as a DOS date-time field with a minimum of 1980-01-01 and a maximum of 2107-12-31
- `ZipArchiveEntry.LastWriteTime` throws `ArgumentOutOfRangeException` for values outside this range
- `AnalysisResult.TimeRangeStart` could be `DateTime.UnixEpoch` (1970-01-01), which is before the ZIP minimum
- Without clamping, a valid analysis result would crash the build, producing no archive at all — a silent failure mode that violates the principle that evidence should always be producible

---

## Formula Injection Defense in CSV

**Decision:** The `CsvFormatter.Escape` method prepends a single quote (`'`) to any cell value starting with `=`, `+`, `-`, or `@`.

**Rationale:**

- CSV files are commonly opened in spreadsheet applications (Excel, Google Sheets, LibreOffice Calc) that interpret leading characters as formula delimiters
- An attacker who controls log content (e.g., a crafted iptables log with a malicious comment) could inject formulas that execute code when the CSV is opened
- This is a well-documented attack class (CVE-2021-23368 and related) — the single-quote prefix causes the spreadsheet to treat the cell as text rather than a formula

**Trade-off:** The single quote appears in the raw CSV content. This is standard practice and matches the defense used by OWASP and other security frameworks.

---

## Self-Contained HTML (No External Dependencies)

**Decision:** The HTML report is a single `<!DOCTYPE html>` document with inline CSS and no external scripts or stylesheets.

**Rationale:**

- Evidence packages must remain readable offline, potentially years after creation
- External CDN links break when the network is unavailable or the CDN goes offline
- Inline styles eliminate the risk of CSS injection from external sources
- The dark theme (`background:#111; color:#eee`) is aesthetic only and does not affect content or security

---

## STIX 2.1 IP Deduplication

**Decision:** `StixFormatter.EnsureIpObject` maintains a dictionary of IP addresses and reuses existing `ipv4-addr` SDOs.

**Rationale:**

- A single IP address (e.g., `192.168.1.100`) may appear as the source in dozens of findings
- Without deduplication, the bundle would contain duplicate `ipv4-addr` objects with different IDs, which violates STIX best practices and can confuse TIP ingestion
- The dictionary lookup is O(1) and adds negligible overhead compared to JSON serialization

---

## Stateless Build (No File I/O During Construction)

**Decision:** `Build` returns `byte[]` and never writes to disk.

**Rationale:**

- The caller decides where and how to persist the archive (disk, network, in-memory display)
- The Avalonia UI can present the archive as a download without temp-file cleanup
- Test code can verify the archive contents without managing file paths
- No side effects means no partial-state corruption if the build fails midway

---

## Security Takeaways

- HMAC over manifest (not individual files) provides a single verification point that covers all content — simpler for the verifier and harder to bypass
- Formula injection defense in CSV is a proactive security measure against a known attack class that affects evidence review workflows
- Self-contained HTML eliminates supply-chain risk from external resources in an evidence artifact
- Stateless `byte[]` return prevents file-system side effects that could leak evidence to unauthorized locations
- Timestamp clamping prevents a denial-of-service condition where valid input crashes the archive writer
- IP deduplication in STIX output prevents invalid bundles that could break downstream threat intelligence platforms
