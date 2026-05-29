> **Step-by-step walkthrough of the evidence packaging algorithm**, from `AnalysisResult` to signed ZIP archive.

---

## Algorithm Overview

The `EvidenceBuilder.Build` method executes seven sequential phases, with cancellation checks between each phase:

```
Phase 1: Timestamp normalization
Phase 2: Content rendering (5 formatters + raw-log passthrough)
Phase 3: Per-file SHA-256 hashing
Phase 4: Manifest assembly
Phase 5: HMAC-SHA256 manifest signing
Phase 6: ZIP archive construction
Phase 7: Return byte array
```

---

## Phase 1 — Timestamp Normalization

**Source:** [EvidenceBuilder.cs:287-308](../../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

```
Input:  AnalysisResult.TimeRangeEnd (or provided DateTime, or UnixEpoch)
Output: DateTimeOffset clamped to [1980-01-01, 2107-12-31]
```

The method selects the best available timestamp in priority order:

1. Caller-provided `analysisTimestampUtc` parameter
2. `result.TimeRangeEnd` (if not `DateTime.MinValue`)
3. `result.TimeRangeStart` (if not `DateTime.MinValue`)
4. `DateTime.UnixEpoch` as fallback

Each candidate is converted to UTC via `EnsureUtc`, which handles `Local`, `Utc`, and `Unspecified` kinds. The resulting `DateTimeOffset` is then clamped:

- Below `1980-01-01` → clamped to `ZipMinTimestamp`
- Above `2107-12-31` → clamped to `ZipMaxTimestamp`

This prevents `ZipArchiveEntry.LastWriteTime` from throwing `ArgumentOutOfRangeException` on non-ZIP-compatible dates.

---

## Phase 2 — Content Rendering

**Source:** [EvidenceBuilder.cs:111-119](../../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

The builder renders six files into a `Dictionary<string, byte[]>`:

| Key | Formatter Method | Output |
|---|---|---|
| `findings.csv` | `_csvFormatter.ToCsv(result)` | RFC 4180 CSV |
| `log.txt` | `rawLog ?? string.Empty` | Raw log passthrough |
| `report.html` | `_htmlFormatter.ToHtml(result)` | Self-contained HTML report |
| `summary.md` | `_markdownFormatter.ToMarkdown(result)` | GFM Markdown |
| `findings.json` | `_jsonFormatter.Format(result, rawLog)` | SIEM-compatible JSON |
| `findings.stix.json` | `_stixFormatter.Format(result, rawLog)` | STIX 2.1 bundle |

All content is encoded as UTF-8 bytes via `Encoding.UTF8.GetBytes`. The dictionary uses `StringComparer.OrdinalIgnoreCase` for consistent key lookup.

---

## Phase 3 — Per-File SHA-256 Hashing

**Source:** [EvidenceBuilder.cs:122-136](../../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

```
foreach file in files.OrderBy(alphabetical):
    hash = SHA256(file.Value)           // 32 bytes
    hashHex = ToHexString(hash).ToLower() // 64-char hex string
    manifestEntries.Add({ file, sha256, length })
```

Files are processed in alphabetical order to ensure deterministic manifest content. Each entry records:

- `file` — the filename key
- `sha256` — lowercase hex string of the SHA-256 hash
- `length` — byte count of the rendered content

---

## Phase 4 — Manifest Assembly

**Source:** [EvidenceBuilder.cs:138-145](../../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

The manifest is an anonymous object with five properties:

```json
{
  "createdUtc": "<timestamp>",
  "files": [ /* ordered entries from Phase 3 */ ],
  "warnings": [ /* from AnalysisResult.Warnings */ ],
  "parseErrors": [ /* from AnalysisResult.ParseErrors */ ],
  "skippedLineCount": 0
}
```

The manifest is serialized to UTF-8 JSON with `WriteIndented = true` for human readability. This indented form is what gets HMAC-signed in Phase 5.

---

## Phase 5 — HMAC-SHA256 Manifest Signing

**Source:** [EvidenceBuilder.cs:153](../../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

```
manifestHmac = HMAC-SHA256(manifestJson, signingKey)
```

The HMAC is computed over the exact UTF-8 bytes of the indented manifest JSON. The signing key (`byte[]`) is provided by the caller — the evidence subsystem never generates or stores keys.

The 32-byte HMAC result is converted to a lowercase hex string and written as UTF-8 text to `manifest.hmac` in the archive.

---

## Phase 6 — ZIP Archive Construction

**Source:** [EvidenceBuilder.cs:156-187](../../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

The archive is built in-memory via `MemoryStream` + `ZipArchive`:

1. Write each core content file as a separate ZIP entry, plus optional `suppressions.csv` and guarded `remediation.md` appendices when present, alphabetical order, `CompressionLevel.Optimal`, `LastWriteTime` set to the normalized timestamp
2. Write `manifest.json` as a ZIP entry
3. Write `manifest.hmac` as a ZIP entry (lowercase hex string)

All entries use the same normalized timestamp for `LastWriteTime`. The `ZipArchive` is created with `leaveOpen: true` so the `MemoryStream` remains readable after the `using` block disposes the archive.

The final `ms.ToArray()` captures the complete ZIP bytes.

---

## Phase 7 — Return

The builder returns `byte[]` — the complete ZIP archive contents. The caller is responsible for writing to disk, transmitting over a network, or loading in memory for the UI.

---

## Cancellation Points

`CancellationToken.ThrowIfCancellationRequested()` is called at **six points** during the build:

1. Before timestamp normalization
2. After content rendering
3. Inside the per-file hashing loop (after each file)
4. After manifest serialization
5. After HMAC computation
6. Inside the ZIP entry writing loop (after each entry)

This ensures that a cancelled operation aborts quickly without producing a corrupt partial archive.

---

## Integrity Verification Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     ZIP Archive                              │
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐   │
│  │ findings.csv │   │ report.html  │   │  summary.md    │   │
│  │   SHA-256    │   │   SHA-256    │   │    SHA-256     │   │
│  └──────┬───────┘   └──────┬───────┘   └───────┬────────┘   │
│         │                  │                    │            │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐   │
│  │findings.json │   │findings.stix │   │    log.txt     │   │
│  │   SHA-256    │   │   SHA-256    │   │    SHA-256     │   │
│  └──────┬───────┘   └──────┬───────┘   └───────┬────────┘   │
│         │                  │                    │            │
│         └──────────────────┼────────────────────┘            │
│                            │                                 │
│                   ┌────────▼────────┐                        │
│                   │  manifest.json  │                        │
│                   │  (6 SHA-256     │                        │
│                   │   hashes +      │                        │
│                   │   metadata)     │                        │
│                   └────────┬────────┘                        │
│                            │                                 │
│                   ┌────────▼────────┐                        │
│                   │  manifest.hmac  │                        │
│                   │  HMAC-SHA256    │                        │
│                   │  of manifest    │                        │
│                   └─────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Takeaways

- The two-layer hash chain (SHA-256 per file → HMAC-SHA256 over manifest) provides file-level and package-level integrity in a single verification workflow
- Alphabetical file ordering ensures deterministic manifest JSON, so the HMAC is reproducible for the same input
- UTF-8 HMAC hex output (not raw bytes) ensures the `manifest.hmac` entry is text-safe and interoperable across platforms
- Cancellation checks between every phase prevent corrupt partial archives from being returned to the caller
- Timestamp clamping prevents a valid analysis result with an extreme date from crashing the ZIP writer and silently failing
