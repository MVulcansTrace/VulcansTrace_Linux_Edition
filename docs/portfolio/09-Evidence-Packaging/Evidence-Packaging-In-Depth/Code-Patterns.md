> **Recurring implementation patterns** in the evidence packaging subsystem and how they support correctness, security, and testability.

---

## Pattern 1 — Builder with Orchestrator-Only Logic

**Where:** [EvidenceBuilder.cs](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

The `EvidenceBuilder` contains no formatting logic. It orchestrates:

1. Call each formatter and include the raw log passthrough
2. Add optional appendices such as active suppressions or guarded remediation plans
3. Hash each content file
4. Assemble and sign the manifest
5. Pack into ZIP

This keeps the builder auditable — the entire integrity chain is visible in one file without interleaving presentation logic.

```csharp
var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
{
    ["findings.csv"]  = Encoding.UTF8.GetBytes(_csvFormatter.ToCsv(result)),
    ["log.txt"]       = Encoding.UTF8.GetBytes(rawLog ?? string.Empty),
    ["report.html"]   = Encoding.UTF8.GetBytes(_htmlFormatter.ToHtml(result)),
    ["summary.md"]    = Encoding.UTF8.GetBytes(_markdownFormatter.ToMarkdown(result)),
    ["findings.json"] = Encoding.UTF8.GetBytes(_jsonFormatter.Format(result, rawLog ?? string.Empty, timestampOffset.UtcDateTime)),
    ["findings.stix.json"] = Encoding.UTF8.GetBytes(_stixFormatter.Format(result, rawLog ?? string.Empty, timestampOffset.UtcDateTime))
};

if (result.ActiveSuppressions.Count > 0)
    files["suppressions.csv"] = Encoding.UTF8.GetBytes(_csvFormatter.ToSuppressionCsv(result));

if (!string.IsNullOrWhiteSpace(remediationPlanMarkdown))
    files["remediation.md"] = Encoding.UTF8.GetBytes(remediationPlanMarkdown);
```

Every formatter implements `IEvidenceFormatter` with `Format`, `FileExtension`, and `ContentType`, ensuring a consistent contract for future formats.

---

## Pattern 2 — Output-Specific Escape then Encode

**Where:** [CsvFormatter.cs:60-80](../../../../VulcansTrace.Linux.Evidence/Formatters/CsvFormatter.cs), [HtmlFormatter.cs](../../../../VulcansTrace.Linux.Evidence/Formatters/HtmlFormatter.cs), [MarkdownFormatter.cs:80-96](../../../../VulcansTrace.Linux.Evidence/Formatters/MarkdownFormatter.cs)

Each formatter applies defense in two stages:

1. **Sanitize** — neutralize format-specific injection vectors (formula characters in CSV, control characters in Markdown)
2. **Encode** — wrap the result in the format's quoting mechanism (double-quote escaping in CSV, `HtmlEncode` in HTML, backslash escaping in Markdown)

```csharp
// CsvFormatter — formula injection defense THEN CSV quoting
if (first == '=' || first == '+' || first == '-' || first == '@')
    sanitized = "'" + sanitized;
if (sanitized.Contains('"') || sanitized.Contains(','))
    return $"\"{sanitized.Replace("\"", "\"\"")}\"";
```

```csharp
// HtmlFormatter — encode every user content field
sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.Category)}</td>");
```

```csharp
// MarkdownFormatter — escape special characters that break GFM tables
string[] specials = ["\\", "|", "*", "_", "`", "[", "]"];
foreach (var s in specials)
    sanitized = sanitized.Replace(s, $"\\{s}");
```

This two-stage approach ensures that injection defense is applied before structural encoding, preventing edge cases where encoding accidentally reintroduces dangerous content.

---

## Pattern 3 — Null-Coalescing at the Boundary

**Where:** [EvidenceBuilder.cs:111-119](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

The builder treats `null` raw log input as `string.Empty` at the point of use:

```csharp
["log.txt"]       = Encoding.UTF8.GetBytes(rawLog ?? string.Empty),
```

This pattern avoids `NullReferenceException` deep in the build pipeline without silently discarding information — the manifest records `length: 0` for an empty log, which is itself informative (the analysis was run without a log file).

---

## Pattern 4 — Crypto Delegation to IntegrityHasher

**Where:** [IntegrityHasher.cs](../../../../VulcansTrace.Linux.Core/Security/IntegrityHasher.cs)

All cryptographic operations are encapsulated in `IntegrityHasher`:

```csharp
public byte[] ComputeSha256(byte[] data)
{
    using var sha = SHA256.Create();
    return sha.ComputeHash(data);
}

public byte[] ComputeHmacSha256(byte[] data, byte[] key)
{
    using var hmac = new HMACSHA256(key);
    return hmac.ComputeHash(data);
}
```

The builder never touches `SHA256` or `HMACSHA256` directly. This:

- Enables test-time mock injection to verify the builder uses the hasher correctly without computing real hashes
- Centralizes any future algorithm migration (e.g., SHA-256 → SHA-3) in a single file
- Makes the cryptographic boundary auditable — all hash/HMAC calls go through one class

---

## Pattern 5 — Deterministic Serialization

**Where:** [EvidenceBuilder.cs:124-136](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

The manifest is constructed from deterministically ordered data:

```csharp
foreach (var kvp in files.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
```

The manifest JSON is serialized with `WriteIndented = true` using .NET's `System.Text.Json`, which produces consistent property ordering for anonymous types. Combined with alphabetical file sorting, this ensures that the manifest byte representation is reproducible for identical inputs, making the HMAC signature deterministic.

---

## Pattern 6 — Conditional STIX Object Creation

**Where:** [StixFormatter.cs:133-145](../../../../VulcansTrace.Linux.Evidence/Formatters/StixFormatter.cs)

The STIX formatter adds the `malware` SDO only when the findings contain a `C2Channel` category:

```csharp
if (result.Findings.Any(f => f.Category.Equals("C2Channel", StringComparison.OrdinalIgnoreCase)))
{
    bundle.Objects.Add(new StixMalware { ... });
}
```

And the `observed-data` SDO is only created when at least one valid IP address exists:

```csharp
if (objectRefs.Count == 0)
    continue;
```

This prevents the bundle from containing empty or meaningless STIX objects that would fail TIP validation.

---

## Pattern 7 — Hex String Interoperability

**Where:** [EvidenceBuilder.cs:182](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs)

Both SHA-256 hashes and the HMAC are written as **lowercase hex strings**, not raw bytes:

```csharp
var hashHex = Convert.ToHexString(hash).ToLowerInvariant();
var hmacHex = Encoding.UTF8.GetBytes(Convert.ToHexString(manifestHmac).ToLowerInvariant());
```

This ensures:

- The manifest is human-readable JSON (hex strings, not base64 or binary)
- The HMAC file is a plain-text file that can be verified with any hex-capable tool
- Cross-platform compatibility — hex strings have no encoding ambiguity

---

## Pattern 8 — Structured Test Verification

**Where:** [EvidenceBuilderTests.cs](../../../../VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs)

The end-to-end test verifies the complete integrity chain:

1. Build an archive from a known `AnalysisResult` and signing key
2. Open the ZIP and verify all core entries exist, plus any requested optional appendices
3. Parse `manifest.json` and verify it lists the expected core and optional files with correct count
4. Re-compute the HMAC from the manifest bytes and signing key
5. Assert the recomputed HMAC matches `manifest.hmac`

This single test validates the entire Phase 2-5 pipeline in one assertion chain.

---

## Security Takeaways

- The orchestrator-only builder pattern keeps the integrity chain auditable — the hash-then-sign logic is in one file with no formatting distractions
- Two-stage output sanitization (sanitize then encode) prevents format-specific injection at every output boundary
- Crypto delegation to `IntegrityHasher` isolates algorithm choices and enables test-time verification of cryptographic behavior
- Deterministic serialization ensures that the HMAC signature is reproducible, supporting forensic corroboration
- Hex string output for all cryptographic artifacts ensures cross-platform, human-readable interoperability
