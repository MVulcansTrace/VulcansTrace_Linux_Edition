> **Known weaknesses, attack surfaces, and the improvement roadmap** for the evidence packaging subsystem.

---

## Known Limitations

### HMAC Does Not Provide Non-Repudiation

HMAC-SHA256 is a symmetric primitive — anyone who holds the signing key can produce a valid signature. This means:

- A recipient with the key cannot cryptographically prove to a third party that the package was produced by a specific source
- An adversary who compromises the signing key can forge valid evidence packages

**Mitigation in context:** The evidence package is designed for team-internal incident response, not for adversarial legal proceedings. For legal-grade non-repudiation, an asymmetric signature (e.g., RSA-PSS or ECDSA over the manifest) would be required.

### No Encryption at Rest

The ZIP archive is unencrypted. Any recipient with access to the file can read all findings, raw logs, and metadata.

**Mitigation in context:** Confidentiality is expected to be handled at the transport/storage layer (encrypted disk, TLS transmission, access-controlled file share). The evidence subsystem's responsibility is integrity, not confidentiality.

### Manifest JSON Indentation Affects HMAC

The manifest is serialized with `WriteIndented = true` for readability. Any change to the JSON serializer's indentation logic across .NET versions could alter the manifest byte representation, breaking HMAC verification for archives produced with older versions.

**Mitigation in context:** The manifest is re-read as raw bytes for HMAC verification, not re-serialized. The stored `manifest.json` bytes are what gets verified, not a re-rendered version. However, cross-version archive reproducibility (rebuilding the same `AnalysisResult` with a newer .NET version) could produce a different manifest and therefore a different HMAC.

### No Streaming Output

The entire archive is built in memory (`MemoryStream`) and returned as `byte[]`. For very large logs, this means the memory footprint is approximately:

```
rendered content (6 formats) + raw log + manifest + HMAC + ZIP overhead
```

**Mitigation in context:** The upstream log normalizer caps input at 100 million characters. In practice, the rendered output is typically smaller than the raw log because the HTML, Markdown, and CSV representations are summaries, not line-by-line transcripts. The raw log passthrough (`log.txt`) is the dominant memory consumer.

---

## Evasion and Attack Surfaces

### Malicious Log Content in CSV Output

An attacker who controls the source IP, destination, or description fields in the log could attempt to inject formulas into the CSV output. The `CsvFormatter.Escape` method neutralizes this by prepending `'` to values starting with `=`, `+`, `-`, or `@`.

**Remaining risk:** If a new formula prefix character is introduced in a spreadsheet application (e.g., a future version of Excel treats `#` as a formula delimiter), the CSV defense would need updating. This is monitored through CVE databases.

### XSS in HTML Output

The `HtmlFormatter` encodes all user-provided content via `System.Net.WebUtility.HtmlEncode`. However:

- The severity field (`f.Severity`) is rendered without encoding because it is an enum value (`Severity.High`, etc.), not user-controlled text
- Timestamps (`f.TimeRangeStart:O`) are rendered without encoding because they are machine-formatted ISO 8601 strings
- The CSS and structural HTML are hardcoded, not derived from user input

**Remaining risk:** If a new formatter is added that forgets to encode user content, XSS becomes possible. The `IEvidenceFormatter` interface does not enforce encoding — this is a convention, not a compile-time guarantee.

### STIX IP Validation Bypass

The `StixFormatter` validates IP addresses with `IPAddress.TryParse` before creating `ipv4-addr` objects. However:

- Non-IP target values (e.g., `"multiple hosts/ports"`) are correctly skipped by the `ExtractTargetIp` + `IsValidIpAddress` chain
- IPv6 addresses are placed in `ipv6-addr` SDOs (not `ipv4-addr`), but TIP compatibility for IPv6 indicators varies by platform

**Remaining risk:** Some strict TIP implementations may not fully support `ipv6-addr` SDOs, or may apply different validation rules for IPv6 indicators compared to IPv4.

### Archive Timestamp Manipulation

ZIP entry timestamps are set to the normalized analysis timestamp, not the actual build time. An attacker who can modify the `createdUtc` field in the manifest and recompute the HMAC (if they have the key) could backdate or forward-date the evidence.

**Mitigation in context:** Without the signing key, the attacker cannot produce a valid HMAC for the modified manifest. With the key, the attacker can produce any valid archive — but key compromise is outside the evidence subsystem's threat model.

---

## Improvement Roadmap

| Enhancement | Priority | Description |
|---|---|---|
| Asymmetric manifest signatures | Medium | Add RSA-PSS or ECDSA signing option for non-repudiation |
| STIX relationship objects | Low | Add `relationship` SDOs linking observed-data to malware and identity objects |
| Streaming ZIP output | Low | Write to a `Stream` instead of `byte[]` to reduce memory footprint for large logs |
| Encrypted archive option | Low | AES-256 ZIP encryption for confidentiality-at-rest |
| Formatter encoding enforcement | Medium | Add a base class or analyzer that verifies `HtmlEncode` is called for all user content |
| Archive reproducibility test | Medium | Add a test that builds the same `AnalysisResult` twice and asserts byte-identical output |

---

## Security Takeaways

- HMAC provides integrity verification but not non-repudiation — a compromised signing key allows archive forgery
- CSV formula injection and HTML XSS are the primary output attack surfaces, both mitigated by per-formatter encoding conventions
- TIP compatibility for `ipv6-addr` SDOs varies by platform and should be verified for the target threat intelligence platform
- The in-memory build approach limits scalability for very large logs but is safe within the 100M-character input cap
- Adding an asymmetric signature option would close the non-repudiation gap for legal-grade evidence workflows
