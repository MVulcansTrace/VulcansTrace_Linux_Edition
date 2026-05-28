> **Evidence integrity standards and regulatory alignment** for the evidence packaging subsystem: capability mapping, NIST alignment, Federal Rules of Evidence mapping, and verification procedures.

---

## Capability Mapping

| Capability | Implementation | Code Location |
|---|---|---|
| File-level integrity (SHA-256) | Per-file hash stored in manifest | [EvidenceBuilder.cs:127-128](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs) |
| Package-level integrity (HMAC-SHA256) | Manifest signed with caller-supplied key | [EvidenceBuilder.cs:153](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs) |
| CSV formula injection defense | Single-quote prefix on `=+-@` cells | [CsvFormatter.cs:67-74](../../../../VulcansTrace.Linux.Evidence/Formatters/CsvFormatter.cs) |
| HTML XSS prevention | `HtmlEncode` on all user content | [HtmlFormatter.cs:61,73-76,79](../../../../VulcansTrace.Linux.Evidence/Formatters/HtmlFormatter.cs) |
| STIX 2.1 compliance | Bundle with identity, observed-data, notes, IP observables, and optional malware context | [StixFormatter.cs](../../../../VulcansTrace.Linux.Evidence/Formatters/StixFormatter.cs) |
| SIEM-compatible JSON export | camelCase, metadata + findings + errors + warnings | [JsonFormatter.cs](../../../../VulcansTrace.Linux.Evidence/Formatters/JsonFormatter.cs) |
| Deterministic archive | Alphabetical file ordering, fixed serialization | [EvidenceBuilder.cs:124](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs) |
| Timestamp normalization | UTC enforcement + ZIP range clamping | [EvidenceBuilder.cs:287-308](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs) |
| Cancellation safety | `ThrowIfCancellationRequested` at 6 points | [EvidenceBuilder.cs](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs) |
| Stateless build | Returns `byte[]`, no disk I/O | [EvidenceBuilder.cs:156-187](../../../../VulcansTrace.Linux.Evidence/EvidenceBuilder.cs) |

---

## NIST SP 800-xx Alignment

| NIST Control | Requirement | Evidence Packaging Implementation |
|---|---|---|
| SP 800-53 AU-2 (Audit Events) | Define auditable events | Each formatter captures category, severity, source, target, and time range — the core auditable fields for network security events |
| SP 800-53 AU-3 (Content of Audit Records) | Include sufficient information in audit trails | `findings.json` includes tool name, version, export timestamp, line counts, time range, findings, parse errors, and warnings |
| SP 800-53 AU-10 (Non-repudiation) | Protect against unauthorized modification | HMAC-SHA256 manifest signature provides cryptographic binding; asymmetric signatures would provide full non-repudiation (noted as roadmap item) |
| SP 800-86 (Media Forensics) | Preserve and analyze digital evidence | ZIP archive is a self-contained evidence container; SHA-256 per-file hashes enable integrity verification independent of the tool |
| SP 800-92 (Log Management) | Generate, transmit, store, and dispose of logs | `log.txt` preserves the original raw log; the manifest records creation timestamp and warnings for chain-of-custody documentation |
| SP 800-137 (Information Security Continuous Monitoring) | Maintain ongoing awareness of security state | Multi-format output (CSV, JSON, STIX) enables automated ingestion into SIEM and TIP platforms for continuous monitoring |

---

## Federal Rules of Evidence (FRE) Mapping

| FRE Rule | Requirement | Evidence Packaging Support |
|---|---|---|
| FRE 901(a) (Authentication) | Sufficient evidence to support a finding that the item is what it claims | SHA-256 hashes in the manifest provide cryptographic authentication of each file; the HMAC signature authenticates the manifest as a whole |
| FRE 901(b)(9) (Process or System) | Evidence describing a process and producing an accurate result | The build algorithm is deterministic: identical inputs produce identical manifest hashes and HMAC signatures. The source code is the process description |
| FRE 902 (Self-Authentication) | Evidence that requires no extrinsic evidence of authenticity | The HMAC can be verified independently using standard tools (`openssl dgst -sha256 -mac HMAC -macopt hexkey:...`) without requiring VulcansTrace software |
| FRE 1001-1004 (Best Evidence) | Original writings, recordings, or photographs | `log.txt` contains the complete original raw log; `manifest.json` records byte lengths and hashes to confirm completeness |
| FRE 1006 (Summaries) | Charts, summaries, or calculations that cannot be conveniently examined in court | `summary.md`, `report.html`, and `findings.csv` are summaries of the analysis; they are derived from the same `AnalysisResult` and their integrity is verified through the same manifest |
| FRE 702 (Expert Testimony) | Expert's opinion based on sufficient facts or data | The multi-format evidence package provides the factual basis (raw log + findings + integrity chain) for an expert to reference |

---

## Integrity Verification Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Integrity Verification Flow                   │
│                                                                  │
│  Step 1: Read manifest.hmac                                     │
│     │                                                            │
│     ▼                                                            │
│  Step 2: Read manifest.json (raw bytes)                         │
│     │                                                            │
│     ▼                                                            │
│  Step 3: Recompute HMAC-SHA256(manifest bytes, shared key)      │
│     │                                                            │
│     ├── Match? ──► Manifest integrity CONFIRMED                 │
│     │                                                            │
│     └── No match? ──► TAMPERED or wrong key                     │
│                                                                  │
│  Step 4: For each file in manifest:                             │
│     │   Read file bytes                                         │
│     │   Recompute SHA-256                                       │
│     │   Compare to manifest["sha256"]                           │
│     │                                                            │
│     ├── All match? ──► Full integrity CONFIRMED                 │
│     │                                                            │
│     └── Any mismatch? ──► File tampered AFTER manifest creation │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Verification Procedure

### Manual Verification with Standard Tools

```bash
# Extract the archive
unzip evidence-package.zip -d evidence/

# Step 1: Verify manifest HMAC with the hex signing key copied from the UI
STORED_HMAC=$(cat evidence/manifest.hmac)
SIGNING_KEY_HEX="<64-character hex signing key>"
COMPUTED_HMAC=$(openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SIGNING_KEY_HEX" \
    evidence/manifest.json | awk '{print $NF}')
[ "$STORED_HMAC" = "$COMPUTED_HMAC" ] && echo "PASS: HMAC verified" || echo "FAIL: HMAC mismatch"

# Step 2: Verify individual file hashes
cat evidence/manifest.json | python3 -c "
import json, hashlib, sys
manifest = json.load(sys.stdin)
for entry in manifest['files']:
    with open(f'evidence/{entry[\"file\"]}', 'rb') as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    expected = entry['sha256']
    status = 'PASS' if actual == expected else 'FAIL'
    print(f'{status}: {entry[\"file\"]} sha256={actual[:16]}...')
"
```

### Programmatic Verification

The same verification logic is tested in [EvidenceBuilderTests.cs](../../../../VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs):

```csharp
// Re-read manifest bytes from the ZIP
// Recompute HMAC with the same signing key
var expectedHmac = Convert.ToHexString(
    hasher.ComputeHmacSha256(manifestBytes, signingKey)
).ToLowerInvariant();
Assert.Equal(expectedHmac, hmacText);
```

---

## Security Takeaways

- The SHA-256 + HMAC-SHA256 two-layer integrity chain maps directly to FRE 901(a) authentication requirements — each file is individually authenticated, and the manifest is authenticated as a whole
- Self-contained verification (FRE 902) is achievable because the HMAC can be validated with standard cryptographic tools — no proprietary software is required
- The original raw log (`log.txt`) satisfies FRE 1001-1004 best evidence requirements, while the summary formats (`summary.md`, `report.html`, `findings.csv`) satisfy FRE 1006 summary requirements
- NIST SP 800-53 AU-10 non-repudiation is partially met through HMAC; full non-repudiation would require the planned asymmetric signature enhancement
- NIST SP 800-86 forensic preservation is supported by the self-contained ZIP format, which bundles the original evidence, analysis results, and integrity metadata in a single portable file
- The deterministic build ensures that the same analysis result always produces the same manifest hashes, supporting reproducibility requirements for forensic testimony
