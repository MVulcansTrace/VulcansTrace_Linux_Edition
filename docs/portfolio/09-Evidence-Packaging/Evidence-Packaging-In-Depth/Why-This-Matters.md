> **Why the evidence packaging subsystem exists, the problem it solves, and the security principles behind it.**

---

## The Problem

When an analyst or automated system finishes analyzing firewall logs, the results are typically a collection of in-memory data structures — findings, warnings, parse errors, and metadata. These results are useless unless they can be:

1. **Shared** with incident responders, forensic analysts, or legal teams who do not have VulcansTrace installed
2. **Ingested** by downstream security tools such as SIEM platforms and threat intelligence platforms
3. **Verified** to confirm that the evidence has not been altered since it was produced
4. **Preserved** in formats that remain readable years after the analysis was performed

Without a packaging step, analysis results evaporate when the process exits. Without cryptographic integrity, any stakeholder can question whether the findings were modified. Without multi-format output, the analyst must manually convert data for each downstream consumer.

---

## Why This Subsystem

The evidence packaging subsystem addresses these requirements with a single `Build` call that:

- Renders the `AnalysisResult` through five formatters and includes the raw log as `log.txt`
- Computes SHA-256 hashes for every content file, embedding them in a structured manifest
- Signs the manifest with HMAC-SHA256 to create a tamper-evident chain
- Packs everything into a portable ZIP archive that any operating system can open

The design is intentionally **stateless and deterministic**: given the same `AnalysisResult`, raw log, and signing key, the builder produces a reproducible archive (sorted file ordering, fixed timestamps where overridden). This is critical for forensic defensibility — two independent verifications should produce the same manifest hashes.

---

## Security Principles

### Tamper Evidence, Not Encryption

The evidence package uses HMAC-SHA256 signing, not encryption. The goal is **integrity verification**, not confidentiality. Any recipient can read the files; only a recipient with the shared signing key can verify the HMAC. This matches the incident response pattern where evidence is shared openly within a team but must be provably unmodified.

### Defense in Depth at the Format Level

Each formatter applies its own output-specific security controls:

- **CSV**: formula injection defense prevents spreadsheet macro attacks when an analyst opens `findings.csv` in Excel or LibreOffice
- **HTML**: `HtmlEncode` on all user-provided content prevents XSS if the report is served from a web share
- **STIX 2.1**: IP validation with `IPAddress.TryParse` ensures that malformed addresses do not produce invalid STIX objects that would break a TIP's ingestion pipeline

### Fail-Safe Cryptography

The `IntegrityHasher` wraps .NET's `SHA256` and `HMACSHA256` implementations directly — no custom cryptography, no third-party libraries. The HMAC key is supplied by the caller, keeping key management outside the evidence subsystem's responsibility.

### Cancellation Safety

The builder checks `CancellationToken.ThrowIfCancellationRequested()` between every major phase — file rendering, per-file hashing, manifest serialization, and ZIP entry writing. This ensures that a cancelled analysis does not produce a partially written, corrupt archive.

---

## Where It Fits in the Pipeline

The evidence packaging subsystem is the **final stage** of the VulcansTrace analysis pipeline:

```
Raw Log Text
    --> Log Normalization (01)
    --> Detectors (02-07, 13-15)
    --> Risk Escalation (08)
    --> Evidence Packaging (09)  <-- you are here
    --> ZIP archive output
```

Every upstream subsystem produces an `AnalysisResult` that accumulates findings. The evidence builder consumes that result and the original log, producing the portable, verifiable output artifact.

---

## Security Takeaways

- Evidence without integrity verification is hearsay — the SHA-256 + HMAC-SHA256 chain provides cryptographic proof of authenticity
- Multi-format output is a security feature, not a convenience — each format's defensive measures (formula injection, XSS, IP validation) protect different downstream attack surfaces
- Deterministic archive construction (sorted entries, clamped timestamps) ensures bitwise reproducibility for forensic corroboration
- Stateless builder design keeps key management and lifecycle concerns outside the packaging boundary — the caller owns the signing key
- Cancellation-aware build prevents corrupt partial archives from being written to disk
