> **Worked example:** constructing an evidence package from a port scan analysis result, showing the exact archive contents at each stage.

---

## Scenario

An analyst runs VulcansTrace against an iptables log that contains a port scan from `192.168.1.100` targeting the internal network. The analysis produces an `AnalysisResult` with one High-severity PortScan finding. The analyst packages it into a signed evidence archive.

---

## Input

```csharp
var result = new AnalysisResult
{
    TotalLines = 2,
    ParsedLines = 2,
    ParseErrorCount = 0,
    Findings =
    [
        new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "10.0.0.1",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan detected",
            Details = "Detected 12 distinct destinations."
        }
    ],
    Warnings = ["Sample warning"]
};

var rawLog = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 "
           + "DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22";

var signingKey = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");
var timestamp = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc);
```

---

## Phase 1 — Timestamp Normalization

```
Input:  analysisTimestampUtc = 2024-01-02T03:04:05Z
Output: DateTimeOffset = 2024-01-02T03:04:05+00:00
Clamped: no (within 1980-2107 range)
```

---

## Phase 2 — Content Rendering

### findings.csv

```csv
Category,Severity,SourceHost,Target,TimeStart,TimeEnd,ShortDescription
PortScan,High,192.168.1.100,10.0.0.1,1970-01-01T00:00:00.0000000Z,1970-01-01T00:01:00.0000000Z,Port scan detected

Warnings
Sample warning
```

### report.html (abbreviated)

```html
<!DOCTYPE html>
<html><head><meta charset="utf-8" />
<title>VulcansTrace Report</title>
<style>
body { background:#111; color:#eee; font-family:Segoe UI,Arial,sans-serif; }
...
</style></head><body>
<h1>VulcansTrace Analysis Report</h1>
<ul>
<li>Total lines: 2</li>
<li>Parsed lines: 2</li>
<li>Warnings: 1</li>
</ul>
...
<td>Port scan detected</td>
...
</body></html>
```

### summary.md

```markdown
# VulcansTrace Analysis Summary

* Total lines: 2
* Parsed lines: 2
* Warnings: 1

## Findings by Severity
* High: 1

## Findings
| Category | Severity | Source | Target | Start | End | Description |
|----------|----------|--------|--------|-------|-----|-------------|
| PortScan | High | 192.168.1.100 | 10.0.0.1 | ... | ... | Port scan detected |
```

### findings.json (abbreviated)

```json
{
  "metadata": {
    "toolName": "VulcansTrace Linux Edition",
    "version": "1.0.0",
    "exportTimestamp": "2024-01-02T03:04:05Z",
    "originalLogLines": 2,
    "parsedEvents": 2
  },
  "findings": [
    {
      "id": "...",
      "category": "PortScan",
      "severity": "High",
      "sourceHost": "192.168.1.100",
      "target": "10.0.0.1",
      "shortDescription": "Port scan detected"
    }
  ],
  "warnings": ["Sample warning"]
}
```

### findings.stix.json (abbreviated)

```json
{
  "type": "bundle",
  "id": "bundle--<guid>",
  "spec_version": "2.1",
  "objects": [
    { "type": "identity", "name": "VulcansTrace Linux Edition", ... },
    { "type": "ipv4-addr", "value": "192.168.1.100", ... },
    { "type": "ipv4-addr", "value": "10.0.0.1", ... },
    {
      "type": "observed-data",
      "first_observed": "1970-01-01T00:00:00Z",
      "last_observed": "1970-01-01T00:01:00Z",
      "object_refs": ["ipv4-addr--<guid1>", "ipv4-addr--<guid2>"],
      "labels": ["PortScan"]
    },
    { "type": "note", "content": "Category: PortScan\nSeverity: High\n...", ... }
  ]
}
```

No `malware` SDO is created because no finding has category `C2Channel`.

### log.txt

```
kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22
```

---

## Phase 3 — Per-File SHA-256 Hashing

```
findings.csv         → SHA-256 = <64-char hex>
findings.json        → SHA-256 = <64-char hex>
findings.stix.json   → SHA-256 = <64-char hex>
log.txt              → SHA-256 = <64-char hex>
report.html          → SHA-256 = <64-char hex>
summary.md           → SHA-256 = <64-char hex>
```

Note alphabetical ordering — `findings.*` comes before `log.txt` because `f` < `l`.

---

## Phase 4 — Manifest Assembly

```json
{
  "createdUtc": "2024-01-02T03:04:05Z",
  "files": [
    { "file": "findings.csv", "sha256": "abc...", "length": 234 },
    { "file": "findings.json", "sha256": "def...", "length": 567 },
    { "file": "findings.stix.json", "sha256": "789...", "length": 890 },
    { "file": "log.txt", "sha256": "012...", "length": 101 },
    { "file": "report.html", "sha256": "345...", "length": 456 },
    { "file": "summary.md", "sha256": "678...", "length": 321 }
  ],
  "warnings": ["Sample warning"]
}
```

---

## Phase 5 — HMAC-SHA256 Signing

```
manifest.hmac = HMAC-SHA256(manifestJson, signingKey) → <64-char lowercase hex>
```

---

## Phase 6 — ZIP Archive

```
Archive contents (8 entries):
  findings.csv           (compressed)
  findings.json          (compressed)
  findings.stix.json     (compressed)
  log.txt                (compressed)
  report.html            (compressed)
  summary.md             (compressed)
  manifest.json          (compressed)
  manifest.hmac          (compressed)

LastWriteTime for all entries: 2024-01-02T03:04:05Z
CompressionLevel: Optimal
```

---

## Verification (Recipient-Side)

```bash
# 1. Extract the archive
unzip evidence.zip -d evidence/

# 2. Read the HMAC
HMAC=$(cat evidence/manifest.hmac)

# 3. Recompute the HMAC (requires the shared key)
EXPECTED=$(openssl dgst -sha256 -hmac "0123456789abcdef0123456789abcdef" evidence/manifest.json | awk '{print $NF}')

# 4. Compare
[ "$HMAC" = "$EXPECTED" ] && echo "HMAC verified" || echo "TAMPERED"

# 5. Verify individual file hashes
sha256sum evidence/findings.csv
# Compare to the sha256 field in manifest.json
```

---

## Security Takeaways

- The complete evidence chain — from raw log to signed archive — is reproducible from the test case in [EvidenceBuilderTests.cs](../../../../VulcansTrace.Linux.Tests/Evidence/EvidenceBuilderTests.cs)
- The CSV output is safe to open in any spreadsheet application because the formula injection defense prepends `'` to any cell starting with `=`, `+`, `-`, or `@`
- The HTML report is safe to serve from a web share because all user content is `HtmlEncode`d
- The STIX bundle contains valid `ipv4-addr` objects because both `192.168.1.100` and `10.0.0.1` pass `IPAddress.TryParse`
- The HMAC can be verified with standard tools (`openssl dgst`) — no VulcansTrace installation is required on the verifier's machine
