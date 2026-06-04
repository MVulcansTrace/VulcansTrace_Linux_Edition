> **Analyst workflow standards and regulatory alignment** for the Avalonia UI subsystem: capability mapping, NIST CSF alignment, analyst workflow steps, and security takeaways.

---

## Capability Mapping

| Capability | Analyst Function | Relevant Standard |
|---|---|---|
| Log paste and intensity selection | Data collection and scoping | NIST CSF DE.CM-1 |
| Async analysis with cancellation | Monitoring and assessment | NIST CSF DE.AE-1 |
| Findings display with severity badges | Event triage and prioritization | NIST CSF RS.AN-1 |
| Severity filtering and text search | Investigation and analysis | NIST CSF DE.AE-2 |
| Timeline visualization by category | Temporal correlation | NIST CSF DE.AE-3 |
| Context-sensitive advisor messages | Analyst guidance and decision support | NIST CSF RS.AN-2 |
| Evidence export with HMAC signing | Evidence preservation and integrity | NIST CSF RS.MI-1 |
| Signing key generation (CSPRNG) | Cryptographic key management | NIST SP 800-57 |
| Signing key clipboard copy | Key distribution to verification tools | NIST SP 800-57 |
| Parse error display (capped at 200) | Data quality assessment | NIST CSF ID.AM-3 |
| Warning display | Analysis confidence assessment | NIST CSF DE.AE-4 |
| Platform-agnostic dialog abstraction | UI testability and portability | Software engineering best practice |
| Composition root wiring | Supply chain integrity (no reflection DI) | NIST CSF ID.SC-1 |

---

## NIST CSF Mapping

| NIST CSF Function | Category | Control | Avalonia UI Implementation |
|---|---|---|---|
| Identify (ID) | Asset Management | ID.AM-3: Organizational communication and data flows are mapped | Log input box accepts raw firewall logs; intensity dropdown defines the analysis scope and detector set |
| Detect (DE) | Alignment | DE.CM-1: The network is monitored to detect potential cybersecurity events | `AnalyzeCommand` triggers `SentryAnalyzer.Analyze` with 14 detectors across 3 intensity tiers |
| Detect (DE) | Analysis | DE.AE-1: Potential incidents are identified | `FindingsViewModel.LoadResults` populates severity-badged finding items for analyst review |
| Detect (DE) | Analysis | DE.AE-2: Incident information is aggregated | `SummaryText` aggregates findings count, high/critical count, parse errors, and warnings into a single status line |
| Detect (DE) | Analysis | DE.AE-3: Incident data is analyzed | `TimelineViewModel` groups findings by category and normalizes to a temporal 0–1 range for visual correlation |
| Detect (DE) | Analysis | DE.AE-4: Severity of incidents is estimated | `MainViewModel.UpdateAdvisorMessage` provides context-sensitive triage guidance based on severity distribution |
| Respond (RS) | Analysis | RS.AN-1: Notifications are established | Severity filter dropdown and text search enable the analyst to narrow findings to actionable subsets |
| Respond (RS) | Analysis | RS.AN-2: Incident impact is understood | Advisor messages guide the analyst: "Multiple High/Critical issues detected. Triage those first, then sweep the rest." |
| Respond (RS) | Mitigation | RS.MI-1: Incidents are contained | `EvidenceViewModel.ExportEvidenceAsync` generates a signed evidence archive for incident response handoff |
| Respond (RS) | Mitigation | RS.MI-2: Incidents are mitigated | The analyst can adjust intensity and re-analyze to find additional threats missed at lower intensity levels |

---

## Analyst Workflow Steps

### Step 1 — Data Collection

The analyst opens VulcansTrace and pastes a raw iptables log into the text area. The UI provides immediate visual feedback that the log is present (the Analyze button becomes enabled).

### Step 2 — Scope Definition

The analyst selects an analysis intensity:

| Intensity | Use Case | Detectors Active |
|---|---|---|
| Low | Critical threat triage | Baseline detectors only |
| Medium | Investigation review | Baseline + Linux-specific detectors |
| High | Deep hunt / forensics | All 14 detectors including C2 and privilege escalation |

The analyst can optionally set `PortScanMaxEntriesPerSource` in the Advanced expander to cap port scan findings per source IP.

### Step 3 — Analysis Execution

The analyst clicks Analyze. The UI shows:

- Progress indicator (indeterminate ProgressBar + "Working...")
- Cancel button becomes enabled
- Summary updates to "Analyzing log..."
- Advisor updates to "Analyzing..."

### Step 4 — Result Review

Analysis completes. The UI displays:

- **Summary badges**: Findings count, High/Critical count, Warnings count, Parse Errors count
- **Findings tab**: DataGrid with all findings (Category, Severity, SourceHost, Target, TimeStart, TimeEnd, ShortDescription)
- **Timeline tab**: Canvas with severity-colored bars grouped by category, with tooltips showing full event details
- **Advisor message**: Context-sensitive guidance based on the result characteristics

### Step 5 — Investigation

The analyst uses interactive filtering to narrow the findings:

- **Severity filter dropdown**: All / High & Critical only / Critical only
- **Search text box**: Filters by Category, SourceHost, Target, or ShortDescription
- **Timeline**: Visual temporal correlation across categories

### Step 6 — Evidence Export

The analyst clicks "Export Evidence". The UI:

1. Generates a 32-byte HMAC signing key (displayed masked)
2. Builds a 6-format ZIP archive (CSV, HTML, Markdown, JSON, STIX, raw log)
3. Computes SHA-256 per file and HMAC-SHA256 over the manifest
4. Shows a save-file dialog
5. Writes the ZIP to the selected path

### Step 7 — Key Distribution

The analyst clicks "Copy signing key" to copy the HMAC key to the clipboard for later verification.

---

## Analyst Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        VulcansTrace Analyst Workflow                     │
│                                                                          │
│  ┌──────────────┐                                                       │
│  │ 1. PASTE LOG │                                                       │
│  │    into text  │                                                       │
│  │    area       │                                                       │
│  └──────┬───────┘                                                       │
│         │                                                                │
│         ▼                                                                │
│  ┌──────────────────┐                                                   │
│  │ 2. SELECT INTENSITY│                                                 │
│  │  Low / Med / High  │                                                 │
│  │  + optional config  │                                                 │
│  └──────┬───────────┘                                                   │
│         │                                                                │
│         ▼                                                                │
│  ┌──────────────┐     ┌──────────────┐                                  │
│  │ 3. ANALYZE   │────►│   CANCEL     │                                  │
│  │  (AnalyzeBtn) │     │  (CancelBtn) │                                  │
│  └──────┬───────┘     └──────────────┘                                   │
│         │ (async)                                                       │
│         ▼                                                                │
│  ┌─────────────────────────────────────────────┐                        │
│  │ 4. REVIEW RESULTS                            │                        │
│  │  ┌─────────┐ ┌──────────┐ ┌────────────┐   │                        │
│  │  │ Findings │ │ Timeline │ │ Errors/    │   │                        │
│  │  │ DataGrid │ │ Canvas   │ │ Warnings   │   │                        │
│  │  └────┬────┘ └──────────┘ └────────────┘   │                        │
│  │       │                                     │                        │
│  │  ┌────▼──────────────────────────────┐      │                        │
│  │  │ Advisor: "Triage High/Critical..."│      │                        │
│  │  └───────────────────────────────────┘      │                        │
│  └──────┬──────────────────────────────────────┘                        │
│         │                                                                │
│         ▼                                                                │
│  ┌──────────────────┐                                                   │
│  │ 5. FILTER & INVESTIGATE │                                            │
│  │  Severity dropdown       │                                            │
│  │  Text search             │                                            │
│  │  Timeline correlation    │                                            │
│  └──────┬───────────┘                                                   │
│         │                                                                │
│         ▼                                                                │
│  ┌──────────────────┐     ┌───────────────────┐                         │
│  │ 6. EXPORT EVIDENCE │────►│ 7. COPY SIGNING   │                         │
│  │  (ExportBtn)       │     │    KEY (CopyBtn)  │                         │
│  │  → ZIP archive     │     │  → Clipboard      │                         │
│  └───────────────────┘     └───────────────────┘                         │
│                                                                          │
│  ────────────────────────────────────────────────────────────────────── │
│  Evidence Archive: 6 formats + manifest.json + manifest.hmac            │
│  Verification: sha256sum + openssl dgst -sha256 -mac HMAC -macopt hexkey│
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Security Takeaways

- The UI workflow maps directly to the NIST CSF Detect and Respond functions — the analyst collects, scopes, analyzes, investigates, and preserves evidence in a structured, repeatable process
- Composition root wiring ensures that the same detectors and evidence pipeline used by the CLI are used by the UI — no detector is skipped or bypassed in the interactive workflow
- Evidence export generates a cryptographically signed archive that is verifiable without VulcansTrace, supporting cross-tool incident response collaboration
- The signing key is generated per-export with a CSPRNG, ensuring that each archive has a unique key that cannot be derived from previous exports
- Advisor messages provide NIST CSF-aligned triage guidance, reducing the risk of analyst error in prioritizing findings
- Parse error and warning visibility ensures the analyst is aware of data quality issues that could affect analysis coverage — hidden errors would violate the principle of transparent analysis
