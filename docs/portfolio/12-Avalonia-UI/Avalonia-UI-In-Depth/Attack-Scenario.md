> **Worked example:** a full analysis-to-export workflow from a real iptables log, showing how each UI component processes the results.

---

## Scenario

An analyst receives an iptables log from a compromised web server. The log contains a port scan, a SYN flood, and periodic beaconing to a C2 server. The analyst pastes the log into VulcansTrace, selects "High - Deep Hunt / Forensics" intensity, and clicks Analyze. After reviewing the findings, the analyst exports a signed evidence bundle.

---

## Input

The analyst pastes the following iptables log into the text box:

```
kernel: Jan 19 10:15:32 webserver IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22
kernel: Jan 19 10:15:33 webserver IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54322 DPT=80
kernel: Jan 19 10:15:34 webserver IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54323 DPT=443
kernel: Jan 19 10:15:35 webserver IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54324 DPT=3306
kernel: Jan 19 10:15:36 webserver IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=54325 DPT=8080
kernel: Jan 19 10:15:37 webserver IN=eth0 SRC=192.168.1.200 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=80 SYN
kernel: Jan 19 10:15:37 webserver IN=eth0 SRC=192.168.1.200 DST=10.0.0.1 PROTO=TCP SPT=12346 DPT=80 SYN
kernel: Jan 19 10:15:37 webserver IN=eth0 SRC=192.168.1.200 DST=10.0.0.1 PROTO=TCP SPT=12347 DPT=80 SYN
kernel: Jan 19 10:15:38 webserver IN=eth0 SRC=10.20.30.40 DST=10.0.0.1 PROTO=TCP SPT=4444 DPT=8443
kernel: Jan 19 10:20:38 webserver IN=eth0 SRC=10.20.30.40 DST=10.0.0.1 PROTO=TCP SPT=4444 DPT=8443
kernel: Jan 19 10:25:38 webserver IN=eth0 SRC=10.20.30.40 DST=10.0.0.1 PROTO=TCP SPT=4444 DPT=8443
```

---

## Step 1 — Composition Root Wiring

When the application starts, `MainWindow.axaml.cs` constructs the full dependency graph:

```
LogNormalizer → 13 detectors (6 baseline + 5 Linux + 2 advanced)
  → RiskEscalator → SentryAnalyzer

IntegrityHasher → 5 formatters → EvidenceBuilder

AvaloniaDialogService(this) → MainViewModel(analyzer, evidenceBuilder, dialogService, profileProvider)

DataContext = viewModel
```

The XAML bindings are now live: `{Binding Findings.FindingsCount}`, `{Binding Timeline.CanvasHeight}`, `{Binding Evidence.ExportEvidenceCommand}`, etc.

---

## Step 2 — Analysis Execution

The analyst selects "High - Deep Hunt / Forensics" and clicks Analyze.

`MainViewModel.AnalyzeAsync` executes:

```
IsBusy = true
SummaryText = "Analyzing log..."
CancellationTokenSource = new()
logSnapshot = _logText

Task.Run(() => AnalyzeWithOverrides(IntensityLevel.High, logSnapshot, token))
  → SentryAnalyzer.Analyze(logText, High, token, profile)
  → Returns AnalysisResult { Findings: [3 findings], Warnings: [], ParseErrorCount: 0 }
```

**Results:**

| Category | Severity | SourceHost | Target | Time Range |
|---|---|---|---|---|
| PortScan | High | 192.168.1.100 | 10.0.0.1 | 10:15:32 – 10:15:36 |
| Flood | Critical | 192.168.1.200 | 10.0.0.1 | 10:15:37 – 10:15:37 |
| Beaconing | High | 10.20.30.40 | 10.0.0.1 | 10:15:38 – 10:25:38 |

---

## Step 3 — Child ViewModel Delegation

MainViewModel delegates the result to each child ViewModel:

### FindingsViewModel.LoadResults

```
Items → [PortScan/High, Flood/Critical, Beaconing/High]
FilteredItems → (all 3, no filters applied)
FindingsCount = 3
HighCriticalCount = 3
WarningCount = 0
ParseErrorCount = 0
```

### TimelineViewModel.LoadAnalysisResult

```
MinTime = 10:15:32, MaxTime = 10:25:38
Categories = [Beaconing, Flood, PortScan] (alphabetical)

TimelineEntries:
  PortScan:    StartPosition=0.0,  EndPosition=0.0067  → row 2, gray bar
  Flood:       StartPosition=0.008, EndPosition=0.008   → row 1, red bar
  Beaconing:   StartPosition=0.01,  EndPosition=1.0     → row 0, orange bar

CanvasHeight = 6 + (3 × 22) + (2 × 8) + 6 = 92px
```

### EvidenceViewModel.SetEvidenceContext

```
_lastResult = AnalysisResult
_logSnapshot = raw log text
_analysisTimestamp = 10:25:38 UTC
ExportEvidenceCommand.RaiseCanExecuteChanged() → enabled
```

---

## Step 4 — Summary and Advisor

MainViewModel computes:

```
SummaryText = "Found 3 issues, 3 High/Critical."
AdvisorMessage = "Multiple High/Critical issues detected. Triage those first, then sweep the rest."
BotIntroText = "High intensity: deep hunt mode, including subtle and borderline patterns."
```

---

## Step 5 — Timeline Rendering

`MainWindow.RenderTimeline` draws on the canvas:

```
Width = ~800px (right panel), usableWidth = 784px

Beaconing row (y=6):   bar from x=8 to x=792, width=784, color=#f97316 (High)
Flood row (y=36):      bar from x=14 to x=14, width=2 (min), color=#ef4444 (Critical)
PortScan row (y=64):   bar from x=8 to x=13, width=5, color=#f97316 (High)

Canvas height = 92px
```

Each bar has a tooltip: "Beaconing | High\nPeriodic beaconing detected\n2024-01-19T10:15:38.0000000Z – 2024-01-19T10:25:38.0000000Z"

---

## Step 6 — Interactive Filtering

The analyst wants to focus on the port scan. They type "port" in the search box.

`FindingsViewModel.ApplyFilters`:

```
FilterItem(PortScan) → Category.Contains("port") → true → included
FilterItem(Flood)    → no match → excluded
FilterItem(Beaconing) → no match → excluded

FilteredItems = [PortScan/High only]
```

The DataGrid updates to show a single row.

---

## Step 7 — Evidence Export

The analyst clicks "Export Evidence".

`EvidenceViewModel.ExportEvidenceAsync`:

```
1. GenerateNewSigningKey() → 32 random bytes
   SigningKey = "A1B2C3D4E5F6..."; MaskedSigningKey = "****************"

2. EvidenceBuilder.BuildAsync(result, logSnapshot, keyBytes, timestamp, token)
   → Renders 6 files (CSV, HTML, Markdown, JSON, STIX, raw log)
   → Computes SHA-256 per file
   → Assembles manifest.json
   → Signs manifest with HMAC-SHA256
   → Packs into ZIP → byte[]

3. AvaloniaDialogService.ShowSaveFileDialogAsync("Save Evidence Bundle", "ZIP|*.zip", "VulcansTrace_Evidence.zip")
   → Analyst selects: /home/analyst/incident-2024-01-19.zip

4. File.WriteAllBytesAsync(path, zipBytes)
   → 8-entry ZIP written to disk

5. StatusChanged?.Invoke(this, "Evidence bundle saved.")
   → MainViewModel.SummaryText = "Evidence bundle saved."

6. AvaloniaDialogService.ShowMessage("Evidence bundle saved.", "VulcansTrace")
```

---

## Step 8 — Signing Key Copy

The analyst clicks "Copy signing key" to store the HMAC verification key separately.

`EvidenceViewModel.CopySigningKeyAsync`:

```
Clipboard.SetTextAsync("A1B2C3D4E5F6...")
ShowMessage("Signing key copied to clipboard.", "VulcansTrace")
```

The analyst now has:
- The evidence ZIP archive at `/home/analyst/incident-2024-01-19.zip`
- The signing key in their clipboard for later HMAC verification

---

## Verification Workflow (Post-Export)

```bash
# Extract and verify the evidence archive
unzip incident-2024-01-19.zip -d incident/

# Verify HMAC (using the key from clipboard)
STORED_HMAC=$(cat incident/manifest.hmac)
SIGNING_KEY_HEX="A1B2C3D4E5F6..."
EXPECTED=$(openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SIGNING_KEY_HEX" \
    incident/manifest.json | awk '{print $NF}')
[ "$STORED_HMAC" = "$EXPECTED" ] && echo "PASS: HMAC verified" || echo "FAIL: TAMPERED"

# Verify individual file hashes
sha256sum incident/findings.csv
# Compare to manifest.json["files"][0]["sha256"]
```

---

## Security Takeaways

- The complete workflow — from log paste to signed archive — is exercised by the tests in [MainViewModelTests.cs](../../../../VulcansTrace.Linux.Tests/Avalonia/MainViewModelTests.cs) and [EvidenceViewModelTests.cs](../../../../VulcansTrace.Linux.Tests/Avalonia/EvidenceViewModelTests.cs)
- The signing key is generated per-export with `RandomNumberGenerator` (CSPRNG), ensuring each evidence archive has a unique key
- The log snapshot prevents the analyst from modifying the input after analysis starts, ensuring the exported evidence matches the displayed findings
- The timeline visualization uses severity colors consistent with the findings table, preventing misinterpretation of severity levels
- Filtered views do not affect the exported evidence — the archive always contains all findings, regardless of the UI filter state
