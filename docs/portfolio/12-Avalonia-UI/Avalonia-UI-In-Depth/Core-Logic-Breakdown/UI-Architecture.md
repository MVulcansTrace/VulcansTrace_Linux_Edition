> **Step-by-step walkthrough of the Avalonia UI architecture**, from composition root to timeline rendering.

---

## The Engineering Problem

VulcansTrace has 13 detectors, a risk escalation engine, 6 evidence formatters, and a cryptographic integrity chain — but none of these components know about each other. The UI must compose them into a coherent workflow: the analyst pastes a log, clicks Analyze, sees results, filters them, and exports evidence. The architecture must wire every dependency, manage async execution, handle cancellation, and render a timeline — all without coupling the ViewModels to the Avalonia framework beyond what is strictly necessary.

---

## Architecture Overview

The UI follows a strict MVVM pattern with five layers:

```
Layer 1: Composition Root (MainWindow.axaml.cs)
         Wires all engine + evidence dependencies

Layer 2: MainViewModel (orchestrator)
         Owns AnalyzeCommand, CancelCommand, advisor messages
         Delegates to child VMs

Layer 3: Child ViewModels
         FindingsViewModel   -- filtering, search, parse errors
         EvidenceViewModel   -- export, signing key, file dialog
         TimelineViewModel   -- category grouping, normalization

Layer 4: Dialog Abstraction
         IDialogService      -- platform-agnostic interface
         AvaloniaDialogService -- Avalonia-native adapter

Layer 5: Code-Behind Rendering
         TimelineCanvas      -- imperative drawing via Canvas.Children.Add
```

---

## Layer 1 — Composition Root

**Source:** [MainWindow.axaml.cs:28-84](../../../../../VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs)

The constructor builds the full dependency graph:

```csharp
// Logging
var logSink = new DiagnosticsLogSink();
var logNormalizer = new LogNormalizer(logSink);

// Analysis profiles
var profileProvider = new AnalysisProfileProvider();

// 13 detectors in 3 tiers
var baselineDetectors = new IDetector[] { PortScan, Flood, Lateral, Beaconing, PolicyViolation, Novelty };
var linuxDetectors = new IDetector[] { FlagAnomaly, MacSpoofing, KernelModule, InterfaceHopping, UnusualPacketSize };
var advancedDetectors = new IDetector[] { C2Channel, PrivilegeEscalation };

// Engine chain
var riskEscalator = new RiskEscalator();
var analyzer = new SentryAnalyzer(logNormalizer, profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, riskEscalator, logSink);

// Evidence chain
var hasher = new IntegrityHasher();
var evidenceBuilder = new EvidenceBuilder(hasher, csv, markdown, html, json, stix);

// UI layer
var dialogService = new AvaloniaDialogService(this);
var viewModel = new MainViewModel(analyzer, evidenceBuilder, dialogService, profileProvider);
DataContext = viewModel;
```

Every dependency is a local variable — no container, no reflection, no hidden registrations. The constructor is the complete wiring specification.

---

## Layer 2 — MainViewModel Orchestration

**Source:** [MainViewModel.cs:289-359](../../../../../VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs)

The `AnalyzeAsync` method executes the analysis workflow:

```
1. Validate preconditions (intensity selected, log not empty)
2. Set IsBusy = true, update summary and advisor
3. Create CancellationTokenSource, snapshot LogText
4. Task.Run(() => AnalyzeWithOverrides(intensity, logSnapshot, token))
5. On success:
   a. Store _lastResult
   b. Compute lastAnalysisTimestampUtc
   c. Delegate to child VMs:
      - Evidence.SetEvidenceContext(result, log, timestamp)
      - Findings.LoadResults(result)
      - Timeline.LoadAnalysisResult(result)
   d. Build summary text (findings count, high/critical, errors, warnings)
   e. Update advisor message based on result characteristics
   f. Update bot intro text based on intensity level
6. Set IsBusy = false
```

**Cancellation handling:** `OperationCanceledException` is caught explicitly, resetting state to "Analysis cancelled by user."

**Error handling:** All non-cancellation exceptions are caught, showing the error message in the summary.

---

## Layer 3 — Child ViewModels

### FindingsViewModel

**Source:** [FindingsViewModel.cs:135-180](../../../../../VulcansTrace.Linux.Avalonia/ViewModels/FindingsViewModel.cs)

`LoadResults(AnalysisResult)`:

```
1. Clear Items, FilteredItems, ParseErrors, Warnings
2. Wrap each Finding in FindingItemViewModel, add to Items
3. Copy parse errors (capped at MaxParseErrorsToDisplay = 200)
4. Copy warnings
5. Compute FindingsCount, HighCriticalCount, WarningCount, ParseErrorCount
6. ApplyFilters() → rebuild FilteredItems
```

`ApplyFilters()` iterates `Items`, applying severity filter (`SelectedSeverityFilter.MinSeverity`) and text search (`SearchText` matched against Category, SourceHost, Target, ShortDescription).

### EvidenceViewModel

**Source:** [EvidenceViewModel.cs:119-194](../../../../../VulcansTrace.Linux.Avalonia/ViewModels/EvidenceViewModel.cs)

`ExportEvidenceAsync()`:

```
1. Validate _lastResult != null
2. GenerateNewSigningKey() → 32 random bytes via RandomNumberGenerator
3. BuildAsync(result, log, keyBytes, timestamp, token)
4. ShowSaveFileDialogAsync("Save Evidence Bundle", ...)
5. If path selected: File.WriteAllBytesAsync(path, zipBytes)
6. StatusChanged?.Invoke(this, statusMessage)
```

The signing key is stored as hex in `SigningKey` and displayed masked via `MaskedSigningKey`.

### TimelineViewModel

**Source:** [TimelineViewModel.cs:66-114](../../../../../VulcansTrace.Linux.Avalonia/ViewModels/TimelineViewModel.cs)

`LoadAnalysisResult(AnalysisResult)`:

```
1. Clear TimelineEntries, Categories
2. Extract all valid timestamps from findings
3. Compute MinTime/MaxTime across all findings
4. Group findings by Category → ordered Categories collection
5. Create TimelineEntry for each finding with valid time range
6. CalculateEntryPositions():
   a. Normalize start/end to 0–1 range against (MinTime, MaxTime)
   b. Assign row = categoryIndex
   c. TopPosition = TopPadding + row * (RowHeight + RowGap)
   d. CanvasHeight = TopPadding + (rowCount * RowHeight) + ((rowCount-1) * RowGap) + TopPadding
```

---

## Layer 4 — Dialog Abstraction

**Source:** [IDialogService.cs](../../../../../VulcansTrace.Linux.Avalonia/Services/IDialogService.cs), [AvaloniaDialogService.cs](../../../../../VulcansTrace.Linux.Avalonia/Services/AvaloniaDialogService.cs)

The interface defines three operations:

| Method | Implementation Detail |
|---|---|
| `ShowMessage` | Creates a modal Window with TextBlock + OK button, shown via `ShowDialog(owner)` |
| `ShowError` | Same as ShowMessage but `Foreground = Brushes.Firebrick` |
| `ShowSaveFileDialogAsync` | Uses `TopLevel.StorageProvider.SaveFilePickerAsync` with parsed filter string |

All UI operations are dispatched via `Dispatcher.UIThread.Post` to ensure thread safety when called from background tasks.

---

## Layer 5 — Timeline Canvas Rendering

**Source:** [MainWindow.axaml.cs:117-163](../../../../../VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs)

The `RenderTimeline` method draws the visualization:

```
1. Guard: TimelineCanvas != null, _timelineViewModel has entries, width > 0
2. Clear existing children
3. For each TimelineEntry:
   a. Compute pixel positions: start = leftPadding + (StartPosition * usableWidth)
   b. Create Border(barWidth, RowHeight, severityBrush, CornerRadius=3)
   c. Set tooltip: "Category | Severity\nDescription\nStartTime – EndTime"
   d. Canvas.SetLeft/Top → add to Children
```

Rendering is triggered by three events:
- `TimelineEntries.CollectionChanged`
- `Categories.CollectionChanged`
- `TimelineViewModel.PropertyChanged`
- `TimelineCanvas.SizeChanged` (resize handling)

---

## Async Execution Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    UI Thread                                 │
│                                                              │
│  AnalyzeCommand.Execute                                      │
│       │                                                      │
│       ├── IsBusy = true                                      │
│       ├── Create CancellationTokenSource                     │
│       │                                                      │
│       │    ┌──────────────────────────────────────────┐      │
│       │    │ ThreadPool (Task.Run)                     │      │
│       │    │                                           │      │
│       │    │  SentryAnalyzer.Analyze(logText,          │      │
│       │    │      intensity, token, profile)           │      │
│       │    │                                           │      │
│       │    │  Returns AnalysisResult                   │      │
│       │    └──────────────────────────────────────────┘      │
│       │                                                      │
│       ├── LoadResults → FindingsViewModel                    │
│       ├── LoadAnalysisResult → TimelineViewModel             │
│       ├── SetEvidenceContext → EvidenceViewModel              │
│       ├── Update summary + advisor                           │
│       ├── IsBusy = false                                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Takeaways

- The composition root is a flat, linear constructor — no reflection-based DI, no service locator, no hidden registrations that could inject malicious components
- Task.Run isolates the engine from the UI thread — a long-running or infinite analysis cannot freeze the application, and cancellation is always available
- The log snapshot (`var logSnapshot = _logText`) is captured before background execution, preventing race conditions if the user modifies the text box during analysis
- Dialog operations are dispatched to the UI thread via `Dispatcher.UIThread.Post`, preventing cross-thread access exceptions that could crash the application
- Timeline rendering guards against degenerate inputs (zero-width canvas, empty entries, negative bar widths) to prevent rendering failures that could mask analysis results
