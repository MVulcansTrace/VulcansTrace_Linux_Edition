> **At-a-glance reference** for the Avalonia UI subsystem: ViewModel responsibilities, timeline colors, command catalog, dialog API, and key bindings.

---

## ViewModel Responsibilities

| ViewModel | Responsibility |
|---|---|
| `MainViewModel` | Central orchestrator: LogText, SummaryText, AdvisorMessage, IsBusy, SelectedIntensity. AnalyzeCommand/CancelCommand. Delegates to child VMs |
| `FindingsViewModel` | Items/FilteredItems collections, severity filter, text search, parse errors (capped at 200), warnings display |
| `EvidenceViewModel` | Export evidence flow, 32-byte signing key generation, save file dialog, clipboard copy. StatusChanged event |
| `TimelineViewModel` | Groups findings by category, normalizes to 0–1 range, assigns row positions, computes canvas height |
| `ComplianceScorecardViewModel` | Binds `ComplianceScorecard` to the Compliance tab: overall score, family DataGrid, trend points, and direction text |
| `FindingItemViewModel` | Adapts a `Finding` for UI display (Category, Severity, SourceHost, Target, TimeStart, TimeEnd, ShortDescription) |
| `IntensityOption` | DTO binding intensity levels to UI dropdown (Low/Medium/High) |
| `SeverityFilterOption` | DTO binding severity thresholds to filter dropdown (All / High+Critical / Critical only) |
| `ViewModelBase` | INotifyPropertyChanged with generic `SetField<T>` equality check |
| `RelayCommand` | ICommand implementation with manual `RaiseCanExecuteChanged()` |
| `AsyncRelayCommand` | Async ICommand with exception handler callback |

---

## Command Catalog

| Command | Owner | CanExecute Condition | Action |
|---|---|---|---|
| `AnalyzeCommand` | MainViewModel | `!IsBusy && !string.IsNullOrWhiteSpace(LogText) && SelectedIntensity != null` | Runs `SentryAnalyzer.Analyze` on background thread, delegates results to child VMs |
| `CancelCommand` | MainViewModel | `IsBusy && CancellationTokenSource != null && !IsCancellationRequested` | Calls `CancellationTokenSource.Cancel()` |
| `ExportEvidenceCommand` | EvidenceViewModel | `LastResult != null && !IsBusy` | Generates 32-byte key, builds ZIP, shows save dialog, writes to disk |
| `CancelExportCommand` | EvidenceViewModel | `IsBusy && CancellationTokenSource != null && !IsCancellationRequested` | Cancels in-progress export |
| `CopySigningKeyCommand` | EvidenceViewModel | `!string.IsNullOrEmpty(SigningKey)` | Copies full hex key to system clipboard |

---

## Timeline Severity Colors

| Severity | Hex Color | Brush Usage |
|---|---|---|
| Critical | `#ef4444` | `new SolidColorBrush(Color.Parse("#ef4444"))` |
| High | `#f97316` | `new SolidColorBrush(Color.Parse("#f97316"))` |
| Medium | `#eab308` | `new SolidColorBrush(Color.Parse("#eab308"))` |
| Low | `#22c55e` | `new SolidColorBrush(Color.Parse("#22c55e"))` |
| Unknown | `#64748b` | Default fallback for unrecognized severity values |

---

## Dialog API (IDialogService)

| Method | Return | Description |
|---|---|---|
| `ShowMessage(message, title)` | `void` | Non-modal information dialog |
| `ShowError(message, title)` | `void` | Non-modal error dialog with Firebrick-styled text |
| `ShowSaveFileDialogAsync(title, filter, defaultFileName)` | `Task<string?>` | Modal save dialog; returns file path or `null` on cancel |

---

## Advisor Message Logic

| Condition | Advisor Message |
|---|---|
| `ParseErrorCount > 0 && totalFindings == 0` | "Fix parse errors in the log and re-run to surface findings." |
| `totalFindings == 0` | "No findings at this intensity. Try High intensity or adjust filters." |
| `highCritical >= 3` | "Multiple High/Critical issues detected. Triage those first, then sweep the rest." |
| `highCritical > 0` | "Prioritize High/Critical findings, then review remaining events." |
| `warnings.Count > 0` | "Findings detected; review warnings for any truncated or skipped activity." |
| Default (findings present) | "Findings detected. Review sources/targets to determine next steps." |
| Any + `parseErrorCount > 0` | Appends: "Fix remaining parse errors to improve coverage." |

---

## Timeline Layout Constants

| Constant | Value | Purpose |
|---|---|---|
| `DefaultRowHeight` | 22px | Height of each timeline bar |
| `DefaultRowGap` | 8px | Vertical spacing between category rows |
| `DefaultTopPadding` | 6px | Top padding before first row |
| `leftPadding` (code-behind) | 8px | Left margin for bar start |
| `rightPadding` (code-behind) | 8px | Right margin for bar end |
| Minimum bar width | 2px | `Math.Max(2, end - start)` ensures visibility |

---

## Composition Root Wiring

```
MainWindow.axaml.cs constructor:
    DiagnosticsLogSink → LogNormalizer
    AnalysisProfileProvider
    6 baseline detectors → IDetector[]
    5 Linux detectors    → IDetector[]
    2 advanced detectors → IDetector[]
    RiskEscalator → SentryAnalyzer(logNormalizer, profileProvider, baseline, linux, advanced, riskEscalator, logSink)
    Agent scanners + rules + DefaultRulePolicyProvider(JsonRulePolicyStore) → SecurityAgent(MachineRole.Workstation)
    IntegrityHasher → CsvFormatter, MarkdownFormatter, HtmlFormatter, JsonFormatter, StixFormatter → EvidenceBuilder
    AvaloniaDialogService(this) → MainViewModel(analyzer, evidenceBuilder, dialogService, profileProvider, agent, stores)
```

---

## Security Takeaways

- All commands use explicit `CanExecute` predicates — no action is possible when preconditions are unmet, preventing invalid state transitions
- The signing key is generated with `RandomNumberGenerator` (CSPRNG), displayed masked, and only revealed on explicit clipboard copy
- Dialog service abstraction isolates ViewModels from platform-specific windowing APIs, reducing the attack surface
- Parse error display is capped at 200 entries to prevent memory exhaustion from corrupted log input
- Timeline rendering guards against zero-width canvases (`width <= 0`) and negative bar widths (`Math.Max(2, ...)`)
