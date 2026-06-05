> **1 page:** the Avalonia UI subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

The Avalonia UI subsystem is the desktop interface for VulcansTrace. It is a single-window MVVM application built on Avalonia (a cross-platform XAML framework for .NET). MainWindow.axaml.cs acts as the composition root, wiring the complete analysis engine — LogNormalizer, 14 detectors across baseline, Linux-specific, and advanced tiers, RiskEscalator, SentryAnalyzer — the local Security Agent — scanners, rules, suppression store, audit history, and role-aware policy — plus the evidence pipeline — IntegrityHasher, report formatters, EvidenceBuilder — in one constructor. The application provides paste-in log analysis with intensity selection, live posture audit chat, real-time findings display with severity filtering and text search, a timeline canvas with category-grouped severity-colored bars, and one-click evidence export with cryptographic signing key generation.

---

## Key Metrics

| Metric | Value |
|---|---|
| ViewModel files | 17, including MainViewModel, Agent, Findings, Evidence, Timeline, Suppressions, Rule Coverage, Rule Catalog, commands, and option/item models |
| Dialog abstraction | 1 interface + 1 Avalonia adapter |
| Avalonia test files | 21, covering main UI, agent UI, findings, evidence, suppressions, coverage, compliance/risk scorecards, audit diff, log diff, live stream, and async commands |
| Detectors wired in composition root | 13 (6 baseline + 5 Linux + 2 advanced) |
| Agent stores wired in composition root | Suppressions, audit history, rule policy, and remediation session JSON stores with in-memory fallbacks |
| Timeline severity colors | 5 (Critical=#ef4444, High=#f97316, Medium=#eab308, Low=#22c55e, Unknown=#64748b) |
| Remediation session UI | Remediation Sessions expander with ListBox selection, Resume, and Delete actions; chat commands `list my sessions`, `show sessions`, `resume session <id>` |

---

## Why It Matters

- **The UI is the analyst's entry point to the entire engine** — without it, VulcansTrace is a library with no interactive workflow
- **MVVM with composition root ensures testability** — every ViewModel accepts dependencies via constructor injection, and the dialog service is hidden behind an interface for test doubles
- **Async analysis with cancellation prevents UI freezes** — `Task.Run` offloads the engine to a background thread, and `CancellationTokenSource` enables clean abort
- **Manual filtering (not CollectionView) gives full control** — FindingsViewModel rebuilds `FilteredItems` on every filter change, avoiding Avalonia CollectionView threading pitfalls
- **Evidence export integrates the full packaging pipeline** — a single button click generates a 32-byte signing key, builds the ZIP archive, and writes it to disk through a save-file dialog
- **Compliance tab surfaces formal CIS scorecard** — overall pass/warn/fail badge, per-family DataGrid, and trend bar chart make manager-readable compliance posture visible without leaving the app
- **Log Diff Window enables forensic timeline comparison** — analysts can compare two log files side-by-side with color-coded state badges (`Unchanged`, `Added`, `Removed`, `Changed`) for both connection patterns and findings, without leaving the desktop app
- **Remediation Sessions expander preserves workflow state** — analysts can resume or delete persisted guided remediation sessions without losing context between app restarts

---

## Key Evidence

- [MainWindow.axaml.cs](../../../../VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs) — composition root wiring 14 detectors + engine + Security Agent + evidence builder
- [MainViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs) — central orchestrator with async analysis, advisor messages
- [FindingsViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/FindingsViewModel.cs) — filtering, search, parse error capping
- [EvidenceViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/EvidenceViewModel.cs) — export flow, key generation, clipboard
- [TimelineViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/TimelineViewModel.cs) — category grouping, normalization, canvas height
- [ComplianceScorecardViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/ComplianceScorecardViewModel.cs) — compliance tab binding and trend visualization
- [LogDiffViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/LogDiffViewModel.cs) — log diff result binding
- [LogDiffWindow.axaml](../../../../VulcansTrace.Linux.Avalonia/Views/LogDiffWindow.axaml) — diff results window with Events and Findings DataGrids
- [AgentView.axaml](../../../../VulcansTrace.Linux.Avalonia/AgentView.axaml) — chat panel UI including Remediation Sessions expander
- [AgentViewModel.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs) — Security Agent command/state coordinator with session list/resume/delete
- [AvaloniaDialogService.cs](../../../../VulcansTrace.Linux.Avalonia/Services/AvaloniaDialogService.cs) — native dialog adapter with UI-thread dispatch
- [IDialogService.cs](../../../../VulcansTrace.Linux.Avalonia/Services/IDialogService.cs) — platform-agnostic dialog interface
- [MainViewModelTests.cs](../../../../VulcansTrace.Linux.Tests/Avalonia/MainViewModelTests.cs) — command gating tests
- [FindingsViewModelTests.cs](../../../../VulcansTrace.Linux.Tests/Avalonia/FindingsViewModelTests.cs) — filter and search tests
- [EvidenceViewModelTests.cs](../../../../VulcansTrace.Linux.Tests/Avalonia/EvidenceViewModelTests.cs) — export gating tests

---

## Key Design Choices

- **Composition root in code-behind** — MainWindow.axaml.cs constructs every dependency explicitly rather than using a DI container, making the engine, agent, policy, persistence, and evidence wiring visible in one file
- **ViewModelBase with SetField pattern** — generic `SetField<T>` checks equality via `EqualityComparer<T>.Default` before raising `PropertyChanged`, preventing unnecessary re-renders
- **RelayCommand with manual RaiseCanExecuteChanged** — commands expose `RaiseCanExecuteChanged()` called explicitly when dependent properties change (e.g., `IsBusy`, `LogText`, `SelectedIntensity`), avoiding memory leaks from automatic re-query subscriptions
- **StatusChanged event for cross-ViewModel communication** — EvidenceViewModel raises `StatusChanged` instead of coupling directly to MainViewModel, keeping the parent–child relationship one-directional
- **Manual filter rebuild** — FindingsViewModel clears and repopulates `FilteredItems` on every filter/search change rather than using Avalonia's `CollectionView`, avoiding threading exceptions and giving deterministic filter behavior
- **Timeline normalization to 0–1 range** — all finding time positions are normalized against the global min/max time range, making the canvas resolution-independent
- **Parse error capping at 200** — FindingsViewModel limits displayed parse errors to 200 entries with a "...and N more" suffix, preventing UI memory issues on badly corrupted logs

---

## Security Takeaways

- The composition root is the single point where all engine, agent, policy, persistence, and evidence dependencies are wired — no hidden registrations or reflection-based DI that could inject malicious implementations
- Signing keys are generated with `RandomNumberGenerator.Create()` (CSPRNG), not `Random`, ensuring cryptographic quality for evidence HMAC signing
- The masked signing key display (`new string('*', length)`) prevents shoulder-surfing exposure of the full key in the UI
- Dialog service abstraction prevents ViewModels from directly accessing Window or StorageProvider, reducing the attack surface for UI-level vulnerabilities
- Parse error capping prevents denial-of-service from extremely malformed log input that could produce thousands of error entries
