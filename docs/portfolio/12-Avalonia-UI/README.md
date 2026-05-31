# Avalonia UI

The Avalonia UI subsystem provides a cross-platform desktop interface for VulcansTrace, composing the full analysis engine, local Security Agent, evidence builder, and interactive timeline into a single-window MVVM application. It is the primary way analysts interact with the system without using the CLI.

Documentation is organized for two audiences:

- **Recruiters and hiring managers** who need a fast, high-level view of what this subsystem does and why it matters
- **Technical reviewers** who want to inspect the actual implementation choices, architectural details, and test evidence

## Start Here

- [Technical Snapshot](./Avalonia-UI-Summary/Technical-Snapshot.md) — one-page overview of the subsystem, its design, and where the proof lives
- [Quick Reference](./Avalonia-UI-Summary/Quick-Reference.md) — ViewModel responsibilities, timeline colors, command catalog, and dialog API at a glance
- [Why This Matters](./Avalonia-UI-In-Depth/Why-This-Matters.md) — the engineering problem this subsystem solves and the principles behind it
- [UI Architecture](./Avalonia-UI-In-Depth/Core-Logic-Breakdown/UI-Architecture.md) — step-by-step walkthrough of the composition root and rendering pipeline
- [Design Decisions](./Avalonia-UI-In-Depth/Design-Decisions.md) — rationale for key architectural choices
- [Code Patterns](./Avalonia-UI-In-Depth/Code-Patterns.md) — recurring implementation patterns and how they support reliability
- [Attack Scenario](./Avalonia-UI-In-Depth/Attack-Scenario.md) — worked example showing a full analysis-to-export workflow from a real log
- [Evasion and Limitations](./Avalonia-UI-In-Depth/Evasion-and-Limitations.md) — known weaknesses and the improvement roadmap
- [Analyst Workflow and Standards](./Avalonia-UI-In-Depth/Analyst-Workflow-and-Standards.md) — capability mapping, NIST CSF alignment, and analyst workflow

## System Capabilities

- **Full engine composition root** — MainWindow.axaml.cs wires LogNormalizer, 13 detectors across 3 tiers, RiskEscalator, SentryAnalyzer, Security Agent scanners/rules/policy, IntegrityHasher, 5 formatters, and EvidenceBuilder in one constructor
- **MVVM with Security Agent child workflow** — MainViewModel orchestrates Findings, Evidence, Timeline, Suppressions, Rule Coverage, and Agent ViewModels without making those child ViewModels own each other's state
- **Context-sensitive advisor** — MainViewModel generates triage guidance based on finding counts, severity distribution, warnings, and parse errors
- **Timeline canvas rendering** — severity-colored horizontal bars grouped by category, normalized to 0–1 range, with dynamic canvas height calculation
- **Evidence export with key generation** — 32-byte random signing key via RandomNumberGenerator, save-file dialog, clipboard copy, status event bubbling
- **Platform-agnostic dialog abstraction** — IDialogService interface backed by AvaloniaDialogService adapter, enabling test-time substitution with no UI dependency
- **Severity color scheme** — Critical (#ef4444), High (#f97316), Medium (#eab308), Low (#22c55e), Unknown (#64748b)
- **Schedule management tab** — DataGrid of recurring audit schedules with Add/Edit/Delete/Run Now/Install Cron actions, cron status indicators, and selection preservation across refreshes
- **Machine role dropdown** — hot-swap roles (Workstation, Server, LabBox, Router, DevMachine) without restarting the app

## Implementation Evidence

- [MainWindow.axaml.cs](../../../VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs) — composition root, engine chain wiring, Security Agent wiring, timeline canvas rendering
- [MainWindow.axaml](../../../VulcansTrace.Linux.Avalonia/MainWindow.axaml) — XAML layout: summary badges, bot advisor, log input, findings DataGrid, timeline tab
- [MainViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs) — central orchestrator: AnalyzeCommand, CancelCommand, advisor messages, child VM delegation
- [FindingsViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/FindingsViewModel.cs) — items/filtered collections, severity filter, text search, parse error capping at 200
- [EvidenceViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/EvidenceViewModel.cs) — export flow, 32-byte key generation, save dialog, clipboard copy, StatusChanged event
- [AgentViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/AgentViewModel.cs) — Security Agent chat, audit history, filtering, and export handoff
- [ScheduleViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/ScheduleViewModel.cs) — recurring schedule management, cron status, selection preservation, and on-demand execution
- [ScheduleEditWindow.axaml](../../../VulcansTrace.Linux.Avalonia/Views/ScheduleEditWindow.axaml) — schedule editor dialog
- [TimelineViewModel.cs](../../../VulcansTrace.Linux.Avalonia/ViewModels/TimelineViewModel.cs) — category grouping, 0–1 normalization, row positioning, canvas height calculation
- [AvaloniaDialogService.cs](../../../VulcansTrace.Linux.Avalonia/Services/AvaloniaDialogService.cs) — native Avalonia dialog adapter with UI-thread dispatching
- [IDialogService.cs](../../../VulcansTrace.Linux.Avalonia/Services/IDialogService.cs) — platform-agnostic dialog interface
- [MainViewModelTests.cs](../../../VulcansTrace.Linux.Tests/Avalonia/MainViewModelTests.cs) — command gating and engine wiring tests
- [FindingsViewModelTests.cs](../../../VulcansTrace.Linux.Tests/Avalonia/FindingsViewModelTests.cs) — load, filter, search, and parse-error cap tests
- [EvidenceViewModelTests.cs](../../../VulcansTrace.Linux.Tests/Avalonia/EvidenceViewModelTests.cs) — context gating and command enablement tests
