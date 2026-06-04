> **Why the Avalonia UI subsystem exists, the engineering problem it solves, and the design principles behind it.**

---

## The Engineering Problem

VulcansTrace's analysis engine is a library — it normalizes logs, runs detectors, escalates risk, and packages evidence, but it has no user interface. For an analyst to use the system, they need:

1. **A way to provide input** — paste a raw firewall log into the application
2. **Control over analysis parameters** — choose scan intensity and optional overrides like port scan event caps
3. **Visibility into results** — see findings, severity distribution, parse errors, and warnings at a glance
4. **Interactive filtering** — narrow findings by severity or text search without re-running analysis
5. **Visual timeline** — see when events occurred relative to each other, grouped by category
6. **Evidence export** — generate a cryptographically signed archive with one click
7. **Guidance** — get context-sensitive advice on what to do with the results

Without a UI, the analyst must use the CLI runner, which provides no interactive filtering, no timeline visualization, and no advisor messages. The UI subsystem bridges this gap by composing the entire engine into a desktop application.

---

## Why This Subsystem

The Avalonia UI subsystem addresses these requirements with:

- **A composition root** that wires the full engine chain in one place — 14 detectors, risk escalation, evidence packaging — visible and auditable
- **MVVM separation** that keeps all logic in testable ViewModels, with the code-behind limited to canvas rendering and ViewModel hooking
- **Async analysis** that offloads the engine to `Task.Run` with `CancellationToken` support, keeping the UI responsive during multi-second analysis runs
- **Child ViewModel delegation** where MainViewModel orchestrates but Findings, Evidence, and Timeline ViewModels own their own state and commands
- **Platform-agnostic dialog abstraction** (`IDialogService`) that enables unit testing without Avalonia windows

The design is intentionally **offline-first and dependency-free**: no network calls, no telemetry, no external services. The application is a self-contained desktop tool that an analyst can run on an air-gapped machine.

---

## Design Principles

### Composition Root, Not DI Container

Every dependency is constructed explicitly in `MainWindow.axaml.cs`. No reflection, no service locator, no container configuration. This makes the wiring:

- **Visible** — one file shows the complete dependency graph
- **Debuggable** — breakpoints in the constructor trace every registration
- **Auditable** — no hidden registrations that could inject a malicious detector or formatter

### ViewModels Own All Logic

The code-behind (`MainWindow.axaml.cs`) contains only two responsibilities:

1. **Timeline canvas rendering** — Avalonia's Canvas requires imperative drawing; this cannot be expressed in XAML bindings
2. **ViewModel hooking** — subscribing to `TimelineViewModel` events to trigger re-renders

All other state, commands, and business logic live in ViewModels that are testable without a Window.

### Commands Reflect Preconditions

Every `RelayCommand` has an explicit `CanExecute` predicate:

- `AnalyzeCommand`: disabled when `IsBusy`, empty log, or no intensity selected
- `CancelCommand`: disabled when not busy or already cancelled
- `ExportEvidenceCommand`: disabled when no analysis result exists or export is in progress
- `CopySigningKeyCommand`: disabled when no signing key has been generated

This prevents invalid operations at the UI level rather than requiring error handling in the engine.

### One-Directional Parent–Child Communication

MainViewModel creates and owns child ViewModels. Communication flows:

- **Parent → Child**: method calls (`Findings.LoadResults`, `Timeline.LoadAnalysisResult`, `Evidence.SetEvidenceContext`)
- **Child → Parent**: events (`Evidence.StatusChanged`)

Children never reference the parent. This prevents circular dependencies and makes each ViewModel independently testable.

---

## Where It Fits in the Pipeline

The Avalonia UI is the **interaction layer** that sits above the entire VulcansTrace pipeline:

```
Analyst Input (paste log, choose intensity)
    --> Avalonia UI (12)           <-- you are here
    --> Log Normalization (01)
    --> Detectors (02-07, 13-15)
    --> Risk Escalation (08)
    --> Results back to UI
    --> Evidence Packaging (09) on export
    --> ZIP archive written to disk
```

The UI does not modify analysis results — it presents them, filters them, and triggers export. All security decisions are made by the engine, not the UI.

---

## Security Takeaways

- The UI is a thin interaction layer over the engine — it adds no security logic, removes no engine protections, and cannot bypass detector findings
- Composition root wiring is explicit and reflection-free — no hidden service registrations that could substitute malicious implementations
- Signing key generation uses `RandomNumberGenerator` (CSPRNG), ensuring the HMAC signing key for evidence archives is cryptographically strong
- The masked key display and explicit clipboard copy prevent accidental key exposure through screen sharing or screenshots
- Parse error capping at 200 entries prevents a malformed-log denial-of-service from consuming all available UI memory
- Async analysis with cancellation prevents the UI from becoming unresponsive, which could otherwise force the analyst to kill the process and lose results
