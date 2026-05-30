> **Rationale for the key architectural and engineering decisions** in the Avalonia UI subsystem.

---

## Composition Root in Code-Behind (Not DI Container)

**Decision:** `MainWindow.axaml.cs` constructs every dependency explicitly as local variables.

**Rationale:**

- The UI is the only entry point — there is no need for scoped lifetimes, interceptor support, or modular registration
- Every dependency is visible in one composition block — a reviewer can audit the complete engine, agent, persistence, policy, and evidence wiring without searching multiple configuration files
- No DI container means no reflection overhead at startup and no hidden registrations that could inject a malicious detector or formatter
- The constructor is the single source of truth for the dependency graph

**Trade-off:** The constructor has many local variables. This is acceptable because it runs once per application lifecycle and each variable maps directly to a real dependency.

## Desktop Role Defaults Are Explicit

**Decision:** The desktop composition currently creates the Security Agent with `MachineRole.Workstation` and a `DefaultRulePolicyProvider` backed by `JsonRulePolicyStore`.

**Rationale:**

- Workstation is the least surprising default for a desktop app running on an analyst's machine
- Local JSON policy can still override individual tuned rules without adding UI complexity
- The explicit constructor argument makes the current limitation obvious until a role selector exists

---

## MVVM Without a Framework

**Decision:** Hand-written `ViewModelBase`, `RelayCommand`, and `INotifyPropertyChanged` implementation rather than using CommunityToolkit.Mvvm, ReactiveUI, or Prism.

**Rationale:**

- The application has 10 ViewModel-layer classes and 5 command properties — the overhead of a framework is not justified
- `ViewModelBase.SetField<T>` uses `EqualityComparer<T>.Default.Equals` for equality checking, which is correct for all value types, strings, and reference types
- `RelayCommand` is a minimal `ICommand` with explicit `RaiseCanExecuteChanged()` — no weak-reference subscriptions, no memory leak risk from event handlers
- No generated code (no source generators) — the implementation is fully inspectable

**Trade-off:** No `[ObservableProperty]`, `[RelayCommand]` source generation. Every property and command is written manually, which is more code but fully transparent.

---

## Manual Filtering (Not CollectionView)

**Decision:** `FindingsViewModel.ApplyFilters` clears and rebuilds `FilteredItems` on every filter change.

**Rationale:**

- Avalonia's `CollectionView` has threading restrictions — modifying the source collection from a background thread can cause `InvalidOperationException`
- `FilteredItems` is a separate `ObservableCollection<FindingItemViewModel>` owned by the ViewModel, not tied to any framework filtering mechanism
- Manual rebuild gives deterministic behavior: the filtered set is always the exact result of applying `FilterItem` to every item in `Items`
- No hidden sorting, grouping, or filtering that could reorder findings without the ViewModel's knowledge

**Trade-off:** O(n) rebuild on every filter change. For the expected finding counts (tens to low hundreds), this is instantaneous. For thousands of findings, a virtualized or incremental approach would be needed.

---

## StatusChanged Event (Not Direct Parent Reference)

**Decision:** `EvidenceViewModel` raises a `StatusChanged` event that `MainViewModel` subscribes to, rather than EvidenceViewModel holding a reference to MainViewModel.

**Rationale:**

- One-directional dependency: MainViewModel knows about EvidenceViewModel, but EvidenceViewModel does not know about MainViewModel
- EvidenceViewModel can be tested in isolation — the test subscribes to `StatusChanged` instead of mocking a parent
- Multiple subscribers could listen to the event (e.g., a future logging or telemetry component) without modifying EvidenceViewModel

---

## Intensity Selection as a Dropdown (Not Auto-Detection)

**Decision:** The analyst must explicitly select Low, Medium, or High intensity before analysis.

**Rationale:**

- Auto-detection of intensity would require heuristics that may not match the analyst's intent — an analyst investigating a known breach needs High intensity regardless of log size
- The intensity label itself is guidance: "Low - Critical Threat Triage", "Medium - Investigation Review", "High - Deep Hunt / Forensics"
- Profile overrides (e.g., `PortScanMaxEntriesPerSource`) are available in the Advanced expander for fine-tuning
- The selected intensity updates the bot intro text, providing context about what the chosen level does

---

## Timeline Canvas (Not Charting Library)

**Decision:** Timeline is drawn with imperative `Canvas.Children.Add` using `Border` elements, not a charting library.

**Rationale:**

- The timeline visualization is simple: horizontal bars grouped by category with severity colors
- A charting library (LiveCharts, ScottPlot, OxyPlot) would add a dependency for a compact, application-specific rendering feature
- Canvas rendering gives pixel-perfect control over bar positioning, tooltips, and colors
- The `TimelineViewModel` normalizes positions to 0–1 range, making the rendering resolution-independent

**Trade-off:** The canvas does not support zoom, pan, or hover highlighting natively. These would require additional code-behind logic.

---

## Signing Key Display Masked by Default

**Decision:** The signing key is displayed as `MaskedSigningKey` (all asterisks) with an explicit "Copy signing key" button.

**Rationale:**

- Evidence HMAC signing keys are sensitive — anyone with the key can verify (or forge) an evidence archive
- Screen sharing, screenshots, and shoulder surfing could expose a plaintext key
- The masked display provides a visual indicator that a key exists (non-empty length) without revealing the content
- Clipboard copy is an intentional action, making the analyst aware that they are accessing the key

---

## Parse Error Capping at 200

**Decision:** `FindingsViewModel` limits displayed parse errors to 200 entries.

**Rationale:**

- A severely corrupted log could produce one parse error per line — a 100,000-line log would create 100,000 `ObservableCollection` entries
- Each entry is a string displayed in a `ListBox`, consuming UI memory and layout time
- 200 entries is sufficient for the analyst to identify the pattern of errors (e.g., "all lines use an unsupported format")
- The "...and N more parse errors not shown" suffix communicates that additional errors exist without displaying them

---

## Security Takeaways

- Explicit composition root wiring prevents supply-chain attacks through DI container configuration — no reflection-based registration means no externally-injected implementations
- Hand-written MVVM infrastructure avoids framework source generators that could introduce unexpected behavior — every line of the ViewModel base class is inspectable
- Manual filtering avoids Avalonia CollectionView threading issues that could cause silent data corruption in the filtered view
- Masked signing key display prevents accidental exposure through screen sharing or screenshots during incident response collaboration
- Parse error capping prevents denial-of-service through extremely malformed log input that could exhaust UI memory
