> **Recurring implementation patterns** in the Avalonia UI subsystem and how they support correctness, testability, and reliability.

---

## Pattern 1 — ViewModelBase SetField with Equality Check

**Where:** [ViewModelBase.cs](../../../../VulcansTrace.Linux.Avalonia/ViewModels/ViewModelBase.cs)

Every property setter uses `SetField<T>` to check equality before raising `PropertyChanged`:

```csharp
public string LogText
{
    get => _logText;
    set
    {
        if (SetField(ref _logText, value))
        {
            if (string.IsNullOrWhiteSpace(value))
                AdvisorMessage = string.Empty;
            AnalyzeCommand.RaiseCanExecuteChanged();
        }
    }
}
```

The `SetField` pattern prevents:

- **Unnecessary re-renders** — if the value hasn't changed, no `PropertyChanged` event fires
- **Re-entrant command updates** — `RaiseCanExecuteChanged()` is only called when the backing field actually changes
- **Cascading property updates** — the `if (SetField(...))` block is a natural place for side effects like dependent property updates

---

## Pattern 2 — Command with Explicit CanExecute Guard

**Where:** [MainViewModel.cs:279-282](../../../../VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs), [EvidenceViewModel.cs:133-134](../../../../VulcansTrace.Linux.Avalonia/ViewModels/EvidenceViewModel.cs)

Every command defines a boolean guard method:

```csharp
private bool CanAnalyze() =>
    !_isBusy && !string.IsNullOrWhiteSpace(_logText) && _selectedIntensity != null;

private bool CanCancel() =>
    _isBusy && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested;
```

These guards are evaluated:

1. When the command is created (initial state)
2. When `RaiseCanExecuteChanged()` is called explicitly (after property changes)
3. By the Avalonia framework when the UI polls command state

This ensures buttons are disabled when the operation is invalid, preventing errors before they happen.

---

## Pattern 3 — Child ViewModel Delegation

**Where:** [MainViewModel.cs:348-351](../../../../VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs)

After analysis completes, MainViewModel delegates to each child ViewModel:

```csharp
Evidence.SetEvidenceContext(_lastResult, logSnapshot, lastAnalysisTimestampUtc);
Findings.LoadResults(result);
Timeline.LoadAnalysisResult(result);
```

Each child ViewModel:

- Owns its own `ObservableCollection` properties
- Manages its own state (counts, filters, positions)
- Clears previous data before loading new data (preventing stale results)

This delegation pattern ensures that MainViewModel never directly modifies child collections, maintaining encapsulation.

---

## Pattern 4 — Manual Filter Rebuild

**Where:** [FindingsViewModel.cs:206-217](../../../../VulcansTrace.Linux.Avalonia/ViewModels/FindingsViewModel.cs)

Filter changes trigger a complete rebuild of `FilteredItems`:

```csharp
private void ApplyFilters()
{
    FilteredItems.Clear();
    foreach (var item in Items)
    {
        if (FilterItem(item))
            FilteredItems.Add(item);
    }
}
```

`FilterItem` applies two independent filters:

1. **Severity filter** — `item.Severity >= SelectedSeverityFilter.MinSeverity`
2. **Text search** — `SearchText` matched case-insensitively against Category, SourceHost, Target, ShortDescription

Both filters must pass for the item to appear in `FilteredItems`. This is a simple AND composition that is easy to reason about and test.

---

## Pattern 5 — Event-Based Cross-ViewModel Communication

**Where:** [EvidenceViewModel.cs:78](../../../../VulcansTrace.Linux.Avalonia/ViewModels/EvidenceViewModel.cs), [MainViewModel.cs:255-257](../../../../VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs)

EvidenceViewModel raises events instead of calling parent methods:

```csharp
// EvidenceViewModel
public event EventHandler<string>? StatusChanged;
StatusChanged?.Invoke(this, "Exporting evidence bundle...");

// MainViewModel subscribes
Evidence.StatusChanged += (s, msg) => SummaryText = msg;
```

This pattern:

- Keeps EvidenceViewModel unaware of MainViewModel's existence
- Allows multiple subscribers (e.g., a future audit log ViewModel)
- Enables testing by subscribing to the event in the test and asserting the message

---

## Pattern 6 — CancellationToken Lifecycle Management

**Where:** [MainViewModel.cs:302-305](../../../../VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs), [EvidenceViewModel.cs:155-157](../../../../VulcansTrace.Linux.Avalonia/ViewModels/EvidenceViewModel.cs)

Both async operations follow the same CTS lifecycle:

```csharp
_cancellationTokenSource?.Dispose();
_cancellationTokenSource = new CancellationTokenSource();
var token = _cancellationTokenSource.Token;
```

And cleanup after completion:

```csharp
_cancellationTokenSource?.Dispose();
_cancellationTokenSource = null;
```

This prevents:

- **Leaked CTS instances** — each operation disposes the previous CTS before creating a new one
- **Stale cancellation** — a cancelled CTS is replaced with a fresh one on the next operation
- **Double cancellation** — the `CanCancel` guard checks `!_cancellationTokenSource.IsCancellationRequested`

---

## Pattern 7 — Log Snapshot for Thread Safety

**Where:** [MainViewModel.cs:305](../../../../VulcansTrace.Linux.Avalonia/ViewModels/MainViewModel.cs)

Before starting the background task, the log text is captured:

```csharp
var logSnapshot = _logText;
result = await Task.Run(() => AnalyzeWithOverrides(intensity, logSnapshot, token), token);
```

This prevents a race condition where:

1. User clicks Analyze
2. Task.Run begins on background thread
3. User modifies the text box during analysis
4. Background task reads the modified `_logText` instead of the original

The snapshot is immutable — the background task cannot be affected by UI changes after analysis starts.

---

## Pattern 8 — Severity-to-Brush Mapping

**Where:** [MainWindow.axaml.cs:165-175](../../../../VulcansTrace.Linux.Avalonia/MainWindow.axaml.cs)

The `GetSeverityBrush` method maps severity to color with a default fallback:

```csharp
private static IBrush GetSeverityBrush(Severity severity)
{
    return severity switch
    {
        Severity.Critical => new SolidColorBrush(Color.Parse("#ef4444")),
        Severity.High     => new SolidColorBrush(Color.Parse("#f97316")),
        Severity.Medium   => new SolidColorBrush(Color.Parse("#eab308")),
        Severity.Low      => new SolidColorBrush(Color.Parse("#22c55e")),
        _                 => new SolidColorBrush(Color.Parse("#64748b"))
    };
}
```

The `_` fallback ensures that:

- Any future severity level added to the enum is handled gracefully (gray instead of null/crash)
- The method is total — it never returns null, preventing `NullReferenceException` in rendering

---

## Pattern 9 — UI-Thread Dispatching for Dialogs

**Where:** [AvaloniaDialogService.cs:131-153](../../../../VulcansTrace.Linux.Avalonia/Services/AvaloniaDialogService.cs)

Dialog operations check and dispatch to the UI thread:

```csharp
private static Task<T> RunOnUiThreadAsync<T>(Func<Task<T>> action)
{
    if (Dispatcher.UIThread.CheckAccess())
        return action();

    return Dispatcher.UIThread.InvokeAsync(action);
}
```

This ensures that dialog creation and window showing always happen on the UI thread, regardless of whether the caller is on the UI thread (e.g., from a button click) or a background thread (e.g., from `ExportEvidenceAsync` continuation).

---

## Pattern 10 — Structured Test Verification with TestDialogService

**Where:** [MainViewModelTests.cs:194-208](../../../../VulcansTrace.Linux.Tests/Avalonia/MainViewModelTests.cs), [EvidenceViewModelTests.cs:160-179](../../../../VulcansTrace.Linux.Tests/Avalonia/EvidenceViewModelTests.cs)

Tests substitute `IDialogService` with a no-op implementation:

```csharp
private sealed class TestDialogService : IDialogService
{
    public void ShowMessage(string message, string title) { }
    public void ShowError(string message, string title) { }
    public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName)
        => Task.FromResult<string?>(null);
}
```

This enables:

- ViewModel testing without a Window or Avalonia runtime
- Verifying command enablement logic in isolation
- Testing export cancellation by returning `null` from `ShowSaveFileDialogAsync`

---

## Security Takeaways

- `SetField` equality checking prevents unnecessary UI updates that could mask race conditions in property change handlers
- Command `CanExecute` guards prevent invalid operations at the UI level — the engine never receives a null log or a null intensity
- Log snapshot capture prevents TOCTOU races where the analyst modifies input during background analysis
- CancellationToken lifecycle management (dispose old, create new, null after completion) prevents leaked resources and stale cancellation state
- UI-thread dispatching in dialogs prevents cross-thread exceptions that could crash the application during evidence export
- TestDialogService substitution proves that the ViewModel layer is fully testable without Avalonia framework dependencies
