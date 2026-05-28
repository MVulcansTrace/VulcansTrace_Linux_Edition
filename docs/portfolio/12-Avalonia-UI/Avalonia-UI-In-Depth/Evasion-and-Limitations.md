> **Known weaknesses, engineering limitations, and the improvement roadmap** for the Avalonia UI subsystem.

---

## Known Limitations

### No Dark Mode or Theme Switching

The application uses Avalonia's default light theme with hardcoded color values in the XAML. The timeline uses dark-themed colors (red, orange, yellow, green bars on a white canvas), which may have contrast issues in some accessibility contexts.

**Mitigation in context:** The timeline colors follow Material Design severity conventions (red = critical, orange = high, yellow = medium, green = low), which are widely recognized. A dark theme would require parameterizing all color values through a theme resource dictionary.

### No Virtualization for Large Finding Sets

`FindingsViewModel.FilteredItems` is a plain `ObservableCollection` bound to a `DataGrid`. For very large analysis results (hundreds or thousands of findings), the DataGrid will create UI elements for all visible rows without virtualization optimizations.

**Mitigation in context:** The upstream normalizer caps input at 100 million characters, and typical analyses produce tens to low hundreds of findings. The DataGrid's `AutoGenerateColumns="True"` with `IsReadOnly="True"` provides some built-in optimization.

### Single-Window Architecture

The application uses a single `MainWindow` with tab-based navigation (Findings, Timeline, Parse Errors, Warnings). There is no multi-window or multi-document support — the analyst can only work with one analysis at a time.

**Mitigation in context:** The application is designed for single-session incident triage, not concurrent multi-case management.

### Hardcoded Detector Registration

The 13 detectors are registered as fixed arrays in the composition root. Adding a new detector requires modifying `MainWindow.axaml.cs`.

**Mitigation in context:** This is intentional — the explicit registration makes the detector list auditable. A plugin system would introduce reflection and loading complexity that is not justified for the current detector count.

---

## Evasion and Attack Surfaces

### Malicious Log Content in UI Display

Findings from attacker-controlled log content are displayed in the DataGrid without HTML encoding (the DataGrid uses `TextBlock`, which renders plain text). However:

- The `FindingItemViewModel` exposes `Category`, `SourceHost`, `Target`, and `ShortDescription` as string properties
- If the DataGrid were replaced with a `WebView` or rich-text control, XSS could become a risk
- The current `TextBlock`-based rendering is inherently safe — `TextBlock.Text` does not interpret markup

**Remaining risk:** Tooltips on the timeline canvas are set via `ToolTip.SetTip(bar, tip)` with string interpolation. If a finding's description contains newline or tab characters, the tooltip rendering may be confusing but not exploitable.

### Signing Key Exposure via Clipboard

The "Copy signing key" button copies the full HMAC signing key to the system clipboard. On a multi-user or shared machine:

- Clipboard managers may retain the key in history
- Other applications may read the clipboard
- The key remains in clipboard memory until overwritten

**Mitigation in context:** The analyst is expected to clear the clipboard after copying the key. A future improvement could use a timed clipboard clear (e.g., 30 seconds after copy).

### Cancellation Race Condition

If the analyst clicks Cancel and immediately clicks Analyze again, the old `CancellationTokenSource` is disposed and a new one is created. The old background task receives the cancellation token and should throw `OperationCanceledException`. However:

- If the task has already passed its cancellation checkpoint, it may complete normally
- The `IsBusy` flag is set to `false` in the cancellation handler, which could race with the new analysis setting `IsBusy = true`

**Mitigation in context:** The `_cancellationTokenSource?.Dispose()` before creating a new CTS ensures the old token is signaled. The sequential nature of `AnalyzeAsync` (which awaits the task before proceeding) prevents concurrent analysis runs.

### Timeline Rendering on Resize

The timeline canvas re-renders on `SizeChanged`, but the re-render clears all children and redraws from scratch. For large timelines with many entries, this causes a brief visual flash.

**Mitigation in context:** The rendering is synchronous and fast (simple `Border` creation). The flash is cosmetic, not functional.

---

## Improvement Roadmap

| Enhancement | Priority | Description |
|---|---|---|
| Dark mode / theme resource dictionary | Medium | Parameterize all color values for theme switching and accessibility |
| DataGrid row virtualization | Medium | Enable `VirtualizingStackPanel` for large finding sets |
| Timed clipboard clear for signing key | Medium | Clear clipboard 30 seconds after key copy |
| Drag-and-drop log file loading | Low | Accept `.log` files via drag-and-drop on the text area |
| Analysis history | Low | Store previous analysis results in memory for multi-session comparison |
| Export progress reporting | Low | Report evidence build progress (file rendering, hashing, ZIP creation) via IProgress |
| Timeline zoom and pan | Low | Add mouse wheel zoom and drag-to-pan for dense timelines |
| Finding detail panel | Low | Click a DataGrid row to show full finding details in a side panel |
| Keyboard shortcuts | Low | Ctrl+Enter to analyze, Ctrl+S to export, Ctrl+C to cancel |

---

## Security Takeaways

- The DataGrid uses `TextBlock` for rendering, which is inherently safe against markup injection — no XSS risk from attacker-controlled log content in findings
- Timeline tooltips use string interpolation, not markup interpretation — newlines and special characters are displayed verbatim
- Signing key clipboard exposure is the primary operational risk — a timed clipboard clear would reduce the window of exposure
- The single-window, single-session architecture limits the attack surface to one analysis workflow at a time
- Hardcoded detector registration prevents runtime injection of malicious detectors at the cost of requiring code changes to add new ones
