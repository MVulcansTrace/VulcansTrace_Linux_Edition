using System;
using System.Collections.Generic;
using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A clickable chip on an <see cref="AnalysisSummaryCardMessageViewModel"/>: a count
/// that navigates to the Findings view with the matching filter applied. Mirrors the
/// KPI strip cards, which use the same command parameters.
/// </summary>
public sealed class SummaryChipViewModel
{
    /// <summary>Gets the chip text, e.g. "Findings 9".</summary>
    public required string Label { get; init; }

    /// <summary>Gets the stable automation id, e.g. "SummaryFindingsChip".</summary>
    public required string AutomationId { get; init; }

    /// <summary>Gets the screen-reader-friendly chip name, unique among actionables.</summary>
    public required string AccessibleName { get; init; }

    /// <summary>Gets the parameter passed to the navigate command (e.g. "high-critical").</summary>
    public object? CommandParameter { get; init; }
}

/// <summary>
/// Structured "analysis complete" card posted to the agent thread (UI v2 Phase 2):
/// a divider header with run metadata, a one-line outcome summary, and KPI
/// click-through chips. Rendered by its own DataTemplate selected on runtime type.
/// </summary>
public sealed class AnalysisSummaryCardMessageViewModel : AgentMessageViewModel
{
    /// <summary>Gets the divider header, e.g. "Analysis · Jul 18 16:42 · Medium · Workstation".</summary>
    public required string HeaderLine { get; init; }

    /// <summary>Gets the one-line outcome, e.g. "Done. 9 findings — 7 High/Critical, 1 warning."</summary>
    public required string SummaryLine { get; init; }

    /// <summary>Gets the click-through chips (same actions as the KPI strip).</summary>
    public IReadOnlyList<SummaryChipViewModel> Chips { get; init; } = Array.Empty<SummaryChipViewModel>();

    /// <summary>Gets the command invoked by chips; the chip supplies the command parameter.</summary>
    public ICommand? NavigateCommand { get; init; }
}
