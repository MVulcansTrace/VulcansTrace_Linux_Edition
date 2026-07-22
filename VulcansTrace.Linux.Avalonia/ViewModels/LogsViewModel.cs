using System;
using System.Collections.Generic;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Read-only view model for the System → Logs page: the raw log that fed the last analysis
/// (the "raw log browser") plus the per-line skipped-lines detail (lines the parser could not
/// turn into events). Populated via <see cref="Load"/> from the same analysis-complete points
/// that feed the evidence/timeline views; empty until a paste-and-analyze run supplies a raw log.
/// </summary>
public sealed class LogsViewModel : ViewModelBase
{
    private string _rawLog = string.Empty;
    private IReadOnlyList<SkippedLine> _skippedLines = Array.Empty<SkippedLine>();
    private string _statusMessage = "No raw log available — paste a firewall log and analyze to populate this view.";
    private string _skippedLinesHeader = "Skipped lines (0)";

    /// <summary>Gets the raw log text that fed the last analysis (empty when none, e.g. an agent audit).</summary>
    public string RawLog
    {
        get => _rawLog;
        private set => SetField(ref _rawLog, value);
    }

    /// <summary>Gets the lines the parser skipped, with line number + raw text + reason.</summary>
    public IReadOnlyList<SkippedLine> SkippedLines
    {
        get => _skippedLines;
        private set => SetField(ref _skippedLines, value);
    }

    /// <summary>True when a raw log is available to display.</summary>
    public bool HasRawLog => !string.IsNullOrEmpty(_rawLog);

    /// <summary>True when the last analysis skipped one or more lines.</summary>
    public bool HasSkippedLines => _skippedLines.Count > 0;

    /// <summary>Number of lines in the raw log (0 when none).</summary>
    public int RawLogLineCount { get; private set; }

    /// <summary>Human-readable status line for the page header.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    /// <summary>Header text for the skipped-lines section, e.g. "Skipped lines (3)".</summary>
    public string SkippedLinesHeader
    {
        get => _skippedLinesHeader;
        private set => SetField(ref _skippedLinesHeader, value);
    }

    /// <summary>
    /// Loads the page from an analysis result + the raw log snapshot that produced it.
    /// </summary>
    /// <param name="result">The analysis result (its <see cref="AnalysisResult.SkippedLines"/> drives the detail).</param>
    /// <param name="rawLog">The raw log text; empty when the analysis had no raw log (e.g. an agent audit).</param>
    public void Load(AnalysisResult? result, string rawLog)
    {
        RawLog = rawLog ?? string.Empty;
        RawLogLineCount = string.IsNullOrEmpty(rawLog)
            ? 0
            : rawLog.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length;
        SkippedLines = result?.SkippedLines ?? Array.Empty<SkippedLine>();
        SkippedLinesHeader = $"Skipped lines ({SkippedLines.Count})";
        StatusMessage = HasRawLog
            ? $"Raw log: {RawLogLineCount} line{(RawLogLineCount == 1 ? string.Empty : "s")}; {SkippedLines.Count} skipped line{(SkippedLines.Count == 1 ? string.Empty : "s")}."
            : "No raw log available — paste a firewall log and analyze to populate this view.";
    }
}
