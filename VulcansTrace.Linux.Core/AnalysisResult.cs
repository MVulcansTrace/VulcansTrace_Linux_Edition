namespace VulcansTrace.Linux.Core;

/// <summary>
/// Contains the complete results of a log analysis operation.
/// </summary>
/// <remarks>
/// This record stores parsed log entries, detected findings, warnings, and statistics
/// from the analysis process.
/// </remarks>
public sealed record AnalysisResult
{
    private int _totalLines;
    private int _parsedLines;
    private int _parseErrorCount;
    private int _skippedLineCount;
    private IReadOnlyList<string> _parseErrors = Array.Empty<string>();
    private IReadOnlyList<UnifiedEvent> _entries = Array.Empty<UnifiedEvent>();
    private IReadOnlyList<Finding> _findings = Array.Empty<Finding>();
    private IReadOnlyList<string> _warnings = Array.Empty<string>();
    private IReadOnlyList<SuppressionSummary> _activeSuppressions = Array.Empty<SuppressionSummary>();
    private DateTime _timeRangeStart;
    private DateTime _timeRangeEnd;

    /// <summary>Gets the total number of lines in the input log.</summary>
    public int TotalLines
    {
        get => _totalLines;
        init => _totalLines = ValidateNonNegative(value, nameof(TotalLines));
    }

    /// <summary>Gets the number of lines that were successfully parsed.</summary>
    public int ParsedLines
    {
        get => _parsedLines;
        init => _parsedLines = ValidateNonNegative(value, nameof(ParsedLines));
    }

    /// <summary>Gets the number of parse errors encountered.</summary>
    public int ParseErrorCount
    {
        get => _parseErrorCount;
        init => _parseErrorCount = ValidateNonNegative(value, nameof(ParseErrorCount));
    }

    /// <summary>Gets the number of lines skipped because they lacked required fields (SRC/DST/PROTO). Tracked via <see cref="ParseResult.SkippedLineCount"/> and surfaced as a summary warning.</summary>
    public int SkippedLineCount
    {
        get => _skippedLineCount;
        init => _skippedLineCount = ValidateNonNegative(value, nameof(SkippedLineCount));
    }

    /// <summary>Gets the collection of parse errors.</summary>
    public IReadOnlyList<string> ParseErrors
    {
        get => _parseErrors;
        init => _parseErrors = value ?? throw new ArgumentNullException(nameof(ParseErrors));
    }

    /// <summary>Gets the collection of normalized log entries.</summary>
    public IReadOnlyList<UnifiedEvent> Entries
    {
        get => _entries;
        init => _entries = value ?? throw new ArgumentNullException(nameof(Entries));
    }

    /// <summary>Gets the collection of security findings.</summary>
    public IReadOnlyList<Finding> Findings
    {
        get => _findings;
        init => _findings = value ?? throw new ArgumentNullException(nameof(Findings));
    }

    /// <summary>Gets the collection of warnings generated during analysis.</summary>
    public IReadOnlyList<string> Warnings
    {
        get => _warnings;
        init => _warnings = value ?? throw new ArgumentNullException(nameof(Warnings));
    }

    /// <summary>Gets the number of findings suppressed by user configuration.</summary>
    public int SuppressedCount { get; init; }

    /// <summary>Gets active suppressions at the time of export.</summary>
    public IReadOnlyList<SuppressionSummary> ActiveSuppressions
    {
        get => _activeSuppressions;
        init => _activeSuppressions = value ?? throw new ArgumentNullException(nameof(ActiveSuppressions));
    }

    /// <summary>Human-readable report of which data sources were available during the audit.</summary>
    public string CapabilityReport { get; init; } = string.Empty;

    /// <summary>Optional CIS compliance scorecard generated from agent rule results.</summary>
    public Compliance.ComplianceScorecard? Scorecard { get; init; }

    /// <summary>
    /// Gets the start of the time range covered by the analysis.
    /// When using <c>with</c> expressions to modify time range properties, set
    /// <see cref="TimeRangeStart"/> before <see cref="TimeRangeEnd"/> to ensure
    /// cross-field validation runs correctly.
    /// </summary>
    public DateTime TimeRangeStart
    {
        get => _timeRangeStart;
        init
        {
            ValidateTimeRange(value, _timeRangeEnd, nameof(TimeRangeStart));
            _timeRangeStart = value;
        }
    }

    /// <summary>Gets the end of the time range covered by the analysis.</summary>
    public DateTime TimeRangeEnd
    {
        get => _timeRangeEnd;
        init
        {
            ValidateTimeRange(_timeRangeStart, value, nameof(TimeRangeEnd));
            _timeRangeEnd = value;
        }
    }

    private static int ValidateNonNegative(int value, string name)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(name, value, $"{name} cannot be negative.");
        }

        return value;
    }

    private static void ValidateTimeRange(DateTime start, DateTime end, string name)
    {
        if (start != default && end != default && start > end)
        {
            throw new ArgumentException("TimeRangeStart must be <= TimeRangeEnd.", name);
        }
    }
}
