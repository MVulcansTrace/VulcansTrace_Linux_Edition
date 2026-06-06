using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Logging;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Engine;

/// <summary>
/// Orchestrates the complete log analysis pipeline from normalization through detection and risk escalation.
/// </summary>
/// <remarks>
/// This is the main entry point for Linux firewall log analysis. It coordinates:
/// <list type="bullet">
/// <item>Log normalization via <see cref="LogNormalizer"/></item>
/// <item>Threat detection via multiple <see cref="IDetector"/> implementations (both baseline and Linux-specific)</item>
/// <item>Risk escalation via <see cref="RiskEscalator"/></item>
/// <item>Severity filtering based on the analysis profile</item>
/// </list>
/// The analyzer runs a dual-layer detection approach:
/// 1. Baseline detectors (ported from Windows version)
/// 2. Linux Deep Inspection detectors (Linux-specific threats)
/// </summary>
public sealed class SentryAnalyzer
{
    private const int MaxParseErrorsToKeep = 500;

    private readonly LogNormalizer _logNormalizer;
    private readonly AnalysisProfileProvider _profileProvider;
    private readonly IReadOnlyList<IDetector> _baselineDetectors;
    private readonly IReadOnlyList<IDetector> _linuxDetectors;
    private readonly IReadOnlyList<IDetector> _advancedDetectors;
    private readonly RiskEscalator _riskEscalator;
    private readonly ILogSink _logSink;

    /// <summary>
    /// Initializes a new instance of the <see cref="SentryAnalyzer"/> class.
    /// </summary>
    /// <param name="logNormalizer">The log normalizer instance.</param>
    /// <param name="profileProvider">Provider for analysis profiles.</param>
    /// <param name="baselineDetectors">Collection of baseline threat detectors (Windows-tested logic).</param>
    /// <param name="linuxDetectors">Collection of Linux-specific threat detectors.</param>
    /// <param name="riskEscalator">The risk escalation engine.</param>
    /// <param name="advancedDetectors">Collection of advanced threat detectors.</param>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    public SentryAnalyzer(
        LogNormalizer logNormalizer,
        AnalysisProfileProvider profileProvider,
        IEnumerable<IDetector> baselineDetectors,
        IEnumerable<IDetector> linuxDetectors,
        IEnumerable<IDetector> advancedDetectors,
        RiskEscalator riskEscalator,
        ILogSink? logSink = null)
    {
        _logNormalizer = logNormalizer ?? throw new ArgumentNullException(nameof(logNormalizer));
        _profileProvider = profileProvider ?? throw new ArgumentNullException(nameof(profileProvider));
        _baselineDetectors = baselineDetectors == null
            ? throw new ArgumentNullException(nameof(baselineDetectors))
            : baselineDetectors.ToList();
        _linuxDetectors = linuxDetectors == null
            ? throw new ArgumentNullException(nameof(linuxDetectors))
            : linuxDetectors.ToList();
        _advancedDetectors = advancedDetectors == null
            ? throw new ArgumentNullException(nameof(advancedDetectors))
            : advancedDetectors.ToList();
        _riskEscalator = riskEscalator ?? throw new ArgumentNullException(nameof(riskEscalator));
        _logSink = logSink ?? NullLogSink.Instance;
    }

    /// <summary>
    /// Performs a complete analysis of the provided log data.
    /// </summary>
    /// <param name="rawLog">The raw log file content to analyze.</param>
    /// <param name="intensity">The analysis intensity level (Low, Medium, High).</param>
    /// <param name="cancellationToken">Token to cancel the analysis operation.</param>
    /// <param name="overrideProfile">Optional custom profile to use instead of the standard intensity profile.</param>
    /// <param name="referenceDate">Optional reference date for timestamp inference (e.g., iptables year). Defaults to <c>null</c> (uses <c>DateTime.Now</c>).</param>
    /// <returns>An <see cref="Core.AnalysisResult"/> containing normalized events, findings, and statistics.</returns>
    public Core.AnalysisResult Analyze(string rawLog, IntensityLevel intensity, CancellationToken cancellationToken, AnalysisProfile? overrideProfile = null, DateTime? referenceDate = null)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Normalize log data (detects format and parses accordingly)
        var normalized = _logNormalizer.Normalize(rawLog, referenceDate, cancellationToken);
        if (normalized.Errors.Length > 0)
        {
            _logSink.Write(LogLevel.Warning, $"Normalization reported {normalized.Errors.Length} parse errors.");
        }

        var errorsToKeep = normalized.Errors.Take(MaxParseErrorsToKeep).ToList();
        var events = normalized.Events.ToList();

        if (events.Count == 0)
        {
            return new Core.AnalysisResult
            {
                TotalLines = normalized.TotalLines,
                ParseErrorCount = normalized.Errors.Length,
                SkippedLineCount = normalized.SkippedLineCount,
                ParsedLines = 0,
                TimeRangeStart = DateTime.MinValue,
                TimeRangeEnd = DateTime.MinValue,
                ParseErrors = errorsToKeep,
                Entries = events,
                Findings = Array.Empty<Core.Finding>(),
                Warnings = normalized.Warnings
            };
        }

        var profile = overrideProfile ?? _profileProvider.GetProfile(intensity);
        var warnings = new List<string>();
        if (normalized.Warnings.Length > 0)
        {
            warnings.AddRange(normalized.Warnings);
        }

        var findings = RunDetectors(events, profile, warnings, cancellationToken);

        return BuildAnalysisResult(
            events,
            findings,
            warnings,
            normalized.TotalLines,
            normalized.Errors.Length,
            normalized.SkippedLineCount,
            errorsToKeep);
    }

    /// <summary>
    /// Performs analysis directly on pre-parsed events, bypassing log normalization.
    /// Use this overload when the events are already structured (e.g., from a live stream).
    /// </summary>
    public Core.AnalysisResult Analyze(IReadOnlyList<UnifiedEvent> events, IntensityLevel intensity, CancellationToken cancellationToken, AnalysisProfile? overrideProfile = null)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (events.Count == 0)
        {
            return new Core.AnalysisResult
            {
                TotalLines = 0,
                ParseErrorCount = 0,
                SkippedLineCount = 0,
                ParsedLines = 0,
                TimeRangeStart = DateTime.MinValue,
                TimeRangeEnd = DateTime.MinValue,
                ParseErrors = Array.Empty<string>(),
                Entries = Array.Empty<UnifiedEvent>(),
                Findings = Array.Empty<Core.Finding>(),
                Warnings = Array.Empty<string>()
            };
        }

        var profile = overrideProfile ?? _profileProvider.GetProfile(intensity);
        var warnings = new List<string>();

        var findings = RunDetectors(events, profile, warnings, cancellationToken);

        return BuildAnalysisResult(
            events,
            findings,
            warnings,
            totalLines: events.Count,
            parseErrorCount: 0,
            skippedLineCount: 0,
            parseErrors: Array.Empty<string>());
    }

    private IReadOnlyList<Core.Finding> RunDetectors(
        IReadOnlyList<UnifiedEvent> events,
        AnalysisProfile profile,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var allFindings = new List<Core.Finding>();

        // Layer 1: Run baseline detectors (ported from Windows, proven logic)
        foreach (var detector in _baselineDetectors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var detected = detector.Detect(events, profile, cancellationToken);
                allFindings.AddRange(detected.Findings);
                warnings.AddRange(detected.Warnings);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException && ex is not StackOverflowException && ex is not AccessViolationException && ex is not AppDomainUnloadedException && ex is not ThreadAbortException)
            {
                var warning = $"Baseline detector {detector.GetType().Name} crashed ({ex.GetType().Name}).";
                warnings.Add(warning);
                _logSink.Write(LogLevel.Error, warning, ex);
            }
        }

        // Layer 2: Run Linux Deep Inspection detectors (Linux-specific threats)
        foreach (var detector in _linuxDetectors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var detected = detector.Detect(events, profile, cancellationToken);
                allFindings.AddRange(detected.Findings);
                warnings.AddRange(detected.Warnings);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException && ex is not StackOverflowException && ex is not AccessViolationException && ex is not AppDomainUnloadedException && ex is not ThreadAbortException)
            {
                var warning = $"Linux detector {detector.GetType().Name} crashed ({ex.GetType().Name}).";
                warnings.Add(warning);
                _logSink.Write(LogLevel.Error, warning, ex);
            }
        }

        // Layer 3: Run advanced threat detectors (sophisticated patterns)
        foreach (var detector in _advancedDetectors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var detected = detector.Detect(events, profile, cancellationToken);
                allFindings.AddRange(detected.Findings);
                warnings.AddRange(detected.Warnings);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException && ex is not StackOverflowException && ex is not AccessViolationException && ex is not AppDomainUnloadedException && ex is not ThreadAbortException)
            {
                var warning = $"Advanced detector {detector.GetType().Name} crashed ({ex.GetType().Name}).";
                warnings.Add(warning);
                _logSink.Write(LogLevel.Error, warning, ex);
            }
        }

        // Escalate correlated findings
        var escalated = _riskEscalator.Escalate(allFindings);

        // Deduplicate overlapping Beaconing/C2Channel findings on the same tuple
        var deduped = DeduplicateBeaconingC2Overlap(escalated);

        // Filter by minimum severity before applying the per-category cap so
        // hidden low-severity findings cannot displace visible higher-severity ones.
        var visibleFindings = deduped.Where(f => f.Severity >= profile.MinSeverityToShow).ToList();
        return ApplyNoiseBudget(visibleFindings, profile, warnings);
    }

    private static Core.AnalysisResult BuildAnalysisResult(
        IReadOnlyList<UnifiedEvent> events,
        IReadOnlyList<Core.Finding> findings,
        List<string> warnings,
        int totalLines,
        int parseErrorCount,
        int skippedLineCount,
        IReadOnlyList<string> parseErrors)
    {
        var timeRangeStart = events.Count > 0 ? events.Min(e => e.Timestamp) : DateTime.MinValue;
        var timeRangeEnd = events.Count > 0 ? events.Max(e => e.Timestamp) : DateTime.MinValue;

        return new Core.AnalysisResult
        {
            TotalLines = totalLines,
            ParseErrorCount = parseErrorCount,
            SkippedLineCount = skippedLineCount,
            ParsedLines = events.Count,
            TimeRangeStart = timeRangeStart,
            TimeRangeEnd = timeRangeEnd,
            ParseErrors = parseErrors,
            Entries = events.ToList(),
            Findings = findings,
            Warnings = warnings
        };
    }

    /// <summary>
    /// Applies a per-category noise budget by grouping semantically similar findings
    /// by fingerprint, enriching representatives with grouped metadata, and capping
    /// the number of representatives per category.
    /// </summary>
    internal static IReadOnlyList<Core.Finding> ApplyNoiseBudget(
        IReadOnlyList<Core.Finding> findings,
        AnalysisProfile profile,
        List<string> warnings)
    {
        return Core.FindingNoiseBudget.Apply(findings, profile.MaxFindingsPerDetector, warnings);
    }

    internal static IReadOnlyList<string> DeriveRiskDrivers(IEnumerable<Core.Finding> group)
    {
        return Core.FindingNoiseBudget.DeriveRiskDrivers(group);
    }

    /// <summary>
    /// Deduplicates findings where both Beaconing and C2Channel detectors
    /// flagged the same source-to-destination tuple. Keeps the higher-severity
    /// C2Channel finding and absorbs the Beaconing details into it.
    /// </summary>
    private static IReadOnlyList<Core.Finding> DeduplicateBeaconingC2Overlap(IReadOnlyList<Core.Finding> findings)
    {
        var beaconingByTuple = findings
            .Where(f => f.Category == Core.FindingCategories.Beaconing)
            .GroupBy(f => (f.SourceHost, f.Target))
            .ToDictionary(g => g.Key, g => g.ToList());

        if (beaconingByTuple.Count == 0)
            return findings;

        // Build a HashSet of C2Channel tuples for O(1) lookups instead of O(n) .Any() scans.
        var c2Tuples = findings
            .Where(f => f.Category == Core.FindingCategories.C2Channel)
            .Select(f => (f.SourceHost, f.Target))
            .ToHashSet();

        var result = new List<Core.Finding>(findings.Count);
        // Dedup key includes Details to preserve C2 findings with distinct intervals.
        var processedC2Keys = new HashSet<(string SourceHost, string Target, string Details)>();

        foreach (var finding in findings)
        {
            if (finding.Category == Core.FindingCategories.C2Channel &&
                beaconingByTuple.TryGetValue((finding.SourceHost, finding.Target), out var overlapping))
            {
                var dedupKey = (finding.SourceHost, finding.Target, finding.Details);
                if (!processedC2Keys.Add(dedupKey))
                {
                    // Skip exact-duplicate C2 finding (same tuple + same details)
                    continue;
                }

                // Merge: keep C2Channel, absorb Beaconing details
                var beaconInfo = string.Join("; ", overlapping.Select(b => b.Details));
                var merged = finding with
                {
                    Details = $"{finding.Details} Overlap note: also flagged as Beaconing ({beaconInfo})."
                };
                result.Add(merged);
            }
            else if (finding.Category == Core.FindingCategories.Beaconing &&
                     c2Tuples.Contains((finding.SourceHost, finding.Target)))
            {
                // Skip this Beaconing finding — already absorbed into C2Channel
                continue;
            }
            else
            {
                result.Add(finding);
            }
        }

        return result;
    }
}
