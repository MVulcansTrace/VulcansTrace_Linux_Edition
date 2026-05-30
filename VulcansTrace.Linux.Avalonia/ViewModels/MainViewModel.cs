using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Avalonia.Services;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Main ViewModel coordinating analysis operations and child ViewModels.
/// </summary>
public sealed class MainViewModel : ViewModelBase, IDisposable
{
    private readonly SentryAnalyzer _analyzer;
    private readonly AnalysisProfileProvider _profileProvider;
    private readonly IDialogService _dialogService;
    private readonly ISuppressionStore _suppressionStore;
    private CancellationTokenSource? _cancellationTokenSource;
    private readonly EventHandler<string> _evidenceStatusHandler;
    private readonly EventHandler _evidenceExportCompletedHandler;
    private readonly PropertyChangedEventHandler _findingsPropertyChangedHandler;

    private string _logText = "";
    private string _summaryText = "";
    private string _botIntroText = "";
    private string _advisorMessage = "";
    private int _portScanCap;
    private int _portScanMinPorts;
    private int _floodMinEvents;
    private int _floodWindowSeconds;
    private int _privilegeSpikeMinAttempts;
    private int _privilegeSpikeWindowMinutes;
    private int _c2MinGroupSize;
    private double _c2ToleranceSeconds;
    private int _packetSizeLargeThreshold;
    private int _packetSizeSmallThreshold;
    private int _interfaceHoppingWindowMinutes;
    private bool _isBusy;
    private bool _hasAdvisorMessage;
    private IntensityOption? _selectedIntensity;
    private AnalysisResult? _lastResult;
    private bool _analysisCancelRequested;

    /// <summary>Gets the last analysis result.</summary>
    public AnalysisResult? LastResult => _lastResult;

    // Child ViewModels

    /// <summary>Gets the child ViewModel for evidence/export operations.</summary>
    public EvidenceViewModel Evidence { get; }

    /// <summary>Gets the child ViewModel for findings display and filtering.</summary>
    public FindingsViewModel Findings { get; }

    /// <summary>Gets the child ViewModel for timeline visualization.</summary>
    public TimelineViewModel Timeline { get; }

    /// <summary>Gets the child ViewModel for the security agent chat panel.</summary>
    public AgentViewModel Agent { get; }

    /// <summary>Gets the child ViewModel for the rule catalog.</summary>
    public RuleCatalogViewModel RuleCatalog { get; }

    /// <summary>Gets the child ViewModel for suppression management.</summary>
    public SuppressionViewModel Suppressions { get; }

    /// <summary>Gets the child ViewModel for rule coverage display.</summary>
    public RuleCoverageViewModel RuleCoverage { get; }

    /// <summary>Gets the available intensity options.</summary>
    public ObservableCollection<IntensityOption> Intensities { get; } = new();

    /// <summary>Gets or sets the raw log text to analyze.</summary>
    public string LogText
    {
        get => _logText;
        set
        {
            if (SetField(ref _logText, value))
            {
                Agent.LogText = value;

                if (!IsBusy && _lastResult != null)
                {
                    InvalidateAnalysisContext("Log changed. Re-run analysis to refresh findings and exports.");
                }

                if (string.IsNullOrWhiteSpace(value))
                {
                    AdvisorMessage = string.Empty;
                }
                AnalyzeCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets or sets the summary status text.</summary>
    public string SummaryText
    {
        get => _summaryText;
        set => SetField(ref _summaryText, value);
    }

    /// <summary>Gets or sets the bot intro text.</summary>
    public string BotIntroText
    {
        get => _botIntroText;
        set => SetField(ref _botIntroText, value);
    }

    /// <summary>Gets the advisor message.</summary>
    public string AdvisorMessage
    {
        get => _advisorMessage;
        private set
        {
            if (SetField(ref _advisorMessage, value))
            {
                HasAdvisorMessage = !string.IsNullOrWhiteSpace(value);
            }
        }
    }

    /// <summary>Gets whether there is an advisor message.</summary>
    public bool HasAdvisorMessage
    {
        get => _hasAdvisorMessage;
        private set => SetField(ref _hasAdvisorMessage, value);
    }

    /// <summary>Gets or sets whether an analysis is in progress.</summary>
    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetField(ref _isBusy, value))
            {
                AnalyzeCommand.RaiseCanExecuteChanged();
                CancelCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets or sets the selected intensity option.</summary>
    public IntensityOption? SelectedIntensity
    {
        get => _selectedIntensity;
        set
        {
            if (SetField(ref _selectedIntensity, value))
            {
                AnalyzeCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Gets or sets the port scan max entries per source override.</summary>
    public int PortScanMaxEntriesPerSource
    {
        get => _portScanCap;
        set => SetField(ref _portScanCap, value);
    }

    /// <summary>Gets or sets the minimum distinct ports to qualify as a port scan (0 = use profile default).</summary>
    public int PortScanMinPorts
    {
        get => _portScanMinPorts;
        set => SetField(ref _portScanMinPorts, value);
    }

    /// <summary>Gets or sets the minimum events to qualify as a flood (0 = use profile default).</summary>
    public int FloodMinEvents
    {
        get => _floodMinEvents;
        set => SetField(ref _floodMinEvents, value);
    }

    /// <summary>Gets or sets the time window in seconds for flood detection (0 = use profile default).</summary>
    public int FloodWindowSeconds
    {
        get => _floodWindowSeconds;
        set => SetField(ref _floodWindowSeconds, value);
    }

    /// <summary>Gets or sets the minimum admin port access attempts for PrivEsc spike detection (0 = use profile default).</summary>
    public int PrivilegeSpikeMinAttempts
    {
        get => _privilegeSpikeMinAttempts;
        set => SetField(ref _privilegeSpikeMinAttempts, value);
    }

    /// <summary>Gets or sets the time window in minutes for PrivEsc spike detection (0 = use profile default).</summary>
    public int PrivilegeSpikeWindowMinutes
    {
        get => _privilegeSpikeWindowMinutes;
        set => SetField(ref _privilegeSpikeWindowMinutes, value);
    }

    /// <summary>Gets or sets the minimum group size for C2 channel pre-filtering (0 = use profile default).</summary>
    public int C2MinGroupSize
    {
        get => _c2MinGroupSize;
        set => SetField(ref _c2MinGroupSize, value);
    }

    /// <summary>Gets or sets the tolerance in seconds for C2 periodic pattern detection (0 = use profile default).</summary>
    public double C2ToleranceSeconds
    {
        get => _c2ToleranceSeconds;
        set => SetField(ref _c2ToleranceSeconds, value);
    }

    /// <summary>Gets or sets the packet size threshold above which packets are flagged as large (0 = use profile default).</summary>
    public int PacketSizeLargeThreshold
    {
        get => _packetSizeLargeThreshold;
        set => SetField(ref _packetSizeLargeThreshold, value);
    }

    /// <summary>Gets or sets the packet size threshold below which packets are flagged as small (0 = use profile default).</summary>
    public int PacketSizeSmallThreshold
    {
        get => _packetSizeSmallThreshold;
        set => SetField(ref _packetSizeSmallThreshold, value);
    }

    /// <summary>Gets or sets the time window in minutes for interface hopping detection (0 = use profile default).</summary>
    public int InterfaceHoppingWindowMinutes
    {
        get => _interfaceHoppingWindowMinutes;
        set => SetField(ref _interfaceHoppingWindowMinutes, value);
    }

    /// <summary>Gets the analyze command.</summary>
    public AsyncRelayCommand AnalyzeCommand { get; }

    /// <summary>Gets the cancel command.</summary>
    public RelayCommand CancelCommand { get; }

    /// <summary>Gets the accept risk command.</summary>
    public AsyncRelayCommand AcceptRiskCommand { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="MainViewModel"/> class.
    /// </summary>
    public MainViewModel(
        SentryAnalyzer analyzer,
        EvidenceBuilder evidenceBuilder,
        IDialogService dialogService,
        AnalysisProfileProvider profileProvider,
        IAgent agent,
        ISuppressionStore suppressionStore,
        IAuditHistoryStore auditHistoryStore)
    {
        _analyzer = analyzer;
        _profileProvider = profileProvider;
        _dialogService = dialogService;
        _suppressionStore = suppressionStore;

        // Initialize commands first (before setting properties that trigger RaiseCanExecuteChanged)
        AnalyzeCommand = new AsyncRelayCommand(
            async _ => await AnalyzeAsync(),
            _ => CanAnalyze(),
            ex =>
            {
                SummaryText = $"Analysis failed: {ex.Message}";
                AdvisorMessage = "Analysis failed.";
                IsBusy = false;
            });
        CancelCommand = new RelayCommand(_ => CancelAnalysis(), _ => CanCancel());

        // Initialize child ViewModels
        Findings = new FindingsViewModel();
        Timeline = new TimelineViewModel();
        Evidence = new EvidenceViewModel(evidenceBuilder, dialogService);
        Agent = new AgentViewModel(agent, auditHistoryStore)
        {
            SelectedFindingProvider = () => Findings.SelectedItem?.Finding,
            RequestExportAudit = () => Evidence.ExportEvidenceCommand.Execute(null),
            RequestExportRemediation = async markdown => await ExportRemediationPlanAsync(markdown)
        };
        Agent.AuditCompleted += OnAgentAuditCompleted;
        _findingsPropertyChangedHandler = OnFindingsPropertyChanged;
        Findings.PropertyChanged += _findingsPropertyChangedHandler;
        _evidenceStatusHandler = (s, msg) =>
            Dispatcher.UIThread.Post(() => SummaryText = msg);
        Evidence.StatusChanged += _evidenceStatusHandler;
        _evidenceExportCompletedHandler = (_, _) =>
            Dispatcher.UIThread.Post(() => Agent.MarkLatestAuditExported());
        Evidence.ExportCompleted += _evidenceExportCompletedHandler;

        RuleCatalog = new RuleCatalogViewModel();
        Suppressions = new SuppressionViewModel(suppressionStore, dialogService);
        Suppressions.Refresh();
        RuleCoverage = new RuleCoverageViewModel();

        AcceptRiskCommand = new AsyncRelayCommand(
            async _ => await AcceptRiskAsync(),
            _ => Findings.SelectedItem != null,
            ex =>
            {
                SummaryText = $"Accept risk failed: {ex.Message}";
            });

        BotIntroText = "Hi, I'm VulcansTrace. Paste a Linux firewall log, choose scan intensity, and I'll flag port scans, floods, lateral movement, beaconing, policy violations, novelty destinations, plus advanced signals like C2 channels and admin access spikes at higher intensities.";
        SummaryText = "Paste a Linux firewall log and choose an intensity to begin.";

        Intensities.Add(new IntensityOption("Low - Critical Threat Triage", IntensityLevel.Low));
        Intensities.Add(new IntensityOption("Medium - Investigation Review", IntensityLevel.Medium));
        Intensities.Add(new IntensityOption("High - Deep Hunt / Forensics", IntensityLevel.High));
        SelectedIntensity = Intensities[0];
        PortScanMaxEntriesPerSource = 0;
        PortScanMinPorts = 0;
        FloodMinEvents = 0;
        FloodWindowSeconds = 0;
        PrivilegeSpikeMinAttempts = 0;
        PrivilegeSpikeWindowMinutes = 0;
        C2MinGroupSize = 0;
        C2ToleranceSeconds = 0;
        PacketSizeLargeThreshold = 0;
        PacketSizeSmallThreshold = 0;
        InterfaceHoppingWindowMinutes = 0;
    }

    private bool CanAnalyze() =>
        !_isBusy && !string.IsNullOrWhiteSpace(_logText) && _selectedIntensity != null;

    private bool CanCancel() => _isBusy && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested;

    private void CancelAnalysis()
    {
        _analysisCancelRequested = true;
        _cancellationTokenSource?.Cancel();
    }

    private async Task AnalyzeAsync()
    {
        if (_selectedIntensity == null || string.IsNullOrWhiteSpace(_logText))
        {
            SummaryText = "Paste a log and select an intensity first.";
            return;
        }

        IsBusy = true;
        _analysisCancelRequested = false;
        SummaryText = "Analyzing log...";
        AdvisorMessage = "Analyzing...";

        // Prepare cancellation token
        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;
        var logSnapshot = _logText;

        AnalysisResult result;
        try
        {
            InvalidateAnalysisContext();
            var intensity = _selectedIntensity.Level;
            result = await Task.Run(() => AnalyzeWithOverrides(intensity, logSnapshot, token), token);
            token.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException)
        {
            _analysisCancelRequested = false;
            IsBusy = false;
            SummaryText = "Analysis cancelled by user.";
            AdvisorMessage = "Analysis cancelled.";
            return;
        }
        catch (Exception ex)
        {
            IsBusy = false;
            SummaryText = $"Analysis failed: {ex.Message}";
            AdvisorMessage = "Analysis failed.";
            return;
        }
        finally
        {
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
        }

        if (_analysisCancelRequested || token.IsCancellationRequested)
        {
            _analysisCancelRequested = false;
            IsBusy = false;
            SummaryText = "Analysis cancelled by user.";
            AdvisorMessage = "Analysis cancelled.";
            return;
        }

        if (!string.Equals(_logText, logSnapshot, StringComparison.Ordinal))
        {
            IsBusy = false;
            InvalidateAnalysisContext("Log changed during analysis. Re-run analysis to refresh findings and exports.");
            return;
        }

        _lastResult = result;
        var lastAnalysisTimestampUtc = result.TimeRangeEnd != DateTime.MinValue
            ? result.TimeRangeEnd
            : result.TimeRangeStart != DateTime.MinValue
                ? result.TimeRangeStart
                : DateTime.UnixEpoch;

        // Delegate to child ViewModels
        Evidence.SetEvidenceContext(_lastResult, logSnapshot, lastAnalysisTimestampUtc);
        Findings.LoadResults(result);
        Timeline.LoadAnalysisResult(result);

        // Build summary text
        var total = Findings.FindingsCount;
        var highOrCritical = Findings.HighCriticalCount;

        SummaryText = total == 0
            ? "No findings at the current intensity."
            : $"Found {total} issues, {highOrCritical} High/Critical.";

        if (Findings.ParseErrorCount > 0)
        {
            SummaryText += $" ({Findings.ParseErrorCount} parse errors)";
        }
        if (Findings.SkippedLineCount > 0)
        {
            SummaryText += $" ({Findings.SkippedLineCount} lines skipped)";
        }
        if (Findings.WarningCount > 0)
        {
            SummaryText += $" ({Findings.WarningCount} warnings)";
        }

        UpdateAdvisorMessage(result, highOrCritical, total);

        BotIntroText = _selectedIntensity.Level switch
        {
            IntensityLevel.Low =>
                "Low intensity: only clear, high-confidence threats are shown.",
            IntensityLevel.Medium =>
                "Medium intensity: balanced investigation of suspicious activity.",
            IntensityLevel.High =>
                "High intensity: deep hunt mode, including subtle and borderline patterns.",
            _ => BotIntroText
        };

        IsBusy = false;
    }

    private void InvalidateAnalysisContext(string? summaryText = null)
    {
        _lastResult = null;
        Evidence.ClearEvidenceContext();
        Findings.Clear();
        Timeline.LoadAnalysisResult(null);

        if (!string.IsNullOrWhiteSpace(summaryText))
        {
            SummaryText = summaryText;
            AdvisorMessage = "Analysis results are out of date.";
        }
    }

    private void OnAgentAuditCompleted(object? sender, AgentResult agentResult)
    {
        var generator = new AgentReportGenerator(_suppressionStore);
        var analysisResult = generator.ToAnalysisResult(agentResult);

        string? remediationMarkdown = null;
        if (agentResult.AgentFindings.Count > 0)
        {
            var planBuilder = new RemediationPlanBuilder(new ExplanationProvider());
            var plan = planBuilder.Build(agentResult.AgentFindings);
            var validation = RemediationPlanValidator.Validate(plan);
            if (validation.IsValid)
            {
                var formatter = new RemediationMarkdownFormatter();
                remediationMarkdown = formatter.Format(plan);
            }
            else
            {
                var warning = "Remediation plan omitted from evidence bundle: " + string.Join("; ", validation.Errors);
                AdvisorMessage = warning;
            }
        }

        Evidence.SetEvidenceContext(analysisResult, "Agent audit — no raw log", agentResult.UtcTimestamp, remediationMarkdown);
        Findings.LoadResults(analysisResult);
        Timeline.LoadAnalysisResult(null);
        Suppressions.Refresh();
        RuleCoverage.LoadResults(agentResult);
        SummaryText = agentResult.Summary;
    }

    private async Task ExportRemediationPlanAsync(string markdown)
    {
        var path = await _dialogService.ShowSaveFileDialogAsync(
            "Export Remediation Plan",
            "Markdown files (*.md)|*.md|All files (*.*)|*.*",
            $"remediation-plan-{DateTime.UtcNow:yyyyMMdd-HHmmss}.md");

        if (path == null)
            return;

        try
        {
            await File.WriteAllTextAsync(path, markdown);
            SummaryText = $"Remediation plan exported to {path}";
        }
        catch (Exception ex)
        {
            SummaryText = $"Failed to export remediation plan: {ex.Message}";
        }
    }

    private void OnFindingsPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(FindingsViewModel.SelectedItem))
        {
            Agent.NotifySelectedFindingChanged();
            AcceptRiskCommand.RaiseCanExecuteChanged();
        }
    }

    private async Task AcceptRiskAsync()
    {
        var selected = Findings.SelectedItem?.Finding;
        if (selected == null || string.IsNullOrEmpty(selected.RuleId))
        {
            SummaryText = "Select a finding with a rule ID to accept risk.";
            return;
        }

        var durationOptions = new[]
        {
            "7 days",
            "30 days",
            "90 days",
            "Permanent"
        };

        var durationIndex = await _dialogService.ShowSelectionDialogAsync(
            "Accept Risk",
            $"Accept risk for {selected.RuleId} on {selected.Target}?\n\nSelect suppression duration:",
            durationOptions,
            defaultIndex: 1); // Default to 30 days

        if (durationIndex == null)
        {
            return; // Cancelled
        }

        var duration = durationIndex.Value switch
        {
            0 => SuppressionDuration.Days7,
            1 => SuppressionDuration.Days30,
            2 => SuppressionDuration.Days90,
            _ => SuppressionDuration.Permanent
        };

        var reason = await _dialogService.ShowInputDialogAsync(
            "Accept Risk",
            $"Accept risk for {selected.RuleId} on {selected.Target} ({durationOptions[durationIndex.Value]}).\n\nOptional reason:",
            "");

        if (reason == null)
        {
            return; // Cancelled
        }

        Suppressions.AddSuppression(selected.RuleId, selected.Target, reason, duration);
        SummaryText = $"Accepted risk: {selected.RuleId} ({selected.Target}). Re-run audit to apply suppression.";
    }

    private AnalysisResult AnalyzeWithOverrides(IntensityLevel intensity, string logText, CancellationToken token)
    {
        var baseProfile = _profileProvider.GetProfile(intensity);
        var profile = baseProfile;

        if (PortScanMaxEntriesPerSource > 0)
            profile = profile with { PortScanMaxEntriesPerSource = PortScanMaxEntriesPerSource };
        if (PortScanMinPorts > 0)
            profile = profile with { PortScanMinPorts = PortScanMinPorts };
        if (FloodMinEvents > 0)
            profile = profile with { FloodMinEvents = FloodMinEvents };
        if (FloodWindowSeconds > 0)
            profile = profile with { FloodWindowSeconds = FloodWindowSeconds };
        if (PrivilegeSpikeMinAttempts > 0)
            profile = profile with { PrivilegeSpikeMinAttempts = PrivilegeSpikeMinAttempts };
        if (PrivilegeSpikeWindowMinutes > 0)
            profile = profile with { PrivilegeSpikeWindowMinutes = PrivilegeSpikeWindowMinutes };
        if (C2MinGroupSize > 0)
            profile = profile with { C2MinGroupSize = C2MinGroupSize };
        if (C2ToleranceSeconds > 0)
            profile = profile with { C2ToleranceSeconds = C2ToleranceSeconds };
        if (PacketSizeLargeThreshold > 0)
            profile = profile with { PacketSizeLargeThreshold = PacketSizeLargeThreshold };
        if (PacketSizeSmallThreshold > 0)
            profile = profile with { PacketSizeSmallThreshold = PacketSizeSmallThreshold };
        if (InterfaceHoppingWindowMinutes > 0)
            profile = profile with { InterfaceHoppingWindowMinutes = InterfaceHoppingWindowMinutes };

        return _analyzer.Analyze(logText, intensity, token, profile);
    }

    private void UpdateAdvisorMessage(AnalysisResult result, int highCritical, int totalFindings)
    {
        if (result == null)
        {
            AdvisorMessage = string.Empty;
            return;
        }

        if (result.ParseErrorCount > 0 && totalFindings == 0)
        {
            AdvisorMessage = "Fix parse errors in the log and re-run to surface findings.";
            return;
        }

        if (totalFindings == 0)
        {
            AdvisorMessage = "No findings at this intensity. Try High intensity or adjust filters.";
            return;
        }

        if (highCritical >= 3)
        {
            AdvisorMessage = "Multiple High/Critical issues detected. Triage those first, then sweep the rest.";
        }
        else if (highCritical > 0)
        {
            AdvisorMessage = "Prioritize High/Critical findings, then review remaining events.";
        }
        else if (result.Warnings.Count > 0)
        {
            AdvisorMessage = "Findings detected; review warnings for any truncated or skipped activity.";
        }
        else
        {
            AdvisorMessage = "Findings detected. Review sources/targets to determine next steps.";
        }

        if (result.ParseErrorCount > 0)
        {
            AdvisorMessage += " Fix remaining parse errors to improve coverage.";
        }
    }

    public void Dispose()
    {
        _cancellationTokenSource?.Cancel();
        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = null;

        if (Evidence != null)
        {
            Evidence.StatusChanged -= _evidenceStatusHandler;
            Evidence.ExportCompleted -= _evidenceExportCompletedHandler;
            Evidence.Dispose();
        }

        if (Agent != null)
        {
            Agent.AuditCompleted -= OnAgentAuditCompleted;
            Agent.Dispose();
        }

        if (Findings != null)
        {
            Findings.PropertyChanged -= _findingsPropertyChangedHandler;
        }
    }
}
