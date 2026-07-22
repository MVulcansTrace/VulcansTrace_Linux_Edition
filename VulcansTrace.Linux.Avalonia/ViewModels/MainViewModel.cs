using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Diagnostics;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Findings;
using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;
using VulcansTrace.Linux.Core.ThreatIntel;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.LogDiff;
using VulcansTrace.Linux.Engine.Live;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Evidence.Formatters;
using VulcansTrace.Linux.Avalonia.Models;
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
    private readonly IPinnedFindingStore _pinnedFindingStore;
    private readonly IPinnedMessageStore _pinnedMessageStore;
    private readonly IAnalystActionStore _analystActionStore;
    private readonly AnalystActionLogger _analystActionLogger;
    private readonly RemediationPlanBuilder _remediationPlanBuilder;
    private readonly TraceMapCorrelator _traceMapCorrelator;
    private CancellationTokenSource? _cancellationTokenSource;
    private readonly EventHandler<string> _evidenceStatusHandler;
    private readonly EventHandler _evidenceExportCompletedHandler;
    private readonly PropertyChangedEventHandler _findingsPropertyChangedHandler;
    private readonly PropertyChangedEventHandler _agentPropertyChangedHandler;
    private readonly EventHandler _analystActionStoreChangedHandler;
    private readonly EventHandler<LiveAnalysisResult> _liveResultHandler;
    private readonly EventHandler<DemoCompletedEventArgs> _demoCompletedHandler;

    private string _logText = "";
    private string _summaryText = "";
    private string _appStateJson = "{}";
    private AnalystActionEntry? _lastAction;
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
    private MachineRole _selectedMachineRole = MachineRole.Workstation;
    private AnalysisResult? _lastResult;
    private bool _analysisCancelRequested;
    private NavigationItem? _selectedNavigationItem;
    private object? _selectedContent;

    /// <summary>Gets the last analysis result.</summary>
    public AnalysisResult? LastResult => _lastResult;

    // Child ViewModels

    /// <summary>Gets the child ViewModel for evidence/export operations.</summary>
    public EvidenceViewModel Evidence { get; }

    /// <summary>Gets the child ViewModel for findings display and filtering.</summary>
    public FindingsViewModel Findings { get; }

    /// <summary>Gets the child ViewModel for timeline visualization.</summary>
    public TimelineViewModel Timeline { get; }

    /// <summary>Gets the child ViewModel for incident story narrative.</summary>
    public IncidentStoryViewModel IncidentStory { get; }

    /// <summary>Gets the child ViewModel for the security agent chat panel.</summary>
    public AgentViewModel Agent { get; }

    /// <summary>Gets the child ViewModel for the rule catalog.</summary>
    public RuleCatalogViewModel RuleCatalog { get; }

    /// <summary>Gets the child ViewModel for suppression management.</summary>
    public SuppressionViewModel Suppressions { get; }

    /// <summary>Gets the child ViewModel for rule coverage display.</summary>
    public RuleCoverageViewModel RuleCoverage { get; }

    /// <summary>Gets the child ViewModel for schedule management.</summary>
    public ScheduleViewModel Schedules { get; }

    /// <summary>Gets the child ViewModel for threat-intel management.</summary>
    public ThreatIntelViewModel ThreatIntel { get; }

    /// <summary>Gets the child ViewModel for CIS compliance scorecard.</summary>
    public ComplianceScorecardViewModel ComplianceScorecard { get; }

    /// <summary>Gets the child ViewModel for notification channel settings.</summary>
    public NotificationSettingsViewModel NotificationSettings { get; }

    /// <summary>Gets the child ViewModel for risk scorecard.</summary>
    public RiskScorecardViewModel RiskScorecard { get; }

    /// <summary>Gets the child ViewModel for live stream analysis.</summary>
    public LiveStreamViewModel LiveStream { get; }

    /// <summary>Gets the child ViewModel for doctor diagnostics.</summary>
    public DoctorViewModel Doctor { get; }

    /// <summary>Gets the child ViewModel for the analyst action audit log.</summary>
    public AnalystActionLogViewModel AnalystActionLog { get; }

    /// <summary>Gets the sidebar navigation items.</summary>
    public ObservableCollection<NavigationItem> NavigationItems { get; } = new();

    /// <summary>Gets or sets the currently selected navigation item.</summary>
    public NavigationItem? SelectedNavigationItem
    {
        get => _selectedNavigationItem;
        set
        {
            if (SetField(ref _selectedNavigationItem, value))
            {
                SelectedContent = value?.Content;
                if (ReferenceEquals(value?.Content, ThreatIntel))
                {
                    ThreatIntel.Refresh();
                }
                RefreshAppState();
            }
        }
    }

    /// <summary>Gets or sets the content displayed in the main area.</summary>
    public object? SelectedContent
    {
        get => _selectedContent;
        private set => SetField(ref _selectedContent, value);
    }

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
        set
        {
            if (SetField(ref _summaryText, value))
            {
                RefreshAppState();
            }
        }
    }

    /// <summary>
    /// Gets the machine-readable application state snapshot (JSON).
    /// </summary>
    /// <remarks>
    /// Surfaced to harnesses through the AppStateNode automation peer in
    /// MainWindow.axaml. Payload is append-only across versions: add fields,
    /// never rename or remove. Refreshed from the few properties that compose
    /// it, so it can never diverge from what the human UI shows.
    /// </remarks>
    public string AppStateJson
    {
        get => _appStateJson;
        private set => SetField(ref _appStateJson, value);
    }

    private void RefreshAppState()
    {
        AppStateJson = JsonSerializer.Serialize(new
        {
            view = SelectedNavigationItem?.Label ?? "",
            busy = _isBusy,
            agent_busy = Agent?.IsBusy ?? false,
            summary = _summaryText,
            findings = Findings?.FindingsCount ?? 0,
            high_critical = Findings?.HighCriticalCount ?? 0,
            warnings = Findings?.WarningCount ?? 0,
            parse_errors = Findings?.ParseErrorCount ?? 0,
            last_action = _lastAction is null
                ? null
                : new
                {
                    op = _lastAction.ActionType,
                    target = _lastAction.Target ?? "",
                    ts = _lastAction.TimestampUtc.ToString("O"),
                },
        });
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

    /// <summary>Gets whether an analysis is in progress.</summary>
    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetField(ref _isBusy, value))
            {
                AnalyzeCommand.RaiseCanExecuteChanged();
                CancelCommand.RaiseCanExecuteChanged();
                CompareLogsCommand.RaiseCanExecuteChanged();
                OnPropertyChanged(nameof(IsNotBusy));
                RefreshAppState();
            }
        }
    }

    /// <summary>Gets whether the UI is not busy.</summary>
    public bool IsNotBusy => !_isBusy;

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

    /// <summary>Gets the available machine roles.</summary>
    public ObservableCollection<MachineRole> MachineRoles { get; } = new()
    {
        MachineRole.Workstation,
        MachineRole.Server,
        MachineRole.LabBox,
        MachineRole.Router,
        MachineRole.DevMachine
    };

    /// <summary>Gets or sets the selected machine role.</summary>
    public MachineRole SelectedMachineRole
    {
        get => _selectedMachineRole;
        set => SetField(ref _selectedMachineRole, value);
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

    /// <summary>Gets the investigate selected finding command.</summary>
    public AsyncRelayCommand InvestigateCommand { get; }

    /// <summary>Gets the suppress (accept risk) command.</summary>
    public AsyncRelayCommand SuppressCommand { get; }

    /// <summary>Gets the resolve (generate remediation plan) command.</summary>
    public AsyncRelayCommand ResolveCommand { get; }

    /// <summary>Gets the verify-finding remediation command.</summary>
    public AsyncRelayCommand VerifyFindingCommand { get; }

    /// <summary>Gets the compare logs command.</summary>
    public AsyncRelayCommand CompareLogsCommand { get; }

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
        IPinnedFindingStore pinnedFindingStore,
        IPinnedMessageStore pinnedMessageStore,
        IAuditHistoryStore auditHistoryStore,
        RemediationPlanBuilder remediationPlanBuilder,
        RemediationExecutor remediationExecutor,
        TraceMapCorrelator traceMapCorrelator,
        LiveStreamAnalyzer liveStreamAnalyzer,
        IRulePolicyStore? policyStore = null,
        IScheduleStore? scheduleStore = null,
        INotificationService? notificationService = null,
        ISessionStore? sessionStore = null,
        IThreatIntelStore? threatIntelStore = null,
        DoctorService? doctorService = null,
        IAgentMemoryStore? memoryStore = null,
        INotificationSettingsStore? notificationSettingsStore = null,
        IAnalystActionStore? analystActionStore = null,
        AnalystActionLogger? analystActionLogger = null)
    {
        _analyzer = analyzer;
        _profileProvider = profileProvider;
        _dialogService = dialogService;
        _suppressionStore = suppressionStore;
        _pinnedFindingStore = pinnedFindingStore;
        _pinnedMessageStore = pinnedMessageStore;
        _remediationPlanBuilder = remediationPlanBuilder ?? throw new ArgumentNullException(nameof(remediationPlanBuilder));
        _traceMapCorrelator = traceMapCorrelator;
        _analystActionStore = analystActionStore ?? new InMemoryAnalystActionStore();
        _analystActionLogger = analystActionLogger ?? new AnalystActionLogger(_analystActionStore);
        _lastAction = _analystActionStore.GetAll().FirstOrDefault();
        _analystActionStoreChangedHandler = (_, _) =>
            Dispatcher.UIThread.Post(() =>
            {
                _lastAction = _analystActionStore.GetAll().FirstOrDefault();
                RefreshAppState();
            });
        _analystActionStore.Changed += _analystActionStoreChangedHandler;

        // Initialize commands first (before setting properties that trigger RaiseCanExecuteChanged)
        AnalyzeCommand = new AsyncRelayCommand(
            async _ => await AnalyzeAsync(),
            _ => CanAnalyze(),
            ex =>
            {
                SummaryText = $"Analysis failed: {ErrorSanitizer.SanitizeException(ex)}";
                AdvisorMessage = "Analysis failed.";
                IsBusy = false;
            });
        CancelCommand = new RelayCommand(_ => CancelAnalysis(), _ => CanCancel());

        // Initialize child ViewModels
        Findings = new FindingsViewModel(_pinnedFindingStore);
        Timeline = new TimelineViewModel();
        IncidentStory = new IncidentStoryViewModel();
        Evidence = new EvidenceViewModel(evidenceBuilder, dialogService, analystActionLogger: _analystActionLogger);
        Agent = new AgentViewModel(agent, auditHistoryStore, _remediationPlanBuilder, remediationExecutor, sessionStore, threatIntelStore, dialogService, memoryStore, _pinnedMessageStore, _analystActionLogger)
        {
            SelectedFindingProvider = () => Findings.SelectedItem?.Finding,
            RequestExportAudit = () => Evidence.ExportEvidenceCommand.Execute(null),
            RequestExportRemediation = async markdown => await ExportRemediationPlanAsync(markdown),
            RequestExportSession = async markdown => await ExportSessionReportAsync(markdown),
            RequestExportThreatIntel = async () => await ExportThreatIntelAsync()
        };
        Agent.AuditCompleted += OnAgentAuditCompleted;
        _agentPropertyChangedHandler = OnAgentPropertyChanged;
        Agent.PropertyChanged += _agentPropertyChangedHandler;
        _findingsPropertyChangedHandler = OnFindingsPropertyChanged;
        Findings.PropertyChanged += _findingsPropertyChangedHandler;
        _evidenceStatusHandler = (s, msg) =>
            Dispatcher.UIThread.Post(() => SummaryText = msg);
        Evidence.StatusChanged += _evidenceStatusHandler;
        _evidenceExportCompletedHandler = (_, _) =>
            Dispatcher.UIThread.Post(() => Agent.MarkLatestAuditExported());
        Evidence.ExportCompleted += _evidenceExportCompletedHandler;

        RuleCatalog = new RuleCatalogViewModel(policyStore, dialogService, _analystActionLogger);
        Suppressions = new SuppressionViewModel(suppressionStore, dialogService);
        Suppressions.Refresh();
        RuleCoverage = new RuleCoverageViewModel();
        ComplianceScorecard = new ComplianceScorecardViewModel();
        RiskScorecard = new RiskScorecardViewModel();
        // Hoist a single shared store so the scheduler and the settings tab observe the same
        // settings; two independent `?? new InMemoryNotificationSettingsStore()` would diverge.
        var notificationSettings = notificationSettingsStore ?? new InMemoryNotificationSettingsStore();
        Schedules = new ScheduleViewModel(
            scheduleStore ?? new InMemoryScheduleStore(),
            auditHistoryStore,
            notificationSettings,
            notificationService ?? new NotifySendNotificationService(),
            dialogService,
            _analystActionLogger);
        ThreatIntel = new ThreatIntelViewModel(
            threatIntelStore ?? new InMemoryThreatIntelStore(),
            dialogService,
            _analystActionLogger);
        NotificationSettings = new NotificationSettingsViewModel(
            notificationSettings,
            analystActionLogger: _analystActionLogger);

        LiveStream = new LiveStreamViewModel(liveStreamAnalyzer, () => SelectedIntensity?.Level ?? IntensityLevel.Medium);
        Doctor = new DoctorViewModel(doctorService ?? new DoctorService(System.Array.Empty<IScanner>()));
        AnalystActionLog = new AnalystActionLogViewModel(_analystActionStore, dialogService);

        // Wire empty-state action commands
        Findings.EmptyStateActionCommand = AnalyzeCommand;
        Timeline.EmptyStateActionCommand = AnalyzeCommand;
        IncidentStory.EmptyStateActionCommand = AnalyzeCommand;
        RiskScorecard.EmptyStateActionCommand = AnalyzeCommand;
        RuleCoverage.EmptyStateActionCommand = AnalyzeCommand;
        ComplianceScorecard.EmptyStateActionCommand = Agent.FullAuditCommand;
        ComplianceScorecard.EmptyStateActionText = "Run full audit";

        _liveResultHandler = (_, result) =>
        {
            foreach (var finding in result.DeltaFindings)
            {
                Findings.AddFinding(finding);
            }
        };
        LiveStream.LiveResultReceived += _liveResultHandler;

        _demoCompletedHandler = (_, e) => OnDemoCompleted(e);
        LiveStream.DemoCompleted += _demoCompletedHandler;

        // Initialize sidebar navigation
        NavigationItems.Add(new NavigationItem { Label = "Agent", Icon = "mdi-robot", Content = Agent, Group = "ANALYSIS" });
        NavigationItems.Add(new NavigationItem { Label = "Findings", Icon = "mdi-magnify", Content = Findings, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Timeline", Icon = "mdi-chart-timeline-variant", Content = Timeline, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Incident Story", Icon = "mdi-book-open-variant", Content = IncidentStory, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Rules", Icon = "mdi-shield-check", Content = RuleCatalog, Group = "MANAGEMENT" });
        NavigationItems.Add(new NavigationItem { Label = "Threat Intel", Icon = "mdi-forest-fire", Content = ThreatIntel, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Suppressions", Icon = "mdi-volume-off", Content = Suppressions, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Coverage", Icon = "mdi-bullseye-arrow", Content = RuleCoverage, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Compliance", Icon = "mdi-clipboard-check", Content = ComplianceScorecard, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Risk", Icon = "mdi-alert-decagram", Content = RiskScorecard, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Schedules", Icon = "mdi-calendar-clock", Content = Schedules, Group = "OPERATIONS" });
        NavigationItems.Add(new NavigationItem { Label = "Notifications", Icon = "mdi-bell", Content = NotificationSettings, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Live Stream", Icon = "mdi-antenna", Content = LiveStream, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Doctor", Icon = "mdi-stethoscope", Content = Doctor, Group = "" });
        NavigationItems.Add(new NavigationItem { Label = "Analyst Action Log", Icon = "mdi-clipboard-text-clock", Content = AnalystActionLog, Group = "ACCOUNTABILITY" });
        NavigationItems.Add(new NavigationItem { Label = "Parse Errors", Icon = "mdi-alert-circle", Content = Findings, Group = "SYSTEM" });
        NavigationItems.Add(new NavigationItem { Label = "Warnings", Icon = "mdi-alert", Content = Findings, Group = "" });

        Agent.NavigateToThreatIntelAction = NavigateToThreatIntel;
        SelectedNavigationItem = NavigationItems[0];

        InvestigateCommand = new AsyncRelayCommand(
            async parameter => await InvestigateFindingAsync(parameter),
            parameter => parameter is FindingItemViewModel && !Agent.IsBusy,
            ex =>
            {
                SummaryText = $"Investigate failed: {ErrorSanitizer.SanitizeException(ex)}";
            });

        SuppressCommand = new AsyncRelayCommand(
            async parameter => await SuppressFindingAsync(parameter),
            parameter => parameter is FindingItemViewModel item && !string.IsNullOrEmpty(item.Finding.RuleId),
            ex =>
            {
                SummaryText = $"Suppress failed: {ErrorSanitizer.SanitizeException(ex)}";
            });

        ResolveCommand = new AsyncRelayCommand(
            async parameter => await ResolveFindingAsync(parameter),
            parameter => parameter is FindingItemViewModel item && !string.IsNullOrEmpty(item.Finding.RuleId),
            ex =>
            {
                SummaryText = $"Resolve failed: {ErrorSanitizer.SanitizeException(ex)}";
            });

        VerifyFindingCommand = new AsyncRelayCommand(
            async parameter => await VerifyFindingAsync(parameter),
            parameter => parameter is FindingItemViewModel item && !string.IsNullOrEmpty(item.Finding.RuleId) && !Agent.IsBusy,
            ex =>
            {
                SummaryText = $"Verify failed: {ErrorSanitizer.SanitizeException(ex)}";
            });

        Findings.InvestigateCommand = InvestigateCommand;
        Findings.SuppressCommand = SuppressCommand;
        Findings.ResolveCommand = ResolveCommand;
        Findings.VerifyFindingCommand = VerifyFindingCommand;

        CompareLogsCommand = new AsyncRelayCommand(
            async _ => await RunLogDiffAsync(),
            _ => !IsBusy,
            ex =>
            {
                SummaryText = $"Log comparison failed: {ErrorSanitizer.SanitizeException(ex)}";
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

        CompareLogsCommand.RaiseCanExecuteChanged();
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
            SummaryText = $"Analysis failed: {ErrorSanitizer.SanitizeException(ex)}";
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

        // Build risk scorecard for log analysis path (engine does not produce one)
        var riskBuilder = new RiskScorecardBuilder();
        result = result with { RiskScorecard = riskBuilder.Build(result.Findings) };

        _lastResult = result;
        var lastAnalysisTimestampUtc = result.TimeRangeEnd != DateTime.MinValue
            ? result.TimeRangeEnd
            : result.TimeRangeStart != DateTime.MinValue
                ? result.TimeRangeStart
                : DateTime.UnixEpoch;

        // Delegate to child ViewModels
        var traceMap = _traceMapCorrelator.Correlate(result.Findings);
        Evidence.SetEvidenceContext(_lastResult, logSnapshot, lastAnalysisTimestampUtc, traceMap: traceMap);
        Findings.LoadResults(result);
        Timeline.LoadAnalysisResult(result, traceMap.Edges);
        IncidentStory.LoadTraceMap(traceMap);
        RiskScorecard.LoadScorecard(result.RiskScorecard);
        InjectCountermeasureMessages(traceMap);

        // Build summary text
        var total = Findings.FindingsCount;
        var highOrCritical = Findings.HighCriticalCount;

        SummaryText = total == 0
            ? "No findings at the current intensity."
            : $"Found {total} {(total == 1 ? "issue" : "issues")}, {highOrCritical} High/Critical.";

        if (Findings.ParseErrorCount > 0)
        {
            SummaryText += $" ({Findings.ParseErrorCount} parse errors)";
        }
        if (Findings.SkippedLineCount > 0)
        {
            var linesWord = Findings.SkippedLineCount == 1 ? "line" : "lines";
            SummaryText += $" ({Findings.SkippedLineCount} {linesWord} skipped)";
        }
        if (Findings.WarningCount > 0)
        {
            SummaryText += $" ({Findings.WarningCount} warnings)";
        }

        UpdateAdvisorMessage(result, highOrCritical, total);

        await _analystActionLogger.LogAuditAsync("avalonia", "LogAnalysis", _selectedMachineRole.ToString(), result.Findings.Count);

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

    private async Task RunLogDiffAsync()
    {
        var baselinePath = await _dialogService.ShowOpenFileDialogAsync("Select Baseline Log", "Log files (*.log)|*.log|All files (*.*)|*.*");
        if (string.IsNullOrWhiteSpace(baselinePath))
            return;

        var incidentPath = await _dialogService.ShowOpenFileDialogAsync("Select Incident Log", "Log files (*.log)|*.log|All files (*.*)|*.*");
        if (string.IsNullOrWhiteSpace(incidentPath))
            return;

        IsBusy = true;
        SummaryText = "Comparing logs...";
        AdvisorMessage = "Running log diff analysis...";

        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;

        try
        {
            var baselineLog = await File.ReadAllTextAsync(baselinePath, token);
            var incidentLog = await File.ReadAllTextAsync(incidentPath, token);

            var baselineResult = await Task.Run(() => _analyzer.Analyze(baselineLog, _selectedIntensity?.Level ?? IntensityLevel.Medium, token), token);
            var incidentResult = await Task.Run(() => _analyzer.Analyze(incidentLog, _selectedIntensity?.Level ?? IntensityLevel.Medium, token), token);

            var diffAnalyzer = new LogDiffAnalyzer();
            var diffResult = diffAnalyzer.Compare(baselineResult, incidentResult) with
            {
                BaselineLabel = baselinePath,
                IncidentLabel = incidentPath
            };

            var viewModel = new LogDiffViewModel(_dialogService);
            viewModel.LoadDiff(diffResult);

            var window = new Views.LogDiffWindow(viewModel);
            window.Show();
            window.Activate();

            SummaryText = $"Diff complete: {diffResult.Narrative}";
            AdvisorMessage = "Log comparison finished.";

            await _analystActionLogger.LogDiffAsync("avalonia", baselinePath, incidentPath);
        }
        catch (OperationCanceledException)
        {
            SummaryText = "Log comparison cancelled.";
            AdvisorMessage = "Log comparison cancelled.";
        }
        catch (Exception ex)
        {
            SummaryText = $"Log comparison failed: {ErrorSanitizer.SanitizeException(ex)}";
            AdvisorMessage = "Log comparison failed.";
        }
        finally
        {
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            IsBusy = false;
        }
    }

    /// <summary>
    /// Builds a <see cref="LogDiffResult"/> from two small synthetic logs.
    /// Used by the /logdiffdemo slash command and automation smoke tests.
    /// </summary>
    public async Task<LogDiffResult> BuildLogDiffDemoResultAsync(CancellationToken cancellationToken = default)
    {
        var baselineLog = BuildDemoBaselineLog();
        var incidentLog = BuildDemoIncidentLog();

        var baselineResult = await Task.Run(() => _analyzer.Analyze(baselineLog, _selectedIntensity?.Level ?? IntensityLevel.Medium, cancellationToken), cancellationToken);
        var incidentResult = await Task.Run(() => _analyzer.Analyze(incidentLog, _selectedIntensity?.Level ?? IntensityLevel.Medium, cancellationToken), cancellationToken);

        var diffAnalyzer = new LogDiffAnalyzer();
        return diffAnalyzer.Compare(baselineResult, incidentResult) with
        {
            BaselineLabel = "Demo baseline log",
            IncidentLabel = "Demo incident log"
        };
    }

    /// <summary>
    /// Opens the Log Diff window with two small synthetic logs.
    /// Used by the /logdiffdemo slash command and automation smoke tests.
    /// </summary>
    public async Task ShowLogDiffDemoAsync()
    {
        IsBusy = true;
        SummaryText = "Comparing demo logs...";
        AdvisorMessage = "Running log diff demo...";

        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;

        try
        {
            var diffResult = await BuildLogDiffDemoResultAsync(token);

            var viewModel = new LogDiffViewModel(_dialogService);
            viewModel.LoadDiff(diffResult);

            var window = new Views.LogDiffWindow(viewModel);
            var owner = (global::Avalonia.Application.Current?.ApplicationLifetime as global::Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.MainWindow;
            if (owner != null)
            {
                await window.ShowDialog<object?>(owner);
            }
            else
            {
                window.Show();
            }

            SummaryText = $"Demo diff complete: {diffResult.Narrative}";
            AdvisorMessage = "Log diff demo finished.";
        }
        catch (OperationCanceledException)
        {
            SummaryText = "Log diff demo cancelled.";
            AdvisorMessage = "Log diff demo cancelled.";
        }
        catch (Exception ex)
        {
            SummaryText = $"Log diff demo failed: {ErrorSanitizer.SanitizeException(ex)}";
            AdvisorMessage = "Log diff demo failed.";
        }
        finally
        {
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            IsBusy = false;
        }
    }

    /// <summary>
    /// Opens the Threat Intel management view and refreshes it from the shared store first.
    /// </summary>
    public void NavigateToThreatIntel()
    {
        ThreatIntel.Refresh();
        var item = NavigationItems.FirstOrDefault(i => ReferenceEquals(i.Content, ThreatIntel));
        if (item != null)
        {
            SelectedNavigationItem = item;
        }
    }

    private static string BuildDemoBaselineLog()
    {
        return """
            kernel: Jan 19 10:00:00 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.10 DST=10.0.0.5 PROTO=TCP SPT=12345 DPT=80
            kernel: Jan 19 10:01:00 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.11 DST=10.0.0.6 PROTO=TCP SPT=12346 DPT=443
            kernel: Jan 19 10:02:00 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.12 DST=10.0.0.5 PROTO=UDP SPT=12347 DPT=53
            """;
    }

    private static string BuildDemoIncidentLog()
    {
        return """
            kernel: Jan 19 10:00:00 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.10 DST=10.0.0.5 PROTO=TCP SPT=12345 DPT=80
            kernel: Jan 19 10:01:00 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.11 DST=10.0.0.6 PROTO=TCP SPT=12346 DPT=443
            kernel: Jan 19 10:02:00 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.12 DST=10.0.0.5 PROTO=UDP SPT=12347 DPT=53
            kernel: Jan 19 10:15:32 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.99.99.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=22
            kernel: Jan 19 10:15:33 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.99.99.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=23
            kernel: Jan 19 10:15:34 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.99.99.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=25
            kernel: Jan 19 10:15:35 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.99.99.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=53
            kernel: Jan 19 10:15:36 server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.99.99.100 DST=10.0.0.5 PROTO=TCP SPT=54321 DPT=80
            """;
    }

    private void InvalidateAnalysisContext(string? summaryText = null)
    {
        _lastResult = null;
        Evidence.ClearEvidenceContext();
        Findings.Clear();
        Timeline.LoadAnalysisResult(null);
        IncidentStory.LoadTraceMap(null);
        RiskScorecard.LoadScorecard(null);

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
            var plan = _remediationPlanBuilder.Build(agentResult.AgentFindings);
            var validation = RemediationPlanValidator.Validate(plan);
            if (validation.IsValid)
            {
                var formatter = new RemediationMarkdownFormatter();
                remediationMarkdown = formatter.Format(plan);
            }
            else
            {
                // Keep the left-panel Tip bounded (count only); surface the per-section
                // detail in the Agent transcript, which is built for long content.
                var (tip, detail) = AdvisorText.ForBlockedRemediation(validation);
                AdvisorMessage = tip;
                var transcript = AdvisorText.FormatBlockedRemediationTranscript(detail);
                if (transcript is not null)
                    Agent.PostInfo(transcript);
            }
        }

        var agentTraceMap = _traceMapCorrelator.Correlate(analysisResult.Findings);
        _lastResult = analysisResult;
        Evidence.SetEvidenceContext(analysisResult, "Agent audit — no raw log", agentResult.UtcTimestamp, remediationMarkdown, agentTraceMap);
        Findings.LoadResults(analysisResult);
        Timeline.LoadAnalysisResult(analysisResult, agentTraceMap.Edges);
        IncidentStory.LoadTraceMap(agentTraceMap);
        InjectCountermeasureMessages(agentTraceMap);
        Suppressions.Refresh();
        RuleCoverage.LoadResults(agentResult);
        ComplianceScorecard.LoadScorecard(agentResult.Scorecard);
        RiskScorecard.LoadScorecard(agentResult.RiskScorecard);
        ThreatIntel.Refresh();
        SummaryText = agentResult.Summary;
    }

    private void OnDemoCompleted(DemoCompletedEventArgs e)
    {
        var findings = e.Findings.ToList();
        if (findings.Count == 0)
        {
            Findings.Clear();
            Timeline.LoadAnalysisResult(null);
            IncidentStory.LoadTraceMap(null);
            RiskScorecard.LoadScorecard(null);
            SummaryText = $"Demo complete: {e.ScenarioName} — no findings.";
            return;
        }

        var traceMap = _traceMapCorrelator.Correlate(findings);
        var riskBuilder = new RiskScorecardBuilder();
        var analysisResult = new AnalysisResult
        {
            Findings = findings,
            TimeRangeStart = e.StartTime,
            TimeRangeEnd = e.EndTime,
            TotalLines = 0,
            ParsedLines = 0,
            Warnings = Array.Empty<string>(),
            ParseErrors = Array.Empty<string>(),
            ActiveSuppressions = Array.Empty<SuppressionSummary>(),
            RiskScorecard = riskBuilder.Build(findings)
        };

        Evidence.SetEvidenceContext(analysisResult, $"Synthetic demo: {e.ScenarioName}", e.EndTime, traceMap: traceMap);
        Findings.LoadResults(analysisResult);
        Timeline.LoadAnalysisResult(analysisResult, traceMap.Edges);
        IncidentStory.LoadTraceMap(traceMap);
        RiskScorecard.LoadScorecard(analysisResult.RiskScorecard);

        var highOrCritical = findings.Count(f => f.Severity is Severity.High or Severity.Critical);
        SummaryText = $"Demo complete: {e.ScenarioName} — {findings.Count} {(findings.Count == 1 ? "finding" : "findings")}, {highOrCritical} High/Critical.";
        AdvisorMessage = "Demo findings are ready. Switch to the Evidence tab to export a signed bundle.";
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

            await _analystActionLogger.LogRemediationAsync("avalonia", path);
        }
        catch (Exception ex)
        {
            SummaryText = $"Failed to export remediation plan: {ErrorSanitizer.SanitizeException(ex)}";
        }
    }

    private async Task<bool> ExportSessionReportAsync(string markdown)
    {
        var path = await _dialogService.ShowSaveFileDialogAsync(
            "Export Session Report",
            "Markdown files (*.md)|*.md|All files (*.*)|*.*",
            $"remediation-session-{DateTime.UtcNow:yyyyMMdd-HHmmss}.md");

        if (path == null)
            return false;

        try
        {
            await File.WriteAllTextAsync(path, markdown);
            SummaryText = $"Session report exported to {path}";

            await _analystActionLogger.LogSessionReportAsync("avalonia", path);
            return true;
        }
        catch (Exception ex)
        {
            SummaryText = $"Failed to export session report: {ErrorSanitizer.SanitizeException(ex)}";
            return false;
        }
    }

    private async Task<bool> ExportThreatIntelAsync()
    {
        if (_lastResult == null)
        {
            SummaryText = "Run an analysis first to export threat intelligence.";
            return false;
        }

        var formatOptions = new[] { "STIX 2.1", "MISP JSON" };
        var formatIndex = await _dialogService.ShowSelectionDialogAsync(
            "Export Threat Intelligence",
            "Choose export format:",
            formatOptions,
            defaultIndex: 0);

        if (formatIndex == null)
            return false;

        var format = formatIndex.Value == 0 ? "stix" : "misp";
        var extension = format == "stix" ? ".stix.json" : ".misp.json";
        var defaultFileName = $"vulcanstrace-threat-intel-{DateTime.UtcNow:yyyyMMdd-HHmmss}{extension}";

        var path = await _dialogService.ShowSaveFileDialogAsync(
            "Export Threat Intelligence",
            "JSON files (*.json)|*.json|All files (*.*)|*.*",
            defaultFileName);

        if (path == null)
            return false;

        try
        {
            IEvidenceFormatter formatter = format == "stix"
                ? new StixFormatter()
                : new MispFormatter();

            var json = formatter.Format(_lastResult, _logText);
            await File.WriteAllTextAsync(path, json);
            SummaryText = $"Threat intelligence exported to {path}";

            await _analystActionLogger.LogThreatIntelExportedAsync("avalonia", format, path);
            return true;
        }
        catch (Exception ex)
        {
            SummaryText = $"Failed to export threat intelligence: {ErrorSanitizer.SanitizeException(ex)}";
            return false;
        }
    }

    private void OnFindingsPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(FindingsViewModel.SelectedItem))
        {
            Agent.NotifySelectedFindingChanged();
        }
        if (e.PropertyName is nameof(FindingsViewModel.FindingsCount)
            or nameof(FindingsViewModel.HighCriticalCount)
            or nameof(FindingsViewModel.WarningCount)
            or nameof(FindingsViewModel.ParseErrorCount))
        {
            RefreshAppState();
        }
    }

    private void OnAgentPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AgentViewModel.IsBusy))
        {
            InvestigateCommand?.RaiseCanExecuteChanged();
            VerifyFindingCommand?.RaiseCanExecuteChanged();
            RefreshAppState();
        }
    }

    private async Task SuppressFindingAsync(object? parameter)
    {
        if (parameter is FindingItemViewModel item)
        {
            Findings.SelectedItem = item;
        }

        var selected = Findings.SelectedItem?.Finding;
        if (selected == null || string.IsNullOrEmpty(selected.RuleId))
        {
            SummaryText = "Select a finding with a rule ID to suppress.";
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
            "Suppress Finding",
            $"Suppress {selected.RuleId} on {selected.Target}?\n\nSelect suppression duration:",
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
            "Suppress Finding",
            $"Suppress {selected.RuleId} on {selected.Target} ({durationOptions[durationIndex.Value]}).\n\nOptional reason:",
            "");

        if (reason == null)
        {
            return; // Cancelled
        }

        Suppressions.AddSuppression(selected.RuleId, selected.Target, reason, duration, selected.Fingerprint);
        SummaryText = $"Suppressed: {selected.RuleId} ({selected.Target}). Re-run audit to apply suppression.";

        await _analystActionLogger.LogSuppressionAsync("avalonia", selected.RuleId, selected.Target);
    }

    private async Task InvestigateFindingAsync(object? parameter)
    {
        if (parameter is FindingItemViewModel item)
        {
            Findings.SelectedItem = item;
        }

        var selected = Findings.SelectedItem?.Finding;
        if (selected == null)
        {
            SummaryText = "Select a finding to investigate.";
            return;
        }

        if (!Agent.ExplainSelectedCommand.CanExecute(null))
        {
            SummaryText = "Agent is busy. Wait for the current operation to finish.";
            return;
        }

        SummaryText = $"Investigating {selected.Category}…";
        SelectedNavigationItem = NavigationItems[0]; // Agent tab
        Agent.ExplainSelectedCommand.Execute(null);

        // Wait for the agent operation to complete.
        await Agent.ExplainSelectedCommand.ExecutionTask;
        SummaryText = Agent.LastOperationSucceeded
            ? $"Investigation of {selected.Category} ready in the Agent tab."
            : $"Investigation of {selected.Category} did not complete — see the Agent tab.";
    }

    private async Task VerifyFindingAsync(object? parameter)
    {
        if (parameter is FindingItemViewModel item)
        {
            Findings.SelectedItem = item;
        }

        var selected = Findings.SelectedItem?.Finding;
        if (selected == null || string.IsNullOrEmpty(selected.RuleId))
        {
            SummaryText = "Select a finding with a rule ID to verify.";
            return;
        }

        if (!Agent.VerifySelectedCommand.CanExecute(null))
        {
            SummaryText = "Agent is busy or the selected finding cannot be verified. Wait for the current operation to finish.";
            return;
        }

        SummaryText = $"Verifying {selected.RuleId}…";
        SelectedNavigationItem = NavigationItems[0]; // Agent tab
        Agent.VerifySelectedCommand.Execute(null);

        await Agent.VerifySelectedCommand.ExecutionTask;
        SummaryText = Agent.LastOperationSucceeded
            ? $"Verification of {selected.RuleId} ready in the Agent tab."
            : $"Verification of {selected.RuleId} did not complete — see the Agent tab.";

        if (Agent.LastOperationSucceeded)
        {
            await _analystActionLogger.LogFindingVerifiedAsync("avalonia", selected.RuleId);
        }
    }

    private async Task ResolveFindingAsync(object? parameter)
    {
        if (parameter is FindingItemViewModel item)
        {
            Findings.SelectedItem = item;
        }

        var selected = Findings.SelectedItem?.Finding;
        if (selected == null || string.IsNullOrEmpty(selected.RuleId))
        {
            SummaryText = "Select a finding with a rule ID to resolve.";
            return;
        }

        var plan = _remediationPlanBuilder.Build(new[] { selected });
        var validation = RemediationPlanValidator.Validate(plan);
        if (!validation.IsValid)
        {
            SummaryText = $"Resolve blocked for {selected.RuleId}: {string.Join(", ", validation.Errors)}.";
            return;
        }

        if (plan.Sections.Count == 0)
        {
            SummaryText = $"No remediation guidance available for {selected.RuleId}.";
            return;
        }

        var formatter = new RemediationMarkdownFormatter();
        var markdown = formatter.Format(plan);
        await ExportRemediationPlanAsync(markdown);
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

    private void InjectCountermeasureMessages(TraceMapResult traceMap)
    {
        if (traceMap.CriticalChains.Count == 0)
            return;

        var countermeasurePlan = _remediationPlanBuilder.BuildCountermeasures(traceMap);
        foreach (var section in countermeasurePlan.Sections)
        {
            Agent.AddCountermeasureMessage(section);
        }
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

        _analystActionStore.Changed -= _analystActionStoreChangedHandler;

        if (Evidence != null)
        {
            Evidence.StatusChanged -= _evidenceStatusHandler;
            Evidence.ExportCompleted -= _evidenceExportCompletedHandler;
            Evidence.Dispose();
        }

        if (Agent != null)
        {
            Agent.AuditCompleted -= OnAgentAuditCompleted;
            Agent.PropertyChanged -= _agentPropertyChangedHandler;
            Agent.Dispose();
        }

        if (Findings != null)
        {
            Findings.PropertyChanged -= _findingsPropertyChangedHandler;
        }

        if (LiveStream != null)
        {
            LiveStream.LiveResultReceived -= _liveResultHandler;
            LiveStream.DemoCompleted -= _demoCompletedHandler;
            LiveStream.Dispose();
        }
    }
}
