using System;
using System.Collections.Specialized;
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Media;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.Rules.SecurityRules;
using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Logging;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Evidence.Formatters;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core.Security;

namespace VulcansTrace.Linux.Avalonia;

/// <summary>
/// Interaction logic for MainWindow.axaml
/// </summary>
public partial class MainWindow : Window
{
    private TimelineViewModel? _timelineViewModel;

    public MainWindow()
    {
        InitializeComponent();

        // Wire up the complete engine chain
        var logSink = new DiagnosticsLogSink();
        var logNormalizer = new LogNormalizer(logSink);
        var profileProvider = new AnalysisProfileProvider();

        // Baseline detectors (ported from Windows)
        var baselineDetectors = new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            new LateralMovementDetector(),
            new BeaconingDetector(),
            new PolicyViolationDetector(),
            new NoveltyDetector()
        };

        // Linux-specific detectors
        var linuxDetectors = new IDetector[]
        {
            new FlagAnomalyDetector(),
            new MacSpoofingDetector(),
            new KernelModuleDetector(),
            new InterfaceHoppingDetector(),
            new UnusualPacketSizeDetector()
        };

        // Advanced threat detectors
        var advancedDetectors = new IDetector[]
        {
            new C2ChannelDetector(),
            new PrivilegeEscalationDetector()
        };

        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(logNormalizer, profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, riskEscalator, logSink);

        // Wire up evidence building
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var jsonFormatter = new JsonFormatter();
        var stixFormatter = new StixFormatter();
        var evidenceBuilder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter, jsonFormatter, stixFormatter);

        // Wire up the security agent
        var scanners = new IScanner[]
        {
            new FirewallScanner(),
            new PortScanner(),
            new ServiceScanner(),
            new NetworkScanner()
        };

        var rules = new IRule[]
        {
            new FirewallActiveRule(),
            new FirewallDefaultDropRule(),
            new FirewallSshExposureRule(),
            new FirewallStateTrackingRule(),
            new FirewallIcmpRule(),
            new DefaultRouteRule(),
            new SuspiciousConnectionsRule(),
            new NetworkInterfaceUpRule(),
            new LoopbackExposureRule(),
            new TelnetServiceRule(),
            new FtpServiceRule(),
            new SshServiceRule(),
            new LegacyRservicesRule(),
            new UnnecessaryServicesRule(),
            new SshNonDefaultPortRule(),
            new WideOpenServicesRule(),
            new DatabasePortExposureRule(),
            new HighPortListeningRule()
        };

        var explanationProvider = new ExplanationProvider();
        ISuppressionStore suppressionStore;
        try
        {
            suppressionStore = JsonFileSuppressionStore.CreateDefault();
        }
        catch
        {
            suppressionStore = new InMemorySuppressionStore("Suppression persistence is unavailable. Accepted risks will last only for this session.");
        }

        IRulePolicyProvider? policyProvider;
        try
        {
            var jsonPolicyStore = JsonRulePolicyStore.CreateDefault();
            policyProvider = new DefaultRulePolicyProvider(jsonPolicyStore);
        }
        catch
        {
            policyProvider = new DefaultRulePolicyProvider();
        }

        IAuditHistoryStore auditHistoryStore;
        try
        {
            auditHistoryStore = JsonFileAuditHistoryStore.CreateDefault();
        }
        catch
        {
            auditHistoryStore = new InMemoryAuditHistoryStore("Audit history persistence is unavailable. History will last only for this session.");
        }

        var agent = new SecurityAgent(scanners, rules, explanationProvider, analyzer, profileProvider, suppressionStore, MachineRole.Workstation, policyProvider);
        var ruleCatalog = new RuleCatalog(rules);

        var dialogService = new AvaloniaDialogService(this);
        var viewModel = new MainViewModel(analyzer, evidenceBuilder, dialogService, profileProvider, agent, suppressionStore, auditHistoryStore);
        viewModel.RuleCatalog.LoadCatalog(ruleCatalog);
        viewModel.Agent.ShowAuditDiffAction = diff =>
        {
            var window = new Views.AuditDiffWindow();
            window.ViewModel.LoadDiff(diff);
            window.ShowDialog(this);
        };
        DataContext = viewModel;

        DataContextChanged += (_, _) => HookTimelineViewModel();
        TimelineCanvas.SizeChanged += (_, _) => RenderTimeline();
        Closed += OnClosed;
        HookTimelineViewModel();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        UnhookTimelineViewModel();

        if (DataContext is MainViewModel vm)
        {
            vm.Dispose();
        }
    }

    private void UnhookTimelineViewModel()
    {
        if (_timelineViewModel != null)
        {
            _timelineViewModel.TimelineEntries.CollectionChanged -= OnTimelineCollectionChanged;
            _timelineViewModel.Categories.CollectionChanged -= OnTimelineCollectionChanged;
            _timelineViewModel.PropertyChanged -= OnTimelinePropertyChanged;
            _timelineViewModel = null;
        }
    }

    private void HookTimelineViewModel()
    {
        UnhookTimelineViewModel();

        _timelineViewModel = (DataContext as MainViewModel)?.Timeline;

        if (_timelineViewModel != null)
        {
            _timelineViewModel.TimelineEntries.CollectionChanged += OnTimelineCollectionChanged;
            _timelineViewModel.Categories.CollectionChanged += OnTimelineCollectionChanged;
            _timelineViewModel.PropertyChanged += OnTimelinePropertyChanged;
        }

        RenderTimeline();
    }

    private void OnTimelineCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        RenderTimeline();
    }

    private void OnTimelinePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        RenderTimeline();
    }

    private void RenderTimeline()
    {
        if (TimelineCanvas == null)
        {
            return;
        }

        TimelineCanvas.Children.Clear();

        if (_timelineViewModel == null || _timelineViewModel.TimelineEntries.Count == 0)
        {
            return;
        }

        var width = TimelineCanvas.Bounds.Width;
        if (width <= 0)
        {
            return;
        }

        const double leftPadding = 8;
        const double rightPadding = 8;
        var usableWidth = Math.Max(1, width - leftPadding - rightPadding);

        foreach (var entry in _timelineViewModel.TimelineEntries)
        {
            var start = leftPadding + (entry.StartPosition * usableWidth);
            var end = leftPadding + (entry.EndPosition * usableWidth);
            var barWidth = Math.Max(2, end - start);

            var bar = new Border
            {
                Width = barWidth,
                Height = _timelineViewModel.RowHeight,
                Background = GetSeverityBrush(entry.Severity),
                CornerRadius = new CornerRadius(3)
            };

            var tip = $"{entry.Category} | {entry.Severity}\n{entry.Description}\n{entry.StartTime:O} – {entry.EndTime:O}";
            ToolTip.SetTip(bar, tip);

            Canvas.SetLeft(bar, start);
            Canvas.SetTop(bar, entry.TopPosition);

            TimelineCanvas.Children.Add(bar);
        }
    }

    private static IBrush GetSeverityBrush(Severity severity)
    {
        return severity switch
        {
            Severity.Critical => new SolidColorBrush(Color.Parse("#ef4444")),
            Severity.High => new SolidColorBrush(Color.Parse("#f97316")),
            Severity.Medium => new SolidColorBrush(Color.Parse("#eab308")),
            Severity.Low => new SolidColorBrush(Color.Parse("#22c55e")),
            _ => new SolidColorBrush(Color.Parse("#64748b"))
        };
    }
}
