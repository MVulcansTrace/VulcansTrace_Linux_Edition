using System.Threading;
using System.Threading.Tasks;
using System.Reflection;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Engine.Live;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class MainViewModelTests : IAsyncLifetime
{
    private MainViewModel _vm = null!;

    public ValueTask InitializeAsync()
    {
        _vm = BuildViewModel();
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        _vm.Dispose();
        return ValueTask.CompletedTask;
    }

    [AvaloniaFact]
    public void Constructor_WiresFindingsCommands()
    {
        Assert.Same(_vm.InvestigateCommand, _vm.Findings.InvestigateCommand);
        Assert.Same(_vm.SuppressCommand, _vm.Findings.SuppressCommand);
        Assert.Same(_vm.ResolveCommand, _vm.Findings.ResolveCommand);
    }

    [AvaloniaFact]
    public void InvestigateCommand_CanExecute_WhenParameterIsFindingItem()
    {
        var item = new FindingItemViewModel(new Finding { RuleId = "FW-001" });
        Assert.True(_vm.InvestigateCommand.CanExecute(item));
        Assert.False(_vm.InvestigateCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void SuppressCommand_CanExecute_WhenFindingHasRuleId()
    {
        var withRuleId = new FindingItemViewModel(new Finding { RuleId = "FW-001" });
        var withoutRuleId = new FindingItemViewModel(new Finding { RuleId = "" });

        Assert.True(_vm.SuppressCommand.CanExecute(withRuleId));
        Assert.False(_vm.SuppressCommand.CanExecute(withoutRuleId));
        Assert.False(_vm.SuppressCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void ResolveCommand_CanExecute_WhenFindingHasRuleId()
    {
        var withRuleId = new FindingItemViewModel(new Finding { RuleId = "FW-001" });
        var withoutRuleId = new FindingItemViewModel(new Finding { RuleId = "" });

        Assert.True(_vm.ResolveCommand.CanExecute(withRuleId));
        Assert.False(_vm.ResolveCommand.CanExecute(withoutRuleId));
        Assert.False(_vm.ResolveCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void AnalyzeCommand_RequiresLogText()
    {
        Assert.False(_vm.AnalyzeCommand.CanExecute(null));

        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        Assert.True(_vm.AnalyzeCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task AnalyzeAsync_SuccessfulAnalysis_UpdatesAllProperties()
    {
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.NotNull(_vm.LastResult);
        Assert.NotEmpty(_vm.SummaryText);
        Assert.Equal(1, _vm.LastResult.ParsedLines);
        Assert.Single(_vm.LastResult.Entries);
    }

    [AvaloniaFact]
    [Trait("Category", "Timing")]
    public async Task CancelCommand_CancelsActiveAnalysis()
    {
        _vm.Dispose();
        _vm = BuildViewModel(baselineDetectors: [new BlockingDetector()]);
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);

        // Wait until the analysis has actually started before cancelling
        var busyDeadline = Environment.TickCount64 + 5000;
        while (!_vm.IsBusy && Environment.TickCount64 < busyDeadline)
        {
            await Task.Delay(10);
        }

        _vm.CancelCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.Contains("cancelled", _vm.SummaryText.ToLowerInvariant());
    }

    [AvaloniaFact]
    public void SelectedIntensity_ChangesAnalyzeCommandState()
    {
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        _vm.SelectedIntensity = null;
        Assert.False(_vm.AnalyzeCommand.CanExecute(null));

        _vm.SelectedIntensity = _vm.Intensities[0];
        Assert.True(_vm.AnalyzeCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task OverrideFields_FlowIntoProfile()
    {
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22\nkernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.10 DST=10.0.0.1 PROTO=TCP SPT=54322 DPT=80";
        _vm.SelectedIntensity = _vm.Intensities[2];
        _vm.PortScanMinPorts = 1;

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.NotNull(_vm.LastResult);
        Assert.Contains(_vm.LastResult.Findings, finding => finding.Category == FindingCategories.PortScan);
    }

    [AvaloniaFact]
    public async Task ParseErrors_AffectSummaryText()
    {
        _vm.LogText = "not a valid log line at all\nmore garbage";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.Contains("parse error", _vm.SummaryText);
    }

    [AvaloniaFact]
    public async Task SkippedLines_AffectSummaryAndFindingsCounts()
    {
        _vm.LogText = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
not a firewall line
also not a firewall line";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.NotNull(_vm.LastResult);
        Assert.Equal(2, _vm.LastResult.SkippedLineCount);
        Assert.Equal(2, _vm.Findings.SkippedLineCount);
        Assert.Contains("2 lines skipped", _vm.SummaryText);
    }

    [AvaloniaFact]
    public async Task LogTextChangedAfterAnalysis_InvalidatesExportContext()
    {
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.NotNull(_vm.LastResult);
        Assert.True(_vm.Evidence.ExportEvidenceCommand.CanExecute(null));
        Assert.NotEmpty(_vm.Evidence.SigningKey);

        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.20 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=443";

        Assert.Null(_vm.LastResult);
        Assert.False(_vm.Evidence.ExportEvidenceCommand.CanExecute(null));
        Assert.Empty(_vm.Evidence.SigningKey);
        Assert.Equal(0, _vm.Findings.FindingsCount);
        Assert.Contains("Log changed", _vm.SummaryText);
    }

    [AvaloniaFact]
    public async Task AgentAuditCompleted_RefreshesSuppressionReviewQueue()
    {
        var suppressionStore = new InMemorySuppressionStore();
        suppressionStore.Add(new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "A",
            CreatedAt = DateTime.UtcNow.AddDays(-100)
        });

        using var vm = BuildViewModel(suppressionStore: suppressionStore);
        Assert.Single(vm.Suppressions.ReviewQueueItems);

        suppressionStore.Remove("FW-001", "A");

        vm.Agent.FullAuditCommand.Execute(null);
        await vm.Agent.FullAuditCommand.ExecutionTask!;

        Assert.Empty(vm.Suppressions.ReviewQueueItems);
    }

    [AvaloniaFact]
    public void DemoCompleted_ReplacesStaleFindingsWithDemoFindings()
    {
        var oldFinding = CreateFinding(FindingCategories.PortScan, "10.0.0.1");
        var demoFinding = CreateFinding(FindingCategories.Flood, "10.99.99.100");
        _vm.Findings.AddFinding(oldFinding);

        var method = typeof(MainViewModel).GetMethod("OnDemoCompleted", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        method.Invoke(_vm, new object[]
        {
            new DemoCompletedEventArgs(
                "Demo: SSH Brute Force",
                new[] { demoFinding },
                true,
                TimeSpan.FromSeconds(60),
                DateTime.UtcNow.AddSeconds(-60),
                DateTime.UtcNow)
        });

        Assert.Single(_vm.Findings.Items);
        Assert.Equal(FindingCategories.Flood, _vm.Findings.Items[0].Finding.Category);
        Assert.DoesNotContain(_vm.Findings.Items, item => item.Finding.Category == FindingCategories.PortScan);
        Assert.True(_vm.Evidence.ExportEvidenceCommand.CanExecute(null));
    }

    private static async Task WaitForBusyAsync(MainViewModel vm, int timeoutMs = 10000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (vm.IsBusy && Environment.TickCount64 < deadline)
        {
            await Task.Delay(50);
        }
    }

    private static Finding CreateFinding(string category, string sourceHost)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            Category = category,
            Severity = Severity.High,
            Confidence = DetectionConfidence.High,
            SourceHost = sourceHost,
            Target = "demo-target",
            TimeRangeStart = now,
            TimeRangeEnd = now.AddSeconds(1),
            ShortDescription = $"{category} test finding",
            Details = $"{category} test details"
        };
    }

    private static MainViewModel BuildViewModel(
        ISuppressionStore? suppressionStore = null,
        IAgent? agent = null,
        IDetector[]? baselineDetectors = null)
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();

        baselineDetectors ??= new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            new LateralMovementDetector(),
            new BeaconingDetector(),
            new PolicyViolationDetector(),
            new NoveltyDetector()
        };

        var linuxDetectors = new IDetector[]
        {
            new FlagAnomalyDetector(),
            new MacSpoofingDetector(),
            new KernelModuleDetector(),
            new InterfaceHoppingDetector(),
            new UnusualPacketSizeDetector()
        };

        var advancedDetectors = new IDetector[]
        {
            new C2ChannelDetector(),
            new PrivilegeEscalationDetector()
        };

        var analyzer = new SentryAnalyzer(logNormalizer, profileProvider, baselineDetectors, linuxDetectors, advancedDetectors, new RiskEscalator());

        var hasher = new IntegrityHasher();
        var evidenceBuilder = new EvidenceBuilder(
            hasher,
            new CsvFormatter(),
            new MarkdownFormatter(),
            new HtmlFormatter(),
            jsonFormatter: null,
            stixFormatter: null,
            scorecardHtmlFormatter: null,
            scorecardMarkdownFormatter: null,
            riskScorecardHtmlFormatter: new RiskScorecardHtmlFormatter(),
            riskScorecardMarkdownFormatter: new RiskScorecardMarkdownFormatter(),
            traceMapMarkdownFormatter: new TraceMapMarkdownFormatter(),
            traceMapJsonFormatter: new TraceMapJsonFormatter(),
            incidentStoryFormatter: new IncidentStoryFormatter());

        var liveStreamAnalyzer = new LiveStreamAnalyzer(analyzer, profileProvider);
        var remediationExecutor = new RemediationExecutor(new ProcessRunner());

        return new MainViewModel(
            analyzer,
            evidenceBuilder,
            new TestDialogService(),
            profileProvider,
            agent ?? new MockAgent(),
            suppressionStore ?? new InMemorySuppressionStore(),
            new InMemoryAuditHistoryStore(),
            new RemediationPlanBuilder(new ExplanationProvider()),
            remediationExecutor,
            new TraceMapCorrelator(),
            liveStreamAnalyzer);
    }

    private sealed class MockAgent : IAgent
    {
        public Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = "Mock agent response",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = intent,
                Summary = "Mock audit complete",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "Mock explanation",
                AgentFindings = new List<Finding> { finding },
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "Mock baseline set",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "Mock drift check",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "Mock baseline",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Mock remediation session",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = "Mock verification",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Mock export",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "Mock list",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ResumeRemediation,
                Summary = "Mock resume",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "Mock deleted",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.AddSessionNote,
                Summary = "Mock session note",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = "Mock step note",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }
    }

    private sealed class TestDialogService : IDialogService
    {
        public void ShowMessage(string message, string title)
        {
        }

        public void ShowError(string message, string title)
        {
        }

        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName)
        {
            return Task.FromResult<string?>(null);
        }

        public Task<string?> ShowOpenFileDialogAsync(string title, string filter)
        {
            return Task.FromResult<string?>(null);
        }

        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "")
        {
            return Task.FromResult<string?>(null);
        }

        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0)
        {
            return Task.FromResult<int?>(null);
        }
    }

    private sealed class BlockingDetector : IDetector
    {
        public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Thread.Sleep(10);
            }
        }
    }
}
