using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class MainViewModelTests : IAsyncLifetime
{
    private MainViewModel _vm = null!;

    public Task InitializeAsync()
    {
        _vm = BuildViewModel();
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _vm.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public void AnalyzeCommand_RequiresLogText()
    {
        Assert.False(_vm.AnalyzeCommand.CanExecute(null));

        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        Assert.True(_vm.AnalyzeCommand.CanExecute(null));
    }

    [Fact]
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

    [Fact]
    [Trait("Category", "Timing")]
    public async Task CancelCommand_CancelsActiveAnalysis()
    {
        _vm.LogText = new string('k', 100_000);
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

    [Fact]
    public void SelectedIntensity_ChangesAnalyzeCommandState()
    {
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        _vm.SelectedIntensity = null;
        Assert.False(_vm.AnalyzeCommand.CanExecute(null));

        _vm.SelectedIntensity = _vm.Intensities[0];
        Assert.True(_vm.AnalyzeCommand.CanExecute(null));
    }

    [Fact]
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

    [Fact]
    public async Task ParseErrors_AffectSummaryText()
    {
        _vm.LogText = "not a valid log line at all\nmore garbage";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.Contains("parse error", _vm.SummaryText);
    }

    [Fact]
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

    [Fact]
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

    [Fact]
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

    private static async Task WaitForBusyAsync(MainViewModel vm, int timeoutMs = 10000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (vm.IsBusy && Environment.TickCount64 < deadline)
        {
            await Task.Delay(50);
        }
    }

    private static MainViewModel BuildViewModel(ISuppressionStore? suppressionStore = null, IAgent? agent = null)
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();

        var baselineDetectors = new IDetector[]
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
        var evidenceBuilder = new EvidenceBuilder(hasher, new CsvFormatter(), new MarkdownFormatter(), new HtmlFormatter());

        return new MainViewModel(
            analyzer,
            evidenceBuilder,
            new TestDialogService(),
            profileProvider,
            agent ?? new MockAgent(),
            suppressionStore ?? new InMemorySuppressionStore(),
            new InMemoryAuditHistoryStore());
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

        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "")
        {
            return Task.FromResult<string?>(null);
        }

        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0)
        {
            return Task.FromResult<int?>(null);
        }
    }
}
