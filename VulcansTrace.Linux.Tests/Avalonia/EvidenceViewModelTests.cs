using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class EvidenceViewModelTests
{
    [AvaloniaFact]
    public void SetEvidenceContext_EnablesExport()
    {
        var vm = new EvidenceViewModel(BuildEvidenceBuilder(), new TestDialogService());
        var result = new AnalysisResult();

        Assert.False(vm.ExportEvidenceCommand.CanExecute(null));

        vm.SetEvidenceContext(result, "log", DateTime.UnixEpoch);

        Assert.True(vm.ExportEvidenceCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void SetEvidenceContext_GeneratesSigningKey()
    {
        var vm = new EvidenceViewModel(BuildEvidenceBuilder(), new TestDialogService());
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            Findings = Array.Empty<Finding>()
        };

        Assert.Equal(string.Empty, vm.SigningKey);

        vm.SetEvidenceContext(result, "log", DateTime.UnixEpoch);

        Assert.NotEmpty(vm.SigningKey);
        Assert.NotEmpty(vm.MaskedSigningKey);
        Assert.All(vm.SigningKey, c => Assert.True(Uri.IsHexDigit(c)));
    }

    [AvaloniaFact]
    public void SetEvidenceContext_MaskedSigningKey_HidesActualKey()
    {
        var vm = new EvidenceViewModel(BuildEvidenceBuilder(), new TestDialogService());
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            Findings = Array.Empty<Finding>()
        };

        vm.SetEvidenceContext(result, "log", DateTime.UnixEpoch);

        Assert.Equal(new string('*', vm.SigningKey.Length), vm.MaskedSigningKey);
        Assert.DoesNotContain(vm.SigningKey, vm.MaskedSigningKey);
    }

    [AvaloniaFact]
    public async Task ExportEvidenceAsync_GeneratesBundleWithSameKey()
    {
        var dialogService = new TestDialogService();
        var vm = new EvidenceViewModel(BuildEvidenceBuilder(), dialogService);
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            Findings = Array.Empty<Finding>()
        };

        vm.SetEvidenceContext(result, "log", DateTime.UnixEpoch);
        var keyAfterContext = vm.SigningKey;

        vm.ExportEvidenceCommand.Execute(null);
        await ((AsyncRelayCommand)vm.ExportEvidenceCommand).ExecutionTask;

        Assert.Equal(keyAfterContext, vm.SigningKey);
    }

    [AvaloniaFact]
    public async Task ExportEvidenceTwice_ProducesSameSigningKey()
    {
        var dialogService = new TestDialogService();
        var vm = new EvidenceViewModel(BuildEvidenceBuilder(), dialogService);
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            Findings = Array.Empty<Finding>()
        };

        vm.SetEvidenceContext(result, "log", DateTime.UnixEpoch);

        vm.ExportEvidenceCommand.Execute(null);
        await ((AsyncRelayCommand)vm.ExportEvidenceCommand).ExecutionTask;
        var keyAfterFirstExport = vm.SigningKey;

        dialogService.SaveDialogTcs = new TaskCompletionSource<string?>();
        vm.ExportEvidenceCommand.Execute(null);
        await ((AsyncRelayCommand)vm.ExportEvidenceCommand).ExecutionTask;
        var keyAfterSecondExport = vm.SigningKey;

        Assert.Equal(keyAfterFirstExport, keyAfterSecondExport);
    }

    [AvaloniaFact]
    public void CopySigningKey_BeforeContext_CommandDisabled()
    {
        var vm = new EvidenceViewModel(BuildEvidenceBuilder(), new TestDialogService());

        Assert.False(vm.CopySigningKeyCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void CopySigningKey_AfterContext_CommandEnabled()
    {
        var vm = new EvidenceViewModel(BuildEvidenceBuilder(), new TestDialogService());
        var result = new AnalysisResult
        {
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            Findings = Array.Empty<Finding>()
        };

        vm.SetEvidenceContext(result, "log", DateTime.UnixEpoch);

        Assert.True(vm.CopySigningKeyCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task ExportEvidenceAsync_WhenSaveDialogCancelled_DoesNotBuildBundle()
    {
        var dialogService = new TestDialogService();
        var brokenBuilder = new EvidenceBuilder(
            hasher: null!,
            csvFormatter: null!,
            markdownFormatter: null!,
            htmlFormatter: null!);
        var vm = new EvidenceViewModel(brokenBuilder, dialogService);
        var statuses = new List<string>();
        vm.StatusChanged += (_, status) => statuses.Add(status);

        vm.SetEvidenceContext(new AnalysisResult(), "log", DateTime.UnixEpoch);

        vm.ExportEvidenceCommand.Execute(null);
        await ((AsyncRelayCommand)vm.ExportEvidenceCommand).ExecutionTask;

        Assert.Contains("Export cancelled by user.", statuses);
        Assert.Empty(dialogService.Errors);
    }

    [AvaloniaFact]
    public async Task CancelExport_DuringCancellableBuild_ClearsBusyWithoutWritingFile()
    {
        var output = Path.Combine(Path.GetTempPath(), $"vt-cancel-export-{Guid.NewGuid():N}.zip");
        var dialogService = new TestDialogService();
        var statuses = new List<string>();
        var vm = new EvidenceViewModel(
            BuildEvidenceBuilder(),
            dialogService,
            exportPathOverride: () => output,
            beforeBuildAsync: token => Task.Delay(Timeout.InfiniteTimeSpan, token));
        vm.StatusChanged += (_, status) => statuses.Add(status);
        vm.SetEvidenceContext(new AnalysisResult(), "log", DateTime.UnixEpoch);

        vm.ExportEvidenceCommand.Execute(null);
        var deadline = Environment.TickCount64 + 2_000;
        while (!vm.IsBusy && Environment.TickCount64 < deadline)
            await Task.Delay(10);

        Assert.True(vm.IsBusy);
        Assert.True(vm.CancelExportCommand.CanExecute(null));

        vm.CancelExportCommand.Execute(null);
        await vm.ExportEvidenceCommand.ExecutionTask;

        Assert.False(vm.IsBusy);
        Assert.False(vm.CancelExportCommand.CanExecute(null));
        Assert.Contains("Export cancelled by user.", statuses);
        Assert.False(File.Exists(output));
    }

    [AvaloniaFact]
    public async Task ExportEvidenceAsync_LogsAnalystActionReceiptWithPath()
    {
        var output = Path.Combine(Path.GetTempPath(), $"vt-export-receipt-{Guid.NewGuid():N}.zip");
        var store = new InMemoryAnalystActionStore();
        var logger = new AnalystActionLogger(store);
        var vm = new EvidenceViewModel(
            BuildEvidenceBuilder(),
            new TestDialogService(),
            exportPathOverride: () => output,
            analystActionLogger: logger);
        vm.SetEvidenceContext(new AnalysisResult(), "log", DateTime.UnixEpoch);

        vm.ExportEvidenceCommand.Execute(null);
        await vm.ExportEvidenceCommand.ExecutionTask;

        var entry = Assert.Single(store.GetAll());
        Assert.Equal(AnalystActionType.EvidenceExported, entry.ActionType);
        Assert.Equal(output, entry.Target);
        Assert.Equal("avalonia", entry.Actor);
    }

    private static EvidenceBuilder BuildEvidenceBuilder()
    {
        var hasher = new IntegrityHasher();
        return new EvidenceBuilder(
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
            traceMapJsonFormatter: new TraceMapJsonFormatter());
    }

    private sealed class TestDialogService : IDialogService
    {
        public TaskCompletionSource<string?> SaveDialogTcs { get; set; } = new();
        public List<string> Errors { get; } = new();

        public void ShowMessage(string message, string title)
        {
        }

        public void ShowError(string message, string title)
        {
            Errors.Add(message);
        }

        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName)
        {
            SaveDialogTcs.TrySetResult(null);
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

        public Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel)
        {
            return Task.FromResult<bool?>(null);
        }

        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0)
        {
            return Task.FromResult<int?>(null);
        }
    }
}
