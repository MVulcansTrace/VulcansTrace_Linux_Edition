using System;
using System.Threading.Tasks;
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
    [Fact]
    public void SetEvidenceContext_EnablesExport()
    {
        var vm = new EvidenceViewModel(BuildEvidenceBuilder(), new TestDialogService());
        var result = new AnalysisResult();

        Assert.False(vm.ExportEvidenceCommand.CanExecute(null));

        vm.SetEvidenceContext(result, "log", DateTime.UnixEpoch);

        Assert.True(vm.ExportEvidenceCommand.CanExecute(null));
    }

    [Fact]
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

    [Fact]
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

    [Fact]
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

    [Fact]
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

    [Fact]
    public void CopySigningKey_BeforeContext_CommandDisabled()
    {
        var vm = new EvidenceViewModel(BuildEvidenceBuilder(), new TestDialogService());

        Assert.False(vm.CopySigningKeyCommand.CanExecute(null));
    }

    [Fact]
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

    [Fact]
    public async Task ExportEvidenceAsync_WhenSaveDialogCancelled_DoesNotBuildBundle()
    {
        var dialogService = new TestDialogService();
        var brokenBuilder = new EvidenceBuilder(null!, null!, null!, null!, null, null, null, null, null, null);
        var vm = new EvidenceViewModel(brokenBuilder, dialogService);
        var statuses = new List<string>();
        vm.StatusChanged += (_, status) => statuses.Add(status);

        vm.SetEvidenceContext(new AnalysisResult(), "log", DateTime.UnixEpoch);

        vm.ExportEvidenceCommand.Execute(null);
        await ((AsyncRelayCommand)vm.ExportEvidenceCommand).ExecutionTask;

        Assert.Contains("Export cancelled by user.", statuses);
        Assert.Empty(dialogService.Errors);
    }

    private static EvidenceBuilder BuildEvidenceBuilder()
    {
        var hasher = new IntegrityHasher();
        return new EvidenceBuilder(hasher, new CsvFormatter(), new MarkdownFormatter(), new HtmlFormatter(), null, null, null, null, new RiskScorecardHtmlFormatter(), new RiskScorecardMarkdownFormatter());
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
