using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.LogDiff;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class LogDiffViewModelTests
{
    [AvaloniaFact]
    public void LoadDiff_CopiesEventsFindingsAndCountsIntoViewModel()
    {
        var result = new LogDiffResult
        {
            Events =
            [
                new DiffEvent
                {
                    ConnectionKey = "10.0.0.1:*-192.168.1.1:443-TCP",
                    State = LogDiffState.Added,
                    BaselineCount = 0,
                    IncidentCount = 3,
                    SourceIP = "10.0.0.1",
                    DestinationIP = "192.168.1.1",
                    DestinationPort = 443,
                    Protocol = "TCP"
                },
                new DiffEvent
                {
                    ConnectionKey = "10.0.0.2:*-192.168.1.1:22-TCP",
                    State = LogDiffState.Unchanged,
                    BaselineCount = 2,
                    IncidentCount = 2,
                    SourceIP = "10.0.0.2",
                    DestinationIP = "192.168.1.1",
                    DestinationPort = 22,
                    Protocol = "TCP"
                }
            ],
            Findings =
            [
                new DiffFinding
                {
                    State = LogDiffState.Added,
                    Finding = new Finding
                    {
                        Category = FindingCategories.PortScan,
                        Severity = Severity.High,
                        SourceHost = "10.0.0.1",
                        Target = "192.168.1.1:443",
                        TimeRangeStart = DateTime.UtcNow,
                        TimeRangeEnd = DateTime.UtcNow.AddMinutes(1),
                        ShortDescription = "Port scan detected",
                        Details = "Details"
                    }
                }
            ]
        };
        var vm = new LogDiffViewModel();

        vm.LoadDiff(result);

        Assert.Equal(2, vm.Events.Count);
        Assert.Single(vm.Findings);
        Assert.Equal(1, vm.AddedCount);
        Assert.Equal(1, vm.UnchangedCount);
        Assert.Equal(1, vm.AddedFindingsCount);
        Assert.Contains("1 new traffic pattern", vm.Narrative);
    }

    [AvaloniaFact]
    public void ExportCommands_CanExecute_WhenResultLoaded()
    {
        var vm = new LogDiffViewModel(new FakeDialogService());
        Assert.False(vm.ExportHtmlCommand.CanExecute(null));
        Assert.False(vm.ExportMarkdownCommand.CanExecute(null));

        vm.LoadDiff(CreateDiffResult());

        Assert.True(vm.ExportHtmlCommand.CanExecute(null));
        Assert.True(vm.ExportMarkdownCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task ExportHtmlCommand_WritesHtmlFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"vt-logdiff-html-{Guid.NewGuid()}.html");
        var dialog = new FakeDialogService { SaveResult = path };
        var vm = new LogDiffViewModel(dialog);
        vm.LoadDiff(CreateDiffResult());

        vm.ExportHtmlCommand.Execute(null);
        await vm.ExportHtmlCommand.ExecutionTask;

        Assert.True(File.Exists(path));
        var content = await File.ReadAllTextAsync(path);
        Assert.Contains("Log Diff Report", content);
        Assert.Contains(path, vm.StatusMessage);
        File.Delete(path);
    }

    [AvaloniaFact]
    public async Task ExportMarkdownCommand_WritesMarkdownFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"vt-logdiff-md-{Guid.NewGuid()}.md");
        var dialog = new FakeDialogService { SaveResult = path };
        var vm = new LogDiffViewModel(dialog);
        vm.LoadDiff(CreateDiffResult());

        vm.ExportMarkdownCommand.Execute(null);
        await vm.ExportMarkdownCommand.ExecutionTask;

        Assert.True(File.Exists(path));
        var content = await File.ReadAllTextAsync(path);
        Assert.Contains("# Log Diff Report", content);
        Assert.Contains(path, vm.StatusMessage);
        File.Delete(path);
    }

    [AvaloniaFact]
    public async Task ExportHtmlCommand_SetsCancelledStatus_WhenDialogCancelled()
    {
        var dialog = new FakeDialogService { SaveResult = null };
        var vm = new LogDiffViewModel(dialog);
        vm.LoadDiff(CreateDiffResult());

        vm.ExportHtmlCommand.Execute(null);
        await vm.ExportHtmlCommand.ExecutionTask;

        Assert.Equal("Export cancelled.", vm.StatusMessage);
    }

    [AvaloniaFact]
    public async Task LoadDiff_ClearsExportStatusAndNotifiesVisibility()
    {
        var dialog = new FakeDialogService { SaveResult = null };
        var vm = new LogDiffViewModel(dialog);
        vm.LoadDiff(CreateDiffResult());

        vm.ExportHtmlCommand.Execute(null);
        await vm.ExportHtmlCommand.ExecutionTask;
        Assert.True(vm.HasStatusMessage);

        var changedProperties = new List<string?>();
        vm.PropertyChanged += (_, e) => changedProperties.Add(e.PropertyName);

        vm.LoadDiff(CreateDiffResult());

        Assert.Empty(vm.StatusMessage);
        Assert.False(vm.HasStatusMessage);
        Assert.Contains(nameof(LogDiffViewModel.StatusMessage), changedProperties);
        Assert.Contains(nameof(LogDiffViewModel.HasStatusMessage), changedProperties);
    }

    private static LogDiffResult CreateDiffResult() => new()
    {
        Events =
        [
            new DiffEvent
            {
                ConnectionKey = "10.0.0.1:*-192.168.1.1:443-TCP",
                State = LogDiffState.Added,
                BaselineCount = 0,
                IncidentCount = 3,
                SourceIP = "10.0.0.1",
                DestinationIP = "192.168.1.1",
                DestinationPort = 443,
                Protocol = "TCP"
            }
        ],
        Findings = Array.Empty<DiffFinding>()
    };

    private sealed class FakeDialogService : IDialogService
    {
        public string? SaveResult { get; set; }

        public void ShowMessage(string message, string title) { }
        public void ShowError(string message, string title) { }
        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName) =>
            Task.FromResult(SaveResult);
        public Task<string?> ShowOpenFileDialogAsync(string title, string filter) => Task.FromResult<string?>(null);
        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "") =>
            Task.FromResult<string?>(null);
        public Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel) =>
            Task.FromResult<bool?>(null);
        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0) =>
            Task.FromResult<int?>(null);
    }
}
