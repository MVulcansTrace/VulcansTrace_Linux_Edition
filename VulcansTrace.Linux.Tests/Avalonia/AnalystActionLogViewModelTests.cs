using System;
using System.IO;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public class AnalystActionLogViewModelTests
{
    [AvaloniaFact]
    public void Constructor_Refresh_LoadsEntries()
    {
        var store = new InMemoryAnalystActionStore();
        store.Append(new AnalystActionEntry
        {
            Id = "a1",
            TimestampUtc = DateTime.UtcNow,
            Actor = "avalonia",
            ActionType = AnalystActionType.AuditRan,
            Target = "FullAudit"
        });

        var vm = new AnalystActionLogViewModel(store,new TestDialogService());

        Assert.Single(vm.Entries);
        Assert.Equal("avalonia", vm.Entries[0].Actor);
        Assert.Contains("1 analyst action", vm.StatusMessage);
    }

    [AvaloniaFact]
    public void Refresh_AfterStoreChange_UpdatesEntries()
    {
        var store = new InMemoryAnalystActionStore();
        var vm = new AnalystActionLogViewModel(store,new TestDialogService());

        Assert.Empty(vm.Entries);

        store.Append(new AnalystActionEntry
        {
            Id = "a2",
            TimestampUtc = DateTime.UtcNow,
            Actor = "cli",
            ActionType = AnalystActionType.SuppressionAdded,
            Target = "FW-001"
        });
        vm.Refresh();

        Assert.Single(vm.Entries);
        Assert.Equal(AnalystActionType.SuppressionAdded, vm.Entries[0].ActionType);
    }

    [AvaloniaFact]
    public void Store_Change_AutoRefreshes_AndKeepsStateConsistent()
    {
        var store = new InMemoryAnalystActionStore();
        var vm = new AnalystActionLogViewModel(store, new TestDialogService());

        Assert.False(vm.HasEntries);
        Assert.Equal(0, vm.TotalCount);

        // An action logged elsewhere in the app raises Changed; the VM refreshes on the UI thread.
        // Every observable must stay consistent -- the old bug showed HasEntries=false (empty-state
        // text + hidden grid) while the live-store Clear/Export commands were simultaneously enabled.
        store.Append(new AnalystActionEntry
        {
            Id = "auto-1",
            TimestampUtc = DateTime.UtcNow,
            Actor = "cli",
            ActionType = AnalystActionType.AuditRan
        });

        Assert.True(vm.HasEntries);
        Assert.Equal(1, vm.TotalCount);
        Assert.Single(vm.Entries);
        Assert.True(vm.ClearCommand.CanExecute(null));
        Assert.True(vm.ExportCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task ClearCommand_WithConfirmation_ClearsStore()
    {
        var store = new InMemoryAnalystActionStore();
        store.Append(new AnalystActionEntry
        {
            Id = "a3",
            TimestampUtc = DateTime.UtcNow,
            Actor = "cli",
            ActionType = AnalystActionType.AuditRan
        });

        var dialogService = new ConfirmDialogService(confirm: true);
        var vm = new AnalystActionLogViewModel(store,dialogService);

        vm.ClearCommand.Execute(null);
        await vm.ClearCommand.ExecutionTask;

        Assert.Empty(vm.Entries);
        Assert.Empty(store.GetAll());
    }

    [AvaloniaFact]
    public async Task ClearCommand_Cancelled_DoesNotClear()
    {
        var store = new InMemoryAnalystActionStore();
        store.Append(new AnalystActionEntry
        {
            Id = "a4",
            TimestampUtc = DateTime.UtcNow,
            Actor = "cli",
            ActionType = AnalystActionType.AuditRan
        });

        var dialogService = new ConfirmDialogService(confirm: false);
        var vm = new AnalystActionLogViewModel(store,dialogService);

        vm.ClearCommand.Execute(null);
        await vm.ClearCommand.ExecutionTask;

        Assert.Single(vm.Entries);
        Assert.Single(store.GetAll());
    }

    [AvaloniaFact]
    public async Task ExportCommand_WritesJsonFile()
    {
        var store = new InMemoryAnalystActionStore();
        store.Append(new AnalystActionEntry
        {
            Id = "a5",
            TimestampUtc = DateTime.UtcNow,
            Actor = "cli",
            ActionType = AnalystActionType.ThreatIntelExported,
            Target = "/tmp/out.json",
            Details = "format=stix"
        });

        var outputPath = Path.Combine(Path.GetTempPath(), $"vt-export-{Guid.NewGuid()}.json");
        var dialogService = new SaveFileDialogService(outputPath);
        var vm = new AnalystActionLogViewModel(store,dialogService);

        vm.ExportCommand.Execute(null);
        await vm.ExportCommand.ExecutionTask;

        try
        {
            Assert.True(File.Exists(outputPath));
            var json = await File.ReadAllTextAsync(outputPath);
            Assert.Contains("ThreatIntelExported", json);
            Assert.Contains("/tmp/out.json", json);
        }
        finally
        {
            if (File.Exists(outputPath))
                File.Delete(outputPath);
        }
    }

    private sealed class TestDialogService : IDialogService
    {
        public void ShowMessage(string message, string title) { }
        public void ShowError(string message, string title) { }
        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName) => Task.FromResult<string?>(null);
        public Task<string?> ShowOpenFileDialogAsync(string title, string filter) => Task.FromResult<string?>(null);
        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "") => Task.FromResult<string?>(null);
        public Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel) => Task.FromResult<bool?>(null);
        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0) => Task.FromResult<int?>(null);
    }

    private sealed class ConfirmDialogService : IDialogService
    {
        private readonly bool _confirm;

        public ConfirmDialogService(bool confirm)
        {
            _confirm = confirm;
        }

        public void ShowMessage(string message, string title) { }
        public void ShowError(string message, string title) { }
        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName) => Task.FromResult<string?>(null);
        public Task<string?> ShowOpenFileDialogAsync(string title, string filter) => Task.FromResult<string?>(null);
        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "") => Task.FromResult<string?>(null);
        public Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel) => Task.FromResult<bool?>(null);
        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0) => Task.FromResult<int?>(_confirm ? 0 : 1);
    }

    private sealed class SaveFileDialogService : IDialogService
    {
        private readonly string _path;

        public SaveFileDialogService(string path)
        {
            _path = path;
        }

        public void ShowMessage(string message, string title) { }
        public void ShowError(string message, string title) { }
        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName) => Task.FromResult<string?>(_path);
        public Task<string?> ShowOpenFileDialogAsync(string title, string filter) => Task.FromResult<string?>(null);
        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "") => Task.FromResult<string?>(null);
        public Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel) => Task.FromResult<bool?>(null);
        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0) => Task.FromResult<int?>(null);
    }
}
