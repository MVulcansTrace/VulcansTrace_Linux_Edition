using System.IO;
using System.Linq;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core.ThreatIntel;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class ThreatIntelViewModelTests
{
    [AvaloniaFact]
    public void Filter_ByType_ShowsOnlyMatchingEntries()
    {
        var store = new InMemoryThreatIntelStore();
        var vm = new ThreatIntelViewModel(store, new TestDialogService());

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", Source = "STIX" },
            new IocEntry { Type = IocType.Port, Value = "4444", Source = "STIX" },
            new IocEntry { Type = IocType.Domain, Value = "evil.example.com", Source = "MISP" }
        });
        vm.Refresh();

        Assert.Equal(3, vm.FilteredCount);

        vm.SelectedTypeFilter = vm.TypeFilterOptions.First(o => o.Type == IocType.IPv4);

        Assert.Single(vm.FilteredEntries);
        Assert.Equal("192.168.1.1", vm.FilteredEntries[0].Value);
    }

    [AvaloniaFact]
    public void Filter_BySearchText_MatchesValueSourceAndDescription()
    {
        var store = new InMemoryThreatIntelStore();
        var vm = new ThreatIntelViewModel(store, new TestDialogService());

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", Source = "STIX", Description = "C2 server" },
            new IocEntry { Type = IocType.Domain, Value = "safe.example.com", Source = "MISP", Description = "Known good" }
        });
        vm.Refresh();

        vm.SearchText = "C2";

        Assert.Single(vm.FilteredEntries);
        Assert.Equal("192.168.1.1", vm.FilteredEntries[0].Value);

        vm.SearchText = "MISP";

        Assert.Single(vm.FilteredEntries);
        Assert.Equal("safe.example.com", vm.FilteredEntries[0].Value);

        vm.SearchText = "192.168";

        Assert.Single(vm.FilteredEntries);
        Assert.Equal("192.168.1.1", vm.FilteredEntries[0].Value);
    }

    [AvaloniaFact]
    public void Filter_AllTypes_ShowsAllEntries()
    {
        var store = new InMemoryThreatIntelStore();
        var vm = new ThreatIntelViewModel(store, new TestDialogService());

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", Source = "STIX" },
            new IocEntry { Type = IocType.Port, Value = "4444", Source = "STIX" }
        });
        vm.Refresh();

        vm.SelectedTypeFilter = vm.TypeFilterOptions[0]; // All types

        Assert.Equal(2, vm.FilteredCount);
    }

    [AvaloniaFact]
    public void RemoveSelected_RemovesFromStoreAndGrid()
    {
        var store = new InMemoryThreatIntelStore();
        var vm = new ThreatIntelViewModel(store, new TestDialogService());

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", Source = "STIX" },
            new IocEntry { Type = IocType.Port, Value = "4444", Source = "STIX" }
        });
        vm.Refresh();

        vm.SelectedIoc = vm.FilteredEntries.First(e => e.Value == "192.168.1.1");
        vm.RemoveSelectedCommand.Execute(null);

        Assert.Single(store.GetAll());
        Assert.Equal("4444", store.GetAll()[0].Value);
        Assert.Single(vm.FilteredEntries);
    }

    [AvaloniaFact]
    public async Task RemoveSelected_LogsAnalystAction()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", Source = "STIX" },
            new IocEntry { Type = IocType.Port, Value = "4444", Source = "STIX" }
        });
        var actionStore = new InMemoryAnalystActionStore();
        var vm = new ThreatIntelViewModel(store, new TestDialogService(), new AnalystActionLogger(actionStore));
        vm.Refresh();

        vm.SelectedIoc = vm.FilteredEntries.First(e => e.Value == "192.168.1.1");
        vm.RemoveSelectedCommand.Execute(null);
        await vm.RemoveSelectedCommand.ExecutionTask;

        var entry = Assert.Single(actionStore.GetAll());
        Assert.Equal(AnalystActionType.ThreatIntelRemoved, entry.ActionType);
        Assert.Contains("value=192.168.1.1", entry.Details);
        Assert.Contains("type=IPv4", entry.Details);
    }

    [AvaloniaFact]
    public async Task ClearAll_RemovesAllFromStore()
    {
        var store = new InMemoryThreatIntelStore();
        var vm = new ThreatIntelViewModel(store, new TestDialogService());

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", Source = "STIX" }
        });
        vm.Refresh();

        vm.ClearCommand.Execute(null);
        await vm.ClearCommand.ExecutionTask;

        Assert.Empty(store.GetAll());
        Assert.Empty(vm.FilteredEntries);
        Assert.True(vm.IsEmpty);
    }

    [AvaloniaFact]
    public async Task ClearCommand_LogsAnalystAction()
    {
        var store = new InMemoryThreatIntelStore();
        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "192.168.1.1", Source = "STIX" }
        });
        var actionStore = new InMemoryAnalystActionStore();
        var vm = new ThreatIntelViewModel(store, new TestDialogService(), new AnalystActionLogger(actionStore));
        vm.Refresh();

        vm.ClearCommand.Execute(null);
        await vm.ClearCommand.ExecutionTask;

        var entry = Assert.Single(actionStore.GetAll());
        Assert.Equal(AnalystActionType.ThreatIntelCleared, entry.ActionType);
        Assert.Contains("count=1", entry.Details);
    }

    [AvaloniaFact]
    public async Task ImportCommand_LoadsStixBundleIntoStore()
    {
        var json = @"{
            ""type"": ""bundle"",
            ""objects"": [
                { ""type"": ""ipv4-addr"", ""value"": ""10.0.0.99"" }
            ]
        }";

        var tempFile = Path.GetTempFileName() + ".json";
        await File.WriteAllTextAsync(tempFile, json);

        try
        {
            var store = new InMemoryThreatIntelStore();
            var dialogService = new TestDialogService
            {
                OpenFileResult = tempFile,
                SelectionResult = 1 // STIX 2.1
            };
            var vm = new ThreatIntelViewModel(store, dialogService);

            vm.ImportCommand.Execute(null);
            await ((AsyncRelayCommand)vm.ImportCommand).ExecutionTask;

            Assert.Single(store.GetAll());
            Assert.Equal("10.0.0.99", store.GetAll()[0].Value);
            Assert.Contains("Imported 1 IOC", vm.StatusMessage);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [AvaloniaFact]
    public async Task ImportCommand_LogsAnalystAction()
    {
        var json = @"{
            ""type"": ""bundle"",
            ""objects"": [
                { ""type"": ""ipv4-addr"", ""value"": ""10.0.0.99"" }
            ]
        }";

        var tempFile = Path.GetTempFileName() + ".json";
        await File.WriteAllTextAsync(tempFile, json);

        try
        {
            var store = new InMemoryThreatIntelStore();
            var actionStore = new InMemoryAnalystActionStore();
            var dialogService = new TestDialogService
            {
                OpenFileResult = tempFile,
                SelectionResult = 1
            };
            var vm = new ThreatIntelViewModel(store, dialogService, new AnalystActionLogger(actionStore));

            vm.ImportCommand.Execute(null);
            await vm.ImportCommand.ExecutionTask;

            var entry = Assert.Single(actionStore.GetAll());
            Assert.Equal(AnalystActionType.ThreatIntelImported, entry.ActionType);
            Assert.Equal("stix", entry.Target);
            Assert.Contains("count=1", entry.Details);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [AvaloniaFact]
    public async Task ImportCommand_AutoDetect_LoadsMispBundle()
    {
        var json = @"{
            ""Event"": {
                ""Attribute"": [
                    { ""type"": ""domain"", ""value"": ""misp.example.com"", ""comment"": ""test"" }
                ]
            }
        }";

        var tempFile = Path.GetTempFileName() + ".json";
        await File.WriteAllTextAsync(tempFile, json);

        try
        {
            var store = new InMemoryThreatIntelStore();
            var dialogService = new TestDialogService
            {
                OpenFileResult = tempFile,
                SelectionResult = 0 // Auto-detect
            };
            var vm = new ThreatIntelViewModel(store, dialogService);

            vm.ImportCommand.Execute(null);
            await ((AsyncRelayCommand)vm.ImportCommand).ExecutionTask;

            Assert.Single(store.GetAll());
            Assert.Equal("misp.example.com", store.GetAll()[0].Value);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [AvaloniaFact]
    public async Task ImportCommand_SurfaceParserWarningsInStatus()
    {
        var json = @"{
            ""Event"": {
                ""Attribute"": [
                    { ""type"": ""unsupported-type"", ""value"": ""not-actionable"", ""comment"": ""test"" }
                ]
            }
        }";

        var tempFile = Path.GetTempFileName() + ".json";
        await File.WriteAllTextAsync(tempFile, json);

        try
        {
            var store = new InMemoryThreatIntelStore();
            var dialogService = new TestDialogService
            {
                OpenFileResult = tempFile,
                SelectionResult = 2 // MISP JSON
            };
            var vm = new ThreatIntelViewModel(store, dialogService);

            vm.ImportCommand.Execute(null);
            await vm.ImportCommand.ExecutionTask;

            Assert.Empty(store.GetAll());
            Assert.Contains("Skipped: 1", vm.StatusMessage);
            Assert.Contains("Skipped unsupported MISP attribute type: unsupported-type", vm.StatusMessage);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [AvaloniaFact]
    public async Task ImportCommand_CancelledFileDialog_DoesNothing()
    {
        var store = new InMemoryThreatIntelStore();
        var dialogService = new TestDialogService { OpenFileResult = null };
        var vm = new ThreatIntelViewModel(store, dialogService);

        vm.ImportCommand.Execute(null);
        await ((AsyncRelayCommand)vm.ImportCommand).ExecutionTask;

        Assert.Empty(store.GetAll());
    }

    [AvaloniaFact]
    public void StatusMessage_SingularPluralization_WhenOneIocLoaded()
    {
        // Exactly one IOC: the status must say "1 IOC loaded" (singular),
        // not the old always-plural "1 IOC(s) loaded." parenthetical.
        var store = new InMemoryThreatIntelStore();
        var vm = new ThreatIntelViewModel(store, new TestDialogService());

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "10.0.0.99", Source = "STIX" }
        });
        vm.Refresh();

        Assert.Equal(1, vm.TotalCount);
        Assert.Contains("1 IOC loaded", vm.StatusMessage);
        Assert.DoesNotContain("IOC(s)", vm.StatusMessage);
    }

    [AvaloniaFact]
    public void StatusMessage_PluralPluralization_WhenMultipleIocsLoaded()
    {
        // Multiple IOCs: the status must use the plural "IOCs loaded".
        var store = new InMemoryThreatIntelStore();
        var vm = new ThreatIntelViewModel(store, new TestDialogService());

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "10.0.0.99", Source = "STIX" },
            new IocEntry { Type = IocType.Domain, Value = "evil.example.com", Source = "STIX" }
        });
        vm.Refresh();

        Assert.Equal(2, vm.TotalCount);
        Assert.Contains("2 IOCs loaded", vm.StatusMessage);
    }

    private sealed class TestDialogService : IDialogService
    {
        public string? OpenFileResult { get; set; }
        public int? SelectionResult { get; set; }
        public string? InputResult { get; set; }

        public void ShowMessage(string message, string title) { }
        public void ShowError(string message, string title) { }
        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName)
            => Task.FromResult<string?>(null);
        public Task<string?> ShowOpenFileDialogAsync(string title, string filter)
            => Task.FromResult(OpenFileResult);
        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "")
            => Task.FromResult(InputResult);
        public Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel)
            => Task.FromResult<bool?>(null);
        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0)
            => Task.FromResult(SelectionResult);
    }
}
