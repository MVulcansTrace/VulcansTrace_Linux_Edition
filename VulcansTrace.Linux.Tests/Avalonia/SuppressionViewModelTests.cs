using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class SuppressionViewModelTests
{
    [Fact]
    public void ReviewQueue_CategorizesCorrectly()
    {
        var now = DateTime.UtcNow;
        var store = new InMemorySuppressionStore();
        var vm = new SuppressionViewModel(store, new TestDialogService());

        // Expiring soon (expires in 3 days)
        store.Add(new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "A",
            ExpiresAt = now.AddDays(3),
            CreatedAt = now.AddDays(-27)
        });

        // Expired recently (expired 2 days ago)
        store.Add(new SuppressionEntry
        {
            RuleId = "FW-002",
            Target = "B",
            ExpiresAt = now.AddDays(-2),
            CreatedAt = now.AddDays(-32)
        });

        // Permanent (created 10 days ago)
        store.Add(new SuppressionEntry
        {
            RuleId = "FW-003",
            Target = "C",
            CreatedAt = now.AddDays(-10)
        });

        // Stale permanent (created 100 days ago)
        store.Add(new SuppressionEntry
        {
            RuleId = "FW-004",
            Target = "D",
            CreatedAt = now.AddDays(-100)
        });

        // Active but not expiring soon (expires in 30 days)
        store.Add(new SuppressionEntry
        {
            RuleId = "FW-005",
            Target = "E",
            ExpiresAt = now.AddDays(30),
            CreatedAt = now
        });

        vm.Refresh();

        Assert.Equal(4, vm.ReviewQueueItems.Count);
        Assert.Contains(vm.ReviewQueueItems, i => i.Entry.RuleId == "FW-001" && i.Category == ReviewFilter.ExpiringSoon);
        Assert.Contains(vm.ReviewQueueItems, i => i.Entry.RuleId == "FW-002" && i.Category == ReviewFilter.ExpiredRecently);
        Assert.Contains(vm.ReviewQueueItems, i => i.Entry.RuleId == "FW-003" && i.Category == ReviewFilter.Permanent);
        Assert.Contains(vm.ReviewQueueItems, i => i.Entry.RuleId == "FW-004" && i.Category == ReviewFilter.StalePermanent);
        Assert.DoesNotContain(vm.ReviewQueueItems, i => i.Entry.RuleId == "FW-005");
    }

    [Fact]
    public void ReviewFilter_ExpiringSoon_ReturnsOnlyExpiringSoon()
    {
        var now = DateTime.UtcNow;
        var store = new InMemorySuppressionStore();
        var vm = new SuppressionViewModel(store, new TestDialogService());

        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "A", ExpiresAt = now.AddDays(3) });
        store.Add(new SuppressionEntry { RuleId = "FW-002", Target = "B", ExpiresAt = now.AddDays(-2) });
        store.Add(new SuppressionEntry { RuleId = "FW-003", Target = "C", CreatedAt = now.AddDays(-10) });

        vm.SelectedReviewFilter = ReviewFilter.ExpiringSoon;

        Assert.Single(vm.ReviewQueueItems);
        Assert.Equal("FW-001", vm.ReviewQueueItems[0].Entry.RuleId);
    }

    [Fact]
    public void ReviewFilter_ExpiredRecently_ReturnsOnlyExpiredRecently()
    {
        var now = DateTime.UtcNow;
        var store = new InMemorySuppressionStore();
        var vm = new SuppressionViewModel(store, new TestDialogService());

        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "A", ExpiresAt = now.AddDays(3) });
        store.Add(new SuppressionEntry { RuleId = "FW-002", Target = "B", ExpiresAt = now.AddDays(-2) });
        store.Add(new SuppressionEntry { RuleId = "FW-003", Target = "C", CreatedAt = now.AddDays(-10) });

        vm.SelectedReviewFilter = ReviewFilter.ExpiredRecently;

        Assert.Single(vm.ReviewQueueItems);
        Assert.Equal("FW-002", vm.ReviewQueueItems[0].Entry.RuleId);
    }

    [Fact]
    public void ReviewFilter_ExpiredRecently_IncludesFullRetentionWindow()
    {
        var now = DateTime.UtcNow;
        var store = new InMemorySuppressionStore();
        var vm = new SuppressionViewModel(store, new TestDialogService());

        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "A", ExpiresAt = now.AddDays(-14) });
        store.Add(new SuppressionEntry { RuleId = "FW-002", Target = "B", ExpiresAt = now.AddDays(-31) });

        vm.SelectedReviewFilter = ReviewFilter.ExpiredRecently;

        Assert.Single(vm.ReviewQueueItems);
        Assert.Equal("FW-001", vm.ReviewQueueItems[0].Entry.RuleId);
    }

    [Fact]
    public void ReviewFilter_Permanent_ReturnsOnlyPermanent()
    {
        var now = DateTime.UtcNow;
        var store = new InMemorySuppressionStore();
        var vm = new SuppressionViewModel(store, new TestDialogService());

        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "A", ExpiresAt = now.AddDays(3) });
        store.Add(new SuppressionEntry { RuleId = "FW-002", Target = "B", CreatedAt = now.AddDays(-10) });
        store.Add(new SuppressionEntry { RuleId = "FW-003", Target = "C", CreatedAt = now.AddDays(-100) });

        vm.SelectedReviewFilter = ReviewFilter.Permanent;

        Assert.Single(vm.ReviewQueueItems);
        Assert.Equal("FW-002", vm.ReviewQueueItems[0].Entry.RuleId);
    }

    [Fact]
    public void ReviewFilter_StalePermanent_ReturnsOnlyStalePermanent()
    {
        var now = DateTime.UtcNow;
        var store = new InMemorySuppressionStore();
        var vm = new SuppressionViewModel(store, new TestDialogService());

        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "A", ExpiresAt = now.AddDays(3) });
        store.Add(new SuppressionEntry { RuleId = "FW-002", Target = "B", CreatedAt = now.AddDays(-10) });
        store.Add(new SuppressionEntry { RuleId = "FW-003", Target = "C", CreatedAt = now.AddDays(-100) });

        vm.SelectedReviewFilter = ReviewFilter.StalePermanent;

        Assert.Single(vm.ReviewQueueItems);
        Assert.Equal("FW-003", vm.ReviewQueueItems[0].Entry.RuleId);
    }

    [Fact]
    public async Task RenewCommand_UpdatesExpiryAndReviewDate()
    {
        var now = DateTime.UtcNow;
        var store = new InMemorySuppressionStore();
        var dialogService = new TestDialogService { SelectionResult = 1 }; // 30 days
        var vm = new SuppressionViewModel(store, dialogService);

        store.Add(new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "A",
            ExpiresAt = now.AddDays(3),
            CreatedAt = now.AddDays(-27)
        });

        vm.Refresh();
        var item = vm.ReviewQueueItems[0];

        vm.RenewSuppressionCommand.Execute(item);

        // Wait for async command
        var asyncCmd = vm.RenewSuppressionCommand as AsyncRelayCommand;
        Assert.NotNull(asyncCmd);
        await asyncCmd!.ExecutionTask;

        Assert.DoesNotContain(store.GetAllRaw(), e => e.RuleId == "FW-001" && e.ExpiresAt <= now.AddDays(7));
        var renewed = store.GetAllRaw().First(e => e.RuleId == "FW-001");
        Assert.True(renewed.ExpiresAt > now.AddDays(20));
        Assert.True(renewed.ReviewDate > now.AddDays(20));
    }

    [Fact]
    public async Task ConvertCommand_ChangesDuration()
    {
        var now = DateTime.UtcNow;
        var store = new InMemorySuppressionStore();
        var dialogService = new TestDialogService { SelectionResult = 0 }; // 7 days
        var vm = new SuppressionViewModel(store, dialogService);

        store.Add(new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "A",
            ExpiresAt = now.AddDays(3),
            CreatedAt = now.AddDays(-27)
        });

        vm.Refresh();
        var item = vm.ReviewQueueItems[0];

        vm.ConvertDurationCommand.Execute(item);

        var asyncCmd = vm.ConvertDurationCommand as AsyncRelayCommand;
        Assert.NotNull(asyncCmd);
        await asyncCmd!.ExecutionTask;

        var converted = store.GetAllRaw().First(e => e.RuleId == "FW-001");
        Assert.True(converted.ExpiresAt <= now.AddDays(8));
    }

    [Fact]
    public async Task EditReasonCommand_UpdatesReason()
    {
        var store = new InMemorySuppressionStore();
        var dialogService = new TestDialogService { InputResult = "Updated reason" };
        var vm = new SuppressionViewModel(store, dialogService);

        store.Add(new SuppressionEntry
        {
            RuleId = "FW-001",
            Target = "A",
            Reason = "Old reason"
        });

        vm.Refresh();
        var item = vm.ReviewQueueItems[0];

        vm.EditReasonCommand.Execute(item);

        var asyncCmd = vm.EditReasonCommand as AsyncRelayCommand;
        Assert.NotNull(asyncCmd);
        await asyncCmd!.ExecutionTask;

        Assert.Equal("Updated reason", store.GetAllRaw()[0].Reason);
    }

    [Fact]
    public void RemoveCommand_RemovesFromStoreAndQueue()
    {
        var store = new InMemorySuppressionStore();
        var vm = new SuppressionViewModel(store, new TestDialogService());

        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "A", CreatedAt = DateTime.UtcNow.AddDays(-100) });

        vm.Refresh();
        Assert.Single(vm.ReviewQueueItems);

        vm.RemoveSuppressionCommand.Execute(vm.ReviewQueueItems[0]);

        Assert.Empty(store.GetAllRaw());
        Assert.Empty(vm.ReviewQueueItems);
    }

    [Fact]
    public void RemoveCommand_HandlesSuppressionEntryParameter()
    {
        var store = new InMemorySuppressionStore();
        var vm = new SuppressionViewModel(store, new TestDialogService());

        store.Add(new SuppressionEntry { RuleId = "FW-001", Target = "A" });

        vm.Refresh();
        var entry = vm.Entries[0];

        vm.RemoveSuppressionCommand.Execute(entry);

        Assert.Empty(store.GetAllRaw());
    }

    private sealed class TestDialogService : IDialogService
    {
        public int? SelectionResult { get; set; }
        public string? InputResult { get; set; }

        public void ShowMessage(string message, string title) { }
        public void ShowError(string message, string title) { }
        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName)
            => Task.FromResult<string?>(null);
        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "")
            => Task.FromResult(InputResult);
        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0)
            => Task.FromResult(SelectionResult);
    }
}
