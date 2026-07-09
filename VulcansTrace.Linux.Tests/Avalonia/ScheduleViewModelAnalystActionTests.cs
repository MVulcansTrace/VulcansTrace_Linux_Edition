using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class ScheduleViewModelAnalystActionTests
{
    [Fact]
    public async Task DeleteCommand_LogsAnalystAction()
    {
        var store = new InMemoryScheduleStore();
        var schedule = CreateSchedule(enabled: true);
        store.Save(schedule);
        var actionStore = new InMemoryAnalystActionStore();
        var vm = CreateViewModel(store, actionStore);
        vm.SelectedRow = vm.Rows.Single(r => r.Schedule.Id == schedule.Id);

        vm.DeleteCommand.Execute(null);
        await vm.DeleteCommand.ExecutionTask;

        Assert.Empty(store.GetAll());
        var entry = Assert.Single(actionStore.GetAll());
        Assert.Equal(AnalystActionType.ScheduleDeleted, entry.ActionType);
        Assert.Equal(schedule.Id, entry.Target);
        Assert.Contains(schedule.Name, vm.StatusMessage);
    }

    [Fact]
    public async Task EnableCommand_LogsAnalystAction()
    {
        var store = new InMemoryScheduleStore();
        var schedule = CreateSchedule(enabled: false);
        store.Save(schedule);
        var actionStore = new InMemoryAnalystActionStore();
        var vm = CreateViewModel(store, actionStore);
        vm.SelectedRow = vm.Rows.Single(r => r.Schedule.Id == schedule.Id);

        vm.EnableCommand.Execute(null);
        await vm.EnableCommand.ExecutionTask;

        Assert.True(store.GetById(schedule.Id)!.Enabled);
        var entry = Assert.Single(actionStore.GetAll());
        Assert.Equal(AnalystActionType.ScheduleEnabled, entry.ActionType);
        Assert.Equal(schedule.Id, entry.Target);
    }

    private static ScheduleViewModel CreateViewModel(InMemoryScheduleStore store, InMemoryAnalystActionStore actionStore)
        => new(
            store,
            new InMemoryAuditHistoryStore(),
            new InMemoryNotificationSettingsStore(),
            new NoopNotificationService(),
            new TestDialogService(),
            new AnalystActionLogger(actionStore));

    private static AuditSchedule CreateSchedule(bool enabled)
        => new()
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = "Daily audit",
            Intent = AgentIntent.FullAudit,
            CronExpression = "0 6 * * *",
            MachineRole = MachineRole.Workstation,
            Enabled = enabled
        };

    private sealed class NoopNotificationService : INotificationService
    {
        public Task NotifyAsync(string title, string message, CancellationToken ct = default) => Task.CompletedTask;

        public Task NotifyCriticalFindingsAsync(string scheduleName, int criticalCount, CancellationToken ct = default) => Task.CompletedTask;

        public Task NotifySignedAlertAsync(SignedAlertMessage alert, CancellationToken ct = default) => Task.CompletedTask;

        public Task<bool> SendTestAsync(CancellationToken ct = default) => Task.FromResult(true);
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
}
