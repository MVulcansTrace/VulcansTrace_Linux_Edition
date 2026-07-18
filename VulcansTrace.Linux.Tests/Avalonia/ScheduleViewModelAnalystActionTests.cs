using System.Collections.Generic;
using System.ComponentModel;
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

    [Fact]
    public void HasSelection_False_Initially_And_Notifies_OnSelection()
    {
        var store = new InMemoryScheduleStore();
        var schedule = CreateSchedule(enabled: true);
        store.Save(schedule);
        var vm = CreateViewModel(store, new InMemoryAnalystActionStore());

        // No row selected: the toolbar hint should be visible.
        Assert.False(vm.HasSelection);

        var fired = new List<string?>();
        ((INotifyPropertyChanged)vm).PropertyChanged += (_, e) => fired.Add(e.PropertyName);

        vm.SelectedRow = vm.Rows.Single(r => r.Schedule.Id == schedule.Id);

        // Selection landed and the computed flag re-notified so the hint swaps.
        Assert.True(vm.HasSelection);
        Assert.Contains(nameof(ScheduleViewModel.HasSelection), fired);

        vm.SelectedRow = null;

        Assert.False(vm.HasSelection);
        // The notification fires on every transition (set-null is a real change here).
        Assert.Equal(
            2,
            fired.Count(p => p == nameof(ScheduleViewModel.HasSelection)));
    }

    [Fact]
    public void StatusOrHint_Suppressed_WhenNoRows_Exist()
    {
        // Empty store: never tell the user to "select a schedule" when none exist.
        var vm = CreateViewModel(new InMemoryScheduleStore(), new InMemoryAnalystActionStore());
        Assert.Equal("", vm.StatusOrHint);
    }

    [Fact]
    public void StatusOrHint_ShowsHint_WhenRowsExist_ButNoneSelected()
    {
        var store = new InMemoryScheduleStore();
        store.Save(CreateSchedule(enabled: true));
        var vm = CreateViewModel(store, new InMemoryAnalystActionStore());

        Assert.True(vm.HasRows);
        Assert.False(vm.HasSelection);
        Assert.Contains("Select a schedule", vm.StatusOrHint);
    }

    [Fact]
    public void StatusOrHint_Empty_WhenRowSelected_AndNoStatusMessage()
    {
        var store = new InMemoryScheduleStore();
        var schedule = CreateSchedule(enabled: true);
        store.Save(schedule);
        var vm = CreateViewModel(store, new InMemoryAnalystActionStore());
        vm.SelectedRow = vm.Rows.Single(r => r.Schedule.Id == schedule.Id);

        // Selection clears the hint; no status posted yet.
        Assert.Equal("", vm.StatusOrHint);
    }

    [Fact]
    public async Task StatusOrHint_StatusMessage_WinsOverHint_AfterDelete()
    {
        // The bug-1 regression: Delete leaves no selection AND posts a status, while
        // other rows still exist (so the hint WOULD show if status didn't win). The
        // status must appear alone, not concatenated with the hint.
        var store = new InMemoryScheduleStore();
        var toDelete = CreateSchedule(enabled: true, name: "Daily audit");
        var survivor = CreateSchedule(enabled: true, name: "Weekly audit");
        store.Save(toDelete);
        store.Save(survivor);
        var vm = CreateViewModel(store, new InMemoryAnalystActionStore());
        vm.SelectedRow = vm.Rows.Single(r => r.Schedule.Id == toDelete.Id);

        vm.DeleteCommand.Execute(null);
        await vm.DeleteCommand.ExecutionTask;

        Assert.Single(store.GetAll());         // survivor remains
        Assert.True(vm.HasRows);               // so the hint is otherwise eligible
        Assert.Null(vm.SelectedRow);           // selection cleared
        Assert.False(vm.HasSelection);
        // StatusMessage wins over the hint, with no concatenation.
        Assert.Contains("deleted", vm.StatusOrHint);
        Assert.DoesNotContain("Select a schedule", vm.StatusOrHint);
    }

    private static ScheduleViewModel CreateViewModel(InMemoryScheduleStore store, InMemoryAnalystActionStore actionStore)
        => new(
            store,
            new InMemoryAuditHistoryStore(),
            new InMemoryNotificationSettingsStore(),
            new NoopNotificationService(),
            new TestDialogService(),
            new AnalystActionLogger(actionStore));

    private static AuditSchedule CreateSchedule(bool enabled, string name = "Daily audit")
        => new()
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = name,
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
