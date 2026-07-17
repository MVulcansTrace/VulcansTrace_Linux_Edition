using System;
using System.Linq;
using System.Reflection;
using Avalonia.Media;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Memory;
using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Agent.Suggestions;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Avalonia.Converters;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.ThreatIntel;

using static VulcansTrace.Linux.Tests.Avalonia.TestDispatcher;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public class AgentViewModelTests
{
    private static RemediationPlanBuilder PlanBuilder => new(new ExplanationProvider());

    [AvaloniaFact]
    public void NotifySelectedFindingChanged_RefreshesExplainSelectedState()
    {
        var selected = CreateFinding();
        var hasSelection = false;
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            SelectedFindingProvider = () => hasSelection ? selected : null
        };

        Assert.False(vm.CanExplainSelected);
        Assert.False(vm.ExplainSelectedCommand.CanExecute(null));

        hasSelection = true;
        vm.NotifySelectedFindingChanged();

        Assert.True(vm.CanExplainSelected);
        Assert.True(vm.ExplainSelectedCommand.CanExecute(null));

        hasSelection = false;
        vm.NotifySelectedFindingChanged();

        Assert.False(vm.CanExplainSelected);
        Assert.False(vm.ExplainSelectedCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void NotifySelectedFindingChanged_RefreshesVerifySelectedState()
    {
        var withRuleId = CreateFinding();
        var withoutRuleId = CreateFinding() with { RuleId = "" };
        var current = withRuleId;
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            SelectedFindingProvider = () => current
        };

        Assert.True(vm.CanVerifySelected);
        Assert.True(vm.VerifySelectedCommand.CanExecute(null));

        current = withoutRuleId;
        vm.NotifySelectedFindingChanged();

        Assert.False(vm.CanVerifySelected);
        Assert.False(vm.VerifySelectedCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void SelectedChatCategoryFilter_AllCategories_KeepsFindingMessagesVisible()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        var firewallMessage = new AgentMessageViewModel
        {
            Text = "Firewall finding",
            Category = "Firewall",
            Severity = Severity.High
        };
        var networkMessage = new AgentMessageViewModel
        {
            Text = "Network finding",
            Category = "Network",
            Severity = Severity.Medium
        };
        vm.Messages.Add(firewallMessage);
        vm.Messages.Add(networkMessage);
        vm.ChatCategoryFilters.Add(ChatFilterConstants.AllCategoriesFilter);
        vm.ChatCategoryFilters.Add("Firewall");
        vm.ChatCategoryFilters.Add("Network");

        vm.SelectedChatCategoryFilter = "Firewall";

        Assert.True(firewallMessage.IsVisible);
        Assert.False(networkMessage.IsVisible);

        vm.SelectedChatCategoryFilter = ChatFilterConstants.AllCategoriesFilter;

        Assert.True(firewallMessage.IsVisible);
        Assert.True(networkMessage.IsVisible);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_AddsCapabilityReportOnce()
    {
        const string capabilityReport = "Data sources: ss available.";
        var vm = new AgentViewModel(new CapabilityReportAgent(capabilityReport), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "is my system secure?"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(1, vm.Messages.Count(message => message.Text == capabilityReport));
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_ProgressReports_ResetAfterCompletion()
    {
        var agent = new ProgressReportingAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "run audit"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        // The agent reported progress; Progress<T>.Report is queued on the dispatcher and drains in
        // the Flush above. With the IsBusy=false reset and the OnAuditProgress !IsBusy guard, that
        // late report must NOT leave stale label/percent behind to flash at the start of the next op.
        Assert.False(vm.IsBusy);
        Assert.Equal(0, vm.AuditProgressPercent);
        Assert.Empty(vm.AuditProgressMessage);
        Assert.False(vm.ShowAuditProgress);
    }

    [AvaloniaFact]
    public async Task FullAuditCommand_AddsCapabilityReportOnce()
    {
        const string capabilityReport = "Data sources: ss available.";
        var vm = new AgentViewModel(new CapabilityReportAgent(capabilityReport), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(1, vm.Messages.Count(message => message.Text == capabilityReport));
    }

    [AvaloniaFact]
    public async Task FullAuditCommand_EnablesExportThreatIntelCommand()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.False(vm.CanExportThreatIntel);
        Assert.False(vm.ExportThreatIntelCommand.CanExecute(null));

        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.CanExportThreatIntel);
        Assert.True(vm.ExportThreatIntelCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task ExportThreatIntelCommand_InvokesParentCallback()
    {
        var invoked = false;
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            RequestExportThreatIntel = async () =>
            {
                invoked = true;
                return await Task.FromResult(true);
            }
        };

        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask;
        FlushDispatcher();

        vm.ExportThreatIntelCommand.Execute(null);
        await vm.ExportThreatIntelCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(invoked);
    }

    [AvaloniaFact]
    public async Task ImportThreatIntelCommand_ShowsStorePersistenceWarning()
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
            var store = new WarningThreatIntelStore("Threat intel persistence is unavailable. IOCs will last only for this session.");
            var vm = new AgentViewModel(
                new StubAgent(),
                new InMemoryAuditHistoryStore(),
                PlanBuilder,
                new RemediationExecutor(new ProcessRunner()),
                threatIntelStore: store,
                dialogService: new FakeDialogService(confirmIndex: 1, openFileResult: tempFile));

            vm.ImportThreatIntelCommand.Execute(null);
            await vm.ImportThreatIntelCommand.ExecutionTask;

            Assert.Contains(vm.Messages, message =>
                message.Text.Contains("Imported 1 IOC", StringComparison.Ordinal) &&
                !message.IsError);
            Assert.Contains(vm.Messages, message =>
                message.Text.Contains("IOCs will last only for this session", StringComparison.Ordinal) &&
                message.IsInfo);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_TypedSshAudit_AppendsHistoryAndEnablesExport()
    {
        var agent = new TrackingAgent(AgentIntent.SshCheck);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check ssh"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.CanExportAudit);
        Assert.Single(vm.History);
        Assert.Equal(AgentIntent.SshCheck, vm.History[0].Intent);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_TypedYaraAudit_AppendsHistoryAndEnablesExport()
    {
        var agent = new TrackingAgent(AgentIntent.YaraCheck);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "run a yara scan"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.CanExportAudit);
        Assert.Single(vm.History);
        Assert.Equal(AgentIntent.YaraCheck, vm.History[0].Intent);
    }

    [AvaloniaFact]
    public async Task PublishAuditCompleted_FromWorker_MutatesHistoryAndRaisesEventOnUiThread()
    {
        var vm = new AgentViewModel(
            new StubAgent(),
            new InMemoryAuditHistoryStore(),
            PlanBuilder,
            new RemediationExecutor(new ProcessRunner()));
        var uiThreadId = Environment.CurrentManagedThreadId;
        int? historyThreadId = null;
        int? completedThreadId = null;
        vm.History.CollectionChanged += (_, _) =>
            historyThreadId ??= Environment.CurrentManagedThreadId;
        vm.AuditCompleted += (_, _) =>
            completedThreadId ??= Environment.CurrentManagedThreadId;

        var result = new AgentResult
        {
            Intent = AgentIntent.SshCheck,
            UtcTimestamp = DateTime.UtcNow
        };
        var publish = typeof(AgentViewModel).GetMethod(
            "PublishAuditCompleted",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(publish);

        await Task.Run(() => publish.Invoke(vm, new object[] { result }));
        FlushDispatcher();

        Assert.Single(vm.History);
        Assert.Equal(uiThreadId, historyThreadId);
        Assert.Equal(uiThreadId, completedThreadId);
    }

    [AvaloniaFact]
    public void SlashPalette_PrefixQuery_ShowsMatchingCommands()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "/firewall";

        Assert.True(vm.IsSlashPaletteOpen);
        Assert.Contains(vm.FilteredSlashCommands, c => c.CommandText == "/firewall");
    }

    [AvaloniaFact]
    public void SlashPalette_NonMatchingPrefix_StaysClosed()
    {
        // The palette filters by command-text prefix, so a genuinely non-matching prefix stays closed
        // and Enter falls through to a normal query instead of silently doing nothing.
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "/zzz";

        Assert.False(vm.IsSlashPaletteOpen);
        Assert.Empty(vm.FilteredSlashCommands);
    }

    [AvaloniaFact]
    public void SlashPalette_BaselinePrefix_ShowsBothBaselineCommands()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "/baseline";

        Assert.True(vm.IsSlashPaletteOpen);
        Assert.Contains(vm.FilteredSlashCommands, c => c.CommandText == "/baseline");
        Assert.Contains(vm.FilteredSlashCommands, c => c.CommandText == "/baseline show");
    }

    [AvaloniaFact]
    public void SlashPalette_ShowPrefix_ShowsShowBaselineAlias()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "/show";

        Assert.True(vm.IsSlashPaletteOpen);
        Assert.Contains(vm.FilteredSlashCommands, c => c.CommandText == "/show baseline");
    }

    [AvaloniaFact]
    public void SlashPalette_RootQuery_ContainsDocumentedCommands()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "/";

        var commands = vm.FilteredSlashCommands.Select(c => c.CommandText).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var expected in new[]
        {
            "/firewall", "/network", "/ports", "/services", "/ssh", "/filesystem", "/kernel",
            "/users", "/logging", "/cron", "/packages", "/containers", "/kubernetes",
            "/threatintel", "/yara", "/processes", "/full", "/fullaudit", "/baseline",
            "/drift", "/show baseline", "/baseline show", "/logdiffdemo", "/sessions", "/risk", "/help", "/clear"
        })
        {
            Assert.Contains(expected, commands);
        }
    }

    [AvaloniaFact]
    public void QuickActions_ExposeCommonAuditsAndFollowUps()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        var runCheckLabels = vm.QuickActionsChecks.Select(action => action.Label).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var baselineLabels = vm.QuickActionsBaseline.Select(action => action.Label).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var exportLabels = vm.QuickActionsExport.Select(action => action.Label).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("Processes", runCheckLabels);
        Assert.Contains("Set baseline", baselineLabels);
        Assert.Contains("Check drift", baselineLabels);
        Assert.Contains("Show baseline", baselineLabels);
        Assert.Contains("Export audit", exportLabels);
    }

    [AvaloniaFact]
    public void SlashPalette_LogDiffDemoPrefix_ShowsCommand()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "/logdiffdemo";

        Assert.True(vm.IsSlashPaletteOpen);
        Assert.Contains(vm.FilteredSlashCommands, c => c.CommandText == "/logdiffdemo");
    }

    [AvaloniaFact]
    public void SlashPalette_Close_DismissesWithoutClearingQuery()
    {
        // Esc / blur dismiss the palette via CloseSlashPalette but preserve the typed query, so a
        // click-away doesn't discard what the user entered.
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "/baseline";
        Assert.True(vm.IsSlashPaletteOpen);

        vm.CloseSlashPalette();

        Assert.False(vm.IsSlashPaletteOpen);
        Assert.Empty(vm.FilteredSlashCommands);
        Assert.Equal("/baseline", vm.UserQuery);
    }

    [AvaloniaFact]
    public void SlashPalette_Close_ThenEditingReopens()
    {
        // After dismissing, editing the query re-derives the palette (UpdateSlashPalette runs again).
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "/baseline";
        vm.CloseSlashPalette();
        Assert.False(vm.IsSlashPaletteOpen);

        vm.UserQuery = "/firewall";

        Assert.True(vm.IsSlashPaletteOpen);
        Assert.Contains(vm.FilteredSlashCommands, c => c.CommandText == "/firewall");
    }

    [AvaloniaFact]
    public void SlashPalette_PrefixQuery_SelectsFirstCommand()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/fire"
        };

        Assert.True(vm.IsSlashPaletteOpen);
        Assert.NotNull(vm.SelectedSlashCommand);
        Assert.Equal("/firewall", vm.SelectedSlashCommand!.CommandText);
    }

    [AvaloniaFact]
    public void SlashPalette_Down_SelectsNextCommand()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/baseline"
        };

        Assert.Equal("/baseline", vm.SelectedSlashCommand!.CommandText);

        vm.SelectNextSlashCommand();

        Assert.Equal("/baseline show", vm.SelectedSlashCommand!.CommandText);
    }

    [AvaloniaFact]
    public void SlashPalette_Down_AtEnd_WrapsToTop()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/baseline"
        };

        vm.SelectNextSlashCommand();
        vm.SelectNextSlashCommand();

        Assert.Equal("/baseline", vm.SelectedSlashCommand!.CommandText);
    }

    [AvaloniaFact]
    public void SlashPalette_Up_WrapsToEnd()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/baseline"
        };

        Assert.Equal("/baseline", vm.SelectedSlashCommand!.CommandText);

        vm.SelectPreviousSlashCommand();

        Assert.Equal("/baseline show", vm.SelectedSlashCommand!.CommandText);
    }

    [AvaloniaFact]
    public void SlashPalette_Close_ClearsSelection()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/firewall"
        };

        Assert.NotNull(vm.SelectedSlashCommand);

        vm.CloseSlashPalette();

        Assert.Null(vm.SelectedSlashCommand);
    }

    [AvaloniaFact]
    public void SlashPalette_Enter_ExecutesSelectedCommand()
    {
        // Programmatic Enter dispatch when the palette is open executes the highlighted command,
        // mirroring the view's KeyDown handler.
        var agent = new TrackingAgent(AgentIntent.FullAudit);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/firewall"
        };

        vm.ExecuteSlashCommandCommand.Execute(vm.SelectedSlashCommand);

        Assert.Equal(AgentIntent.FirewallCheck, agent.LastRunAuditIntent);
        Assert.False(vm.IsSlashPaletteOpen);
    }

    [AvaloniaFact]
    public void SlashHelp_OpenSlashHelpCommand_ShowsAllCommands()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.False(vm.IsSlashHelpOpen);
        Assert.True(vm.OpenSlashHelpCommand.CanExecute(null));
        Assert.False(vm.CloseSlashHelpCommand.CanExecute(null));

        var openChanged = false;
        var closeChanged = false;
        vm.OpenSlashHelpCommand.CanExecuteChanged += (_, _) => openChanged = true;
        vm.CloseSlashHelpCommand.CanExecuteChanged += (_, _) => closeChanged = true;

        vm.OpenSlashHelpCommand.Execute(null);

        Assert.True(vm.IsSlashHelpOpen);
        Assert.False(vm.OpenSlashHelpCommand.CanExecute(null));
        Assert.True(vm.CloseSlashHelpCommand.CanExecute(null));
        Assert.True(openChanged, "OpenSlashHelpCommand should raise CanExecuteChanged when popup opens.");
        Assert.True(closeChanged, "CloseSlashHelpCommand should raise CanExecuteChanged when popup opens.");
        Assert.NotEmpty(vm.FilteredSlashHelpCommands);
        Assert.Contains(vm.FilteredSlashHelpCommands, c => c.CommandText == "/firewall");
        Assert.Contains(vm.FilteredSlashHelpCommands, c => c.CommandText == "/help");
        Assert.NotNull(vm.SelectedSlashHelpCommand);
    }

    [AvaloniaFact]
    public void SlashHelp_OpenSlashHelpCommand_ClosesInlinePalette()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/fire"
        };
        Assert.True(vm.IsSlashPaletteOpen);

        vm.OpenSlashHelpCommand.Execute(null);

        Assert.True(vm.IsSlashHelpOpen);
        Assert.False(vm.IsSlashPaletteOpen);
        Assert.Empty(vm.FilteredSlashCommands);
    }

    [AvaloniaFact]
    public void SlashHelp_OpenSlashHelpCommand_DoesNotMarkChatInteracted()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        Assert.True(vm.HasOnlyWelcomeMessage);

        vm.OpenSlashHelpCommand.Execute(null);

        Assert.True(vm.HasOnlyWelcomeMessage);
    }

    [AvaloniaFact]
    public void SlashHelpQuery_FiltersByTitleAndDescription()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.OpenSlashHelpCommand.Execute(null);

        vm.SlashHelpQuery = "firewall";

        Assert.Contains(vm.FilteredSlashHelpCommands, c => c.CommandText == "/firewall");
        Assert.DoesNotContain(vm.FilteredSlashHelpCommands, c => c.CommandText == "/ports");

        vm.SlashHelpQuery = "ports";

        Assert.Contains(vm.FilteredSlashHelpCommands, c => c.CommandText == "/ports");
        Assert.DoesNotContain(vm.FilteredSlashHelpCommands, c => c.CommandText == "/firewall");
    }

    [AvaloniaFact]
    public void SlashHelpQuery_Empty_ShowsAllCommands()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.OpenSlashHelpCommand.Execute(null);
        var allCount = vm.FilteredSlashHelpCommands.Count;
        vm.SlashHelpQuery = "firewall";
        Assert.Single(vm.FilteredSlashHelpCommands, c => c.CommandText == "/firewall");
        Assert.True(vm.FilteredSlashHelpCommands.Count < allCount);

        vm.SlashHelpQuery = "";

        Assert.Equal(allCount, vm.FilteredSlashHelpCommands.Count);
        Assert.Contains(vm.FilteredSlashHelpCommands, c => c.CommandText == "/firewall");
        Assert.Contains(vm.FilteredSlashHelpCommands, c => c.CommandText == "/ports");
    }

    [AvaloniaFact]
    public void SlashHelp_CloseSlashHelpCommand_HidesHelp()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.OpenSlashHelpCommand.Execute(null);
        Assert.True(vm.IsSlashHelpOpen);

        vm.CloseSlashHelpCommand.Execute(null);

        Assert.False(vm.IsSlashHelpOpen);
        Assert.Empty(vm.FilteredSlashHelpCommands);
        Assert.Null(vm.SelectedSlashHelpCommand);
    }

    [AvaloniaFact]
    public void SlashHelp_OpenSlashHelpCommand_OpensPopup()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.OpenSlashHelpCommand.Execute(null);

        Assert.True(vm.IsSlashHelpOpen);
        Assert.Contains(vm.FilteredSlashHelpCommands, c => c.CommandText == "/help");
        Assert.DoesNotContain(vm.Messages, m => m.Text.Contains("Available commands:", StringComparison.Ordinal));
    }

    [AvaloniaFact]
    public void SlashHelp_ExecuteSelectedCommand_ClosesPopup()
    {
        var agent = new TrackingAgent(AgentIntent.FullAudit);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.OpenSlashHelpCommand.Execute(null);
        vm.SlashHelpQuery = "/firewall";
        Assert.True(vm.IsSlashHelpOpen);

        vm.ExecuteSlashCommandCommand.Execute(vm.SelectedSlashHelpCommand);

        Assert.False(vm.IsSlashHelpOpen);
        Assert.Equal(AgentIntent.FirewallCheck, agent.LastRunAuditIntent);
    }

    [AvaloniaFact]
    public async Task SendQuery_HelpSlashCommand_OpensPopup()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/help"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.IsSlashHelpOpen);
        Assert.True(vm.HasOnlyWelcomeMessage);
        Assert.DoesNotContain(vm.Messages, m => m.Text.Contains("Available commands:", StringComparison.Ordinal));
    }

    [AvaloniaFact]
    public void SlashPalette_UpdateSlashPalette_DoesNotOpenWhileHelpIsOpen()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.OpenSlashHelpCommand.Execute(null);
        Assert.True(vm.IsSlashHelpOpen);

        // Typing a slash command while the help popup is open should not reveal the inline palette.
        vm.UserQuery = "/fire";

        Assert.False(vm.IsSlashPaletteOpen);
        Assert.Empty(vm.FilteredSlashCommands);
    }

    [AvaloniaFact]
    public void SlashHelp_SelectNextSlashHelpCommand_WrapsToTop()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.OpenSlashHelpCommand.Execute(null);
        var first = vm.SelectedSlashHelpCommand;
        Assert.NotNull(first);
        var count = vm.FilteredSlashHelpCommands.Count;
        Assert.True(count > 2, "Test requires at least three slash-help commands.");

        vm.SelectNextSlashHelpCommand();
        var second = vm.SelectedSlashHelpCommand;
        Assert.NotNull(second);
        Assert.NotEqual(first, second);

        // Advance through the remaining items so selection wraps back to the first item.
        for (var i = 0; i < count - 1; i++)
        {
            vm.SelectNextSlashHelpCommand();
        }

        Assert.Equal(first, vm.SelectedSlashHelpCommand);
    }

    [AvaloniaFact]
    public void SlashHelp_SelectPreviousSlashHelpCommand_WrapsToBottom()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.OpenSlashHelpCommand.Execute(null);
        var first = vm.SelectedSlashHelpCommand;
        Assert.NotNull(first);
        var count = vm.FilteredSlashHelpCommands.Count;
        Assert.True(count > 2, "Test requires at least three slash-help commands.");

        vm.SelectPreviousSlashHelpCommand();
        var last = vm.SelectedSlashHelpCommand;
        Assert.NotNull(last);
        Assert.NotEqual(first, last);
        Assert.Equal(vm.FilteredSlashHelpCommands[^1], last);

        // Moving backward from the last item should reach the penultimate item, not wrap again.
        vm.SelectPreviousSlashHelpCommand();
        Assert.Equal(vm.FilteredSlashHelpCommands[^2], vm.SelectedSlashHelpCommand);

        // Wrap all the way back around to the first item.
        for (var i = 0; i < count - 2; i++)
        {
            vm.SelectPreviousSlashHelpCommand();
        }
        Assert.Equal(first, vm.SelectedSlashHelpCommand);
    }

    [AvaloniaFact]
    public void SlashHelpQuery_NoMatches_ClearsSelectedCommand()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.OpenSlashHelpCommand.Execute(null);
        Assert.NotNull(vm.SelectedSlashHelpCommand);

        vm.SlashHelpQuery = "zzzznomatch";

        Assert.Empty(vm.FilteredSlashHelpCommands);
        Assert.Null(vm.SelectedSlashHelpCommand);
    }

    [AvaloniaFact]
    public void SlashHelp_CloseSlashHelpCommand_ThenReopen_RestoresAllCommands()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.OpenSlashHelpCommand.Execute(null);
        var allCount = vm.FilteredSlashHelpCommands.Count;
        vm.SlashHelpQuery = "firewall";
        Assert.Single(vm.FilteredSlashHelpCommands);

        vm.CloseSlashHelpCommand.Execute(null);
        Assert.False(vm.IsSlashHelpOpen);
        Assert.Empty(vm.FilteredSlashHelpCommands);

        vm.OpenSlashHelpCommand.Execute(null);
        Assert.True(vm.IsSlashHelpOpen);
        Assert.Equal(allCount, vm.FilteredSlashHelpCommands.Count);
        Assert.Contains(vm.FilteredSlashHelpCommands, c => c.CommandText == "/firewall");
        Assert.Contains(vm.FilteredSlashHelpCommands, c => c.CommandText == "/ports");
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_HelpSlashCommand_KeepsWelcomeOverlayVisible()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/help"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.IsSlashHelpOpen);
        Assert.True(vm.HasOnlyWelcomeMessage);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_AgentError_MarksMessageAsError()
    {
        var vm = new AgentViewModel(new ErrorAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check firewall"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var errorMessage = vm.Messages.FirstOrDefault(m => m.Text == "Agent error: boom");
        Assert.NotNull(errorMessage);
        Assert.True(errorMessage!.IsError);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_AgentError_StylingUsesErrorBubbleConverter()
    {
        var vm = new AgentViewModel(new ErrorAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check firewall"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var errorMessage = vm.Messages.First(m => m.Text == "Agent error: boom");
        var converter = new MessageBubbleBackgroundConverter();
        var brush = converter.Convert(errorMessage, typeof(global::Avalonia.Media.IBrush), null, System.Globalization.CultureInfo.InvariantCulture);
        Assert.IsType<global::Avalonia.Media.SolidColorBrush>(brush);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_AgentError_ExistingMessageStaysNonError()
    {
        var vm = new AgentViewModel(new ErrorAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check firewall"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var userMessage = vm.Messages.First(m => m.IsUser);
        Assert.False(userMessage.IsError);
    }

    [AvaloniaFact]
    public void ChatSearch_EmptyState_WhenNoMatches()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });

        vm.ChatSearchQuery = "network";

        Assert.True(vm.HasNoSearchMatches);
        Assert.Equal("No messages match your search.", vm.ChatSearchEmptyStateText);
    }

    [AvaloniaFact]
    public void ChatSearch_EmptyState_WithActiveFilters()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.ChatCategoryFilters.Add(ChatFilterConstants.AllCategoriesFilter);
        vm.ChatCategoryFilters.Add("Firewall");
        vm.ChatCategoryFilters.Add("Network");
        vm.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", Category = "Firewall", IsVisible = true });
        vm.Messages.Add(new AgentMessageViewModel { Text = "network port open", Category = "Network", IsVisible = true });

        vm.SelectedChatCategoryFilter = "Firewall";
        vm.ChatSearchQuery = "network";

        Assert.True(vm.HasNoSearchMatches);
        Assert.Equal("No visible messages match your search and active filters.", vm.ChatSearchEmptyStateText);
    }

    [AvaloniaFact]
    public void ChatSearch_ComposesWithSeverityFilter()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.Messages.Add(new AgentMessageViewModel { Text = "critical finding", Severity = Severity.Critical, Category = "Firewall", IsVisible = true });
        vm.Messages.Add(new AgentMessageViewModel { Text = "medium finding", Severity = Severity.Medium, Category = "Firewall", IsVisible = true });

        vm.SelectedChatSeverityFilter = vm.ChatSeverityFilters[2]; // Critical only
        vm.ChatSearchQuery = "finding";

        Assert.True(vm.Messages[0].IsVisible);
        Assert.False(vm.Messages[1].IsVisible);
    }

    [AvaloniaFact]
    public void ChatSearch_ComposesWithSeverityAndCategoryFilters()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.ChatCategoryFilters.Add(ChatFilterConstants.AllCategoriesFilter);
        vm.ChatCategoryFilters.Add("Firewall");
        vm.ChatCategoryFilters.Add("Network");
        vm.Messages.Add(new AgentMessageViewModel { Text = "critical firewall", Severity = Severity.Critical, Category = "Firewall", IsVisible = true });
        vm.Messages.Add(new AgentMessageViewModel { Text = "medium firewall", Severity = Severity.Medium, Category = "Firewall", IsVisible = true });
        vm.Messages.Add(new AgentMessageViewModel { Text = "critical network", Severity = Severity.Critical, Category = "Network", IsVisible = true });

        vm.SelectedChatSeverityFilter = vm.ChatSeverityFilters[2]; // Critical only
        vm.SelectedChatCategoryFilter = "Firewall";
        vm.ChatSearchQuery = "firewall";

        Assert.True(vm.Messages[0].IsVisible);
        Assert.False(vm.Messages[1].IsVisible);
        Assert.False(vm.Messages[2].IsVisible);
    }

    [AvaloniaFact]
    public void QueryHistory_DownFromEmpty_KeepsEmpty()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.RecallNextQuery();

        Assert.Empty(vm.UserQuery);
    }

    [AvaloniaFact]
    public void QueryHistory_UpDown_ResetsIndexToEmpty()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "first";
        vm.SendQueryCommand.Execute(null);

        vm.RecallPreviousQuery();
        Assert.Equal("first", vm.UserQuery);

        vm.RecallNextQuery();
        Assert.Empty(vm.UserQuery);

        // Recalling next again from empty state should remain empty.
        vm.RecallNextQuery();
        Assert.Empty(vm.UserQuery);
    }

    [AvaloniaFact]
    public void QueryHistory_EditingRecalled_DoesNotAddUntilSent()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "first";
        vm.SendQueryCommand.Execute(null);
        vm.UserQuery = "second";
        vm.SendQueryCommand.Execute(null);

        vm.RecallPreviousQuery();
        Assert.Equal("second", vm.UserQuery);

        // Modify without sending - history should not change yet.
        vm.UserQuery = "modified";
        vm.RecallNextQuery();
        Assert.Empty(vm.UserQuery);
        vm.RecallPreviousQuery();
        Assert.Equal("second", vm.UserQuery);
    }

    [AvaloniaFact]
    public void SendQueryCommand_AgentError_KeepsAutomationIdAndFeatureParityControls()
    {
        var xaml = ReadAgentViewXaml();

        Assert.Contains("MessageBubbleBackground", xaml);
        Assert.Contains("MessageBubbleBorderBrush", xaml);
        Assert.Contains("MessageBubbleForeground", xaml);
        Assert.Contains("FormattedBlocks", xaml);
    }

    [AvaloniaFact]
    public void AgentMessageViewModel_IsError_DefaultsFalse()
    {
        var message = new AgentMessageViewModel { Text = "normal" };

        Assert.False(message.IsError);
    }

    [AvaloniaFact]
    public void AgentMessageViewModel_ErrorText_IsErrorSetByPresenter()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/clear"
        };
        vm.SendQueryCommand.Execute(null);

        // /clear adds an info message; no error.
        Assert.DoesNotContain(vm.Messages, m => m.IsError);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_AgentError_AddsErrorMessageAndClearsBusyState()
    {
        var vm = new AgentViewModel(new ErrorAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check firewall"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.IsBusy);
        Assert.Contains(vm.Messages, message => message.Text == "Agent error: boom" && message.IsInfo);
    }

    [AvaloniaFact]
    public async Task SendQuery_SlashCommand_RunsThatCommand()
    {
        // The typed command must dispatch to its own handler (consistent with the palette shown).
        var agent = new TrackingAgent(AgentIntent.FullAudit);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/firewall"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(AgentIntent.FirewallCheck, agent.LastRunAuditIntent);
    }

    [AvaloniaTheory]
    [InlineData("/ssh", AgentIntent.SshCheck)]
    [InlineData("/filesystem", AgentIntent.FilesystemAuditCheck)]
    [InlineData("/kernel", AgentIntent.KernelCheck)]
    [InlineData("/users", AgentIntent.UserAccountCheck)]
    [InlineData("/logging", AgentIntent.LoggingAuditCheck)]
    [InlineData("/cron", AgentIntent.CronJobCheck)]
    [InlineData("/packages", AgentIntent.PackageVulnerabilityCheck)]
    [InlineData("/threatintel", AgentIntent.ThreatIntelCheck)]
    [InlineData("/full", AgentIntent.FullAudit)]
    public async Task SendQuery_SlashAuditAlias_RunsExpectedAudit(string command, AgentIntent expectedIntent)
    {
        var agent = new TrackingAgent(AgentIntent.FullAudit);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = command
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(expectedIntent, agent.LastRunAuditIntent);
    }

    [AvaloniaFact]
    public async Task SendQuery_ClearSlashCommand_ClearsVisibleConversation()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "/clear"
        };
        vm.Messages.Add(new AgentMessageViewModel { Text = "old" });

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.DoesNotContain(vm.Messages, m => m.Text == "old");
        Assert.Contains(vm.Messages, m => m.Text.Contains("Ask me about your system security", StringComparison.Ordinal));
    }

    [AvaloniaFact]
    public void Constructor_HasOnlyWelcomeMessage_IsTrue()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.True(vm.HasOnlyWelcomeMessage);
    }

    [AvaloniaFact]
    public void Constructor_InitializesAgentToolsPanelCollections()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.False(vm.IsAgentToolsPanelOpen);
        Assert.NotEmpty(vm.ToolPanelAnalysisActions);
        Assert.NotEmpty(vm.ToolPanelRunCheckActions);
        Assert.NotEmpty(vm.ToolPanelBaselineActions);
        Assert.NotEmpty(vm.ToolPanelExportActions);
    }

    [AvaloniaFact]
    public void ToggleAgentToolsPanelCommand_FlipsIsAgentToolsPanelOpen()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.False(vm.IsAgentToolsPanelOpen);

        vm.ToggleAgentToolsPanelCommand.Execute(null);

        Assert.True(vm.IsAgentToolsPanelOpen);

        vm.ToggleAgentToolsPanelCommand.Execute(null);

        Assert.False(vm.IsAgentToolsPanelOpen);
    }

    [AvaloniaFact]
    public async Task RunCheckCommand_CollapsesAgentToolsPanel()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.ToggleAgentToolsPanelCommand.Execute(null);
        Assert.True(vm.IsAgentToolsPanelOpen);

        vm.FirewallCommand.Execute(null);
        await vm.FirewallCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.IsAgentToolsPanelOpen);
    }

    [AvaloniaFact]
    public void AgentToolsPanel_PreservesLegacyAutomationIds()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        var panelIds = vm.ToolPanelAnalysisActions
            .Concat(vm.ToolPanelRunCheckActions)
            .Concat(vm.ToolPanelBaselineActions)
            .Concat(vm.ToolPanelExportActions)
            .Select(a => a.AutomationId)
            .ToList();

        Assert.Contains("AgentExplainSelectedButton", panelIds);
        Assert.Contains("AgentThreatIntelButton", panelIds);
        Assert.Contains("AgentCompareAuditsButton", panelIds);
        Assert.Contains("AgentCompareSelectedButton", panelIds);
        Assert.Contains("AgentExportRemediationButton", panelIds);
        Assert.Contains("AgentExportSessionButton", panelIds);
    }

    [AvaloniaFact]
    public async Task SendQuery_MarksChatInteracted()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "hello"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.HasOnlyWelcomeMessage);
    }

    [AvaloniaFact]
    public async Task ClearChat_RestoresWelcomeState()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "hello"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();
        Assert.False(vm.HasOnlyWelcomeMessage);

        vm.UserQuery = "/clear";
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.HasOnlyWelcomeMessage);
    }

    [AvaloniaFact]
    public void SelectedChatSeverityFilter_NonDefault_CreatesActiveChip()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.SelectedChatSeverityFilter = vm.ChatSeverityFilters[1];

        Assert.Single(vm.ActiveChatFilterChips);
        Assert.Contains("High", vm.ActiveChatFilterChips[0].Label, StringComparison.Ordinal);
    }

    [AvaloniaFact]
    public void SelectedChatCategoryFilter_NonAll_CreatesActiveChip()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.ChatCategoryFilters.Add(ChatFilterConstants.AllCategoriesFilter);
        vm.ChatCategoryFilters.Add("Firewall");

        vm.SelectedChatCategoryFilter = "Firewall";

        Assert.Single(vm.ActiveChatFilterChips);
        Assert.Contains("Firewall", vm.ActiveChatFilterChips[0].Label, StringComparison.Ordinal);
    }

    [AvaloniaFact]
    public void HasNoVisibleMessages_TrueWhenFiltersHideAllMessages()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear(); // remove welcome message so the property reflects filtered content only
        vm.ChatCategoryFilters.Add(ChatFilterConstants.AllCategoriesFilter);
        vm.ChatCategoryFilters.Add("Firewall");
        vm.Messages.Add(new AgentMessageViewModel { Text = "Network finding", Category = "Network", IsVisible = true });

        Assert.False(vm.HasNoVisibleMessages);

        vm.SelectedChatCategoryFilter = "Firewall";

        Assert.True(vm.HasNoVisibleMessages);
    }

    [AvaloniaFact]
    public void HasNoVisibleFilterMessages_IgnoresAlwaysVisibleContextMessages()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Add(new AgentMessageViewModel
        {
            Text = "Medium firewall finding",
            Category = "Firewall",
            Severity = Severity.Medium,
            IsVisible = true
        });

        vm.SelectedChatSeverityFilter = vm.ChatSeverityFilters[2]; // Critical only

        Assert.False(vm.HasNoVisibleMessages); // welcome/context text remains visible
        Assert.True(vm.HasNoVisibleFilterMessages);

        vm.Messages.Add(new AgentMessageViewModel
        {
            Text = "Critical firewall finding",
            Category = "Firewall",
            Severity = Severity.Critical,
            IsVisible = true
        });

        Assert.False(vm.HasNoVisibleFilterMessages);
    }

    [AvaloniaFact]
    public void HasNoVisibleMessages_UpdatesWhenMessageBecomesVisibleWithoutFilterChange()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.ChatCategoryFilters.Add(ChatFilterConstants.AllCategoriesFilter);
        vm.ChatCategoryFilters.Add("Firewall");
        vm.SelectedChatCategoryFilter = "Firewall";

        var message = new AgentMessageViewModel { Text = "Network finding", Category = "Network", IsVisible = false };
        vm.Messages.Add(message);

        Assert.True(vm.HasNoVisibleMessages);

        message.IsVisible = true;

        Assert.False(vm.HasNoVisibleMessages);
    }

    [AvaloniaFact]
    public void HasNoVisibleMessages_UpdatesWhenMessageRemoved()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();

        var message = new AgentMessageViewModel { Text = "Hidden finding", Category = "Network", IsVisible = true };
        vm.Messages.Add(message);
        vm.ChatSearchQuery = "xyz";
        Assert.True(vm.HasNoVisibleMessages);

        vm.Messages.Remove(message);

        Assert.False(vm.HasNoVisibleMessages);
    }

    [AvaloniaFact]
    public void AgentMessageViewModel_FormattedTimestamp_ReturnsShortTime()
    {
        var message = new AgentMessageViewModel
        {
            Timestamp = new DateTime(2026, 7, 2, 14, 30, 0)
        };

        Assert.Equal("14:30", message.FormattedTimestamp);
        Assert.True(message.ShowTimestamp);
    }

    [AvaloniaFact]
    public void AgentViewXaml_ExposesFeatureParityControls()
    {
        var xaml = ReadAgentViewXaml();
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        foreach (var automationId in new[]
        {
            "AgentQueryInput",
            "AgentSendButton",
            "AgentCancelButton",
            "AgentSlashHelpButton",
            "AgentToolsToggleButton",
            "AgentChatSeverityFilter",
            "AgentChatCategoryFilter",
            "AgentClearChatFiltersButton",
            "AgentDeployCountermeasuresButton",
            "AgentVerifyRemediationButton"
        })
        {
            Assert.Contains($"AutomationProperties.AutomationId=\"{automationId}\"", xaml);
        }

        var panelIds = vm.ToolPanelAnalysisActions
            .Concat(vm.ToolPanelRunCheckActions)
            .Concat(vm.ToolPanelBaselineActions)
            .Concat(vm.ToolPanelExportActions)
            .Select(a => a.AutomationId)
            .ToList();

        foreach (var automationId in new[]
        {
            "AgentExplainSelectedButton",
            "AgentThreatIntelButton",
            "AgentExportRemediationButton",
            "AgentExportSessionButton",
            "AgentCompareAuditsButton",
            "AgentCompareSelectedButton"
        })
        {
            Assert.Contains(automationId, panelIds);
        }

        Assert.Contains("Header=\"Audit History\"", xaml);
        Assert.Contains("Header=\"Remediation Sessions\"", xaml);
        Assert.Contains("ToolPanelAnalysisActions", xaml);
        Assert.Contains("ToolPanelRunCheckActions", xaml);
        Assert.Contains("ToolPanelBaselineActions", xaml);
        Assert.Contains("ToolPanelExportActions", xaml);
        Assert.Contains("ToggleAgentToolsPanelCommand", xaml);
        Assert.Contains("BoolToMaxHeight", xaml);
        Assert.Contains("HasImpactPreview", xaml);
        Assert.Contains("ImpactPreviewRiskBefore", xaml);
        Assert.Contains("ImpactPreviewRollbackAvailabilityLabel", xaml);
        Assert.Contains("HasCountermeasureCommands", xaml);
        Assert.Contains("CountermeasureCommands", xaml);
        Assert.Contains("DeployCountermeasuresCommand", xaml);
        Assert.Contains("HasActiveSession", xaml);
        Assert.Contains("VerifySessionCommand", xaml);
        Assert.Contains("HasSessionTimeline", xaml);
        Assert.Contains("SessionTimeline", xaml);

        foreach (var directAction in new[]
        {
            "Export Remediation",
            "Export Session",
            "Compare Last Two",
            "Compare Selected"
        })
        {
            Assert.DoesNotContain($"<Button Content=\"{directAction}\"", xaml);
            Assert.DoesNotContain($"<MenuItem Header=\"{directAction}\"", xaml);
        }
    }

    [AvaloniaFact]
    public async Task YaraCommand_RunsYaraAudit()
    {
        var agent = new TrackingAgent(AgentIntent.YaraCheck);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.YaraCommand.Execute(null);
        await vm.YaraCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(AgentIntent.YaraCheck, agent.LastRunAuditIntent);
        Assert.True(vm.CanExportAudit);
        Assert.Single(vm.History);
        Assert.Equal(AgentIntent.YaraCheck, vm.History[0].Intent);
    }

    [AvaloniaFact]
    public async Task CheckDriftCommand_AfterShowBaseline_UsesLastAuditIntent()
    {
        var agent = new TrackingAgent(AgentIntent.SshCheck);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check ssh"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        vm.ShowBaselineCommand.Execute(null);
        await vm.ShowBaselineCommand.ExecutionTask;
        FlushDispatcher();

        vm.CheckDriftCommand.Execute(null);
        await vm.CheckDriftCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(AgentIntent.SshCheck, agent.LastBaselineIntent);
        Assert.Equal(AgentIntent.SshCheck, agent.LastDriftIntent);
    }

    [AvaloniaFact]
    public void SetBaselineCommand_IsDisabledBeforeAudit()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.False(vm.SetBaselineCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task SetAgent_ClearsStaleAuditState()
    {
        var vm = new AgentViewModel(new TrackingAgent(AgentIntent.SshCheck), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check ssh"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();
        Assert.True(vm.CanExportAudit);
        Assert.True(vm.SetBaselineCommand.CanExecute(null));

        vm.SetAgent(new StubAgent());

        Assert.Null(vm.LastResult);
        Assert.False(vm.CanExportAudit);
        Assert.False(vm.SetBaselineCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task CancelQueryCommand_CancelsActiveOperationAndClearsBusyState()
    {
        var vm = new AgentViewModel(new CancellableAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check firewall"
        };

        vm.SendQueryCommand.Execute(null);
        Assert.True(vm.IsBusy);
        Assert.True(vm.CancelQueryCommand.CanExecute(null));

        vm.CancelQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.IsBusy);
        Assert.Contains(vm.Messages, message => message.Text == "Query cancelled." && message.IsInfo);
    }

    [AvaloniaFact]
    public async Task SetBaselineCommand_AgentError_AddsErrorMessageAndClearsBusyState()
    {
        var vm = new AgentViewModel(new SetBaselineErrorAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        vm.SetBaselineCommand.Execute(null);
        await vm.SetBaselineCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.IsBusy);
        Assert.Contains(vm.Messages, message => message.Text == "Agent error: baseline boom" && message.IsInfo);
    }

    [AvaloniaFact]
    public async Task CancelQueryCommand_CancelsActiveDriftOperationAndClearsBusyState()
    {
        var vm = new AgentViewModel(new CancellableDriftAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        vm.CheckDriftCommand.Execute(null);
        Assert.True(vm.IsBusy);
        Assert.True(vm.CancelQueryCommand.CanExecute(null));

        vm.CancelQueryCommand.Execute(null);
        await vm.CheckDriftCommand.ExecutionTask;
        FlushDispatcher();

        Assert.False(vm.IsBusy);
        Assert.Contains(vm.Messages, message => message.Text == "Query cancelled." && message.IsInfo);
    }

    [AvaloniaFact]
    public async Task ShowBaselineCommand_SuppressesCapabilityPassedAndWarningSections()
    {
        var vm = new AgentViewModel(new NoisyBaselineAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();
        vm.Messages.Clear();

        vm.ShowBaselineCommand.Execute(null);
        await vm.ShowBaselineCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, message => message.Text == "baseline summary");
        Assert.DoesNotContain(vm.Messages, message => message.Text == "hidden capability report");
        Assert.DoesNotContain(vm.Messages, message => message.Text == "✓ 4 check(s) passed");
        Assert.DoesNotContain(vm.Messages, message => message.Text.StartsWith("Warnings:"));
    }

    [AvaloniaFact]
    public async Task ExplainSelectedCommand_ExplainsFindingAndAddsMessages()
    {
        var finding = CreateFinding();
        var agent = new ExplainFindingAgent(finding);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            SelectedFindingProvider = () => finding
        };

        Assert.True(vm.ExplainSelectedCommand.CanExecute(null));

        vm.ExplainSelectedCommand.Execute(null);
        await vm.ExplainSelectedCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text == "Explain selected" && m.IsUser);
        Assert.Contains(vm.Messages, m => m.Text == "explanation summary");
        Assert.Contains(vm.Messages, m => m.Details.Contains("SSH exposed") && m.Severity == Severity.High);
        Assert.False(vm.IsBusy);
    }

    [AvaloniaFact]
    public async Task ExplainSelectedCommand_NoSelection_AddsGuidanceMessage()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            SelectedFindingProvider = () => null
        };

        vm.ExplainSelectedCommand.Execute(null);
        await vm.ExplainSelectedCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text == "No finding is selected. Select a finding from the list first." && m.IsInfo);
        Assert.False(vm.IsBusy);
    }

    [AvaloniaFact]
    public async Task VerifySelectedCommand_VerifiesFindingAndAddsMessages()
    {
        var finding = CreateFinding();
        var agent = new VerifyFindingAgent(finding.RuleId!);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            SelectedFindingProvider = () => finding
        };

        Assert.True(vm.VerifySelectedCommand.CanExecute(null));

        vm.VerifySelectedCommand.Execute(null);
        await vm.VerifySelectedCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text == $"Verify {finding.RuleId}" && m.IsUser);
        Assert.Contains(vm.Messages, m => m.Text == $"verified {finding.RuleId}");
        Assert.False(vm.IsBusy);
    }

    [AvaloniaFact]
    public async Task VerifySelectedCommand_NoRuleId_AddsGuidanceMessage()
    {
        var finding = CreateFinding() with { RuleId = "" };
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            SelectedFindingProvider = () => finding
        };

        vm.VerifySelectedCommand.Execute(null);
        await vm.VerifySelectedCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text == "Select a finding with a rule ID to verify remediation." && m.IsInfo);
        Assert.False(vm.IsBusy);
    }

    [AvaloniaFact]
    public async Task VerifySelectedCommand_NoSelection_AddsGuidanceMessage()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            SelectedFindingProvider = () => null
        };

        vm.VerifySelectedCommand.Execute(null);
        await vm.VerifySelectedCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text == "Select a finding with a rule ID to verify remediation." && m.IsInfo);
        Assert.False(vm.IsBusy);
    }

    [AvaloniaFact]
    public async Task SetBaselineCommand_AfterAudit_DisplaysBaselineSummary()
    {
        var vm = new AgentViewModel(new SetBaselineSuccessAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.SetBaselineCommand.CanExecute(null));
        vm.Messages.Clear();

        vm.SetBaselineCommand.Execute(null);
        await vm.SetBaselineCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text == "Set baseline" && m.IsUser);
        Assert.Contains(vm.Messages, m => m.Text == "baseline saved" && m.IsInfo);
        Assert.False(vm.IsBusy);
    }

    [AvaloniaFact]
    public async Task CheckDriftCommand_AfterAudit_DisplaysDriftResult()
    {
        var agent = new DriftResultAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "check ssh"
        };
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();
        vm.Messages.Clear();

        vm.CheckDriftCommand.Execute(null);
        await vm.CheckDriftCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Contains(vm.Messages, m => m.Text.StartsWith("Check drift") && m.IsUser);
        Assert.Contains(vm.Messages, m => m.Text == "drift summary");
        Assert.DoesNotContain(vm.Messages, m => m.Text == "hidden capability report");
        Assert.False(vm.IsBusy);
    }

    [AvaloniaFact]
    public async Task ExportSessionCommand_WithSessionResult_InvokesExportCallbackAndRefreshesTimeline()
    {
        var agent = new SessionResultAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "guided fix FW-001"
        };
        string? exported = null;
        vm.RequestExportSession = markdown =>
        {
            exported = markdown;
            return Task.FromResult(true);
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.CanExportSession);

        vm.ExportSessionCommand.Execute(null);
        await vm.ExportSessionCommand.ExecutionTask;
        FlushDispatcher();

        Assert.NotNull(exported);
        Assert.Contains("VulcansTrace Remediation Session Report", exported);
        Assert.Contains("abc12345", exported);
        Assert.Equal(1, agent.MarkExportedCallCount);
        Assert.Contains(vm.LastResult!.RemediationSession!.Timeline, e => e.Type == RemediationSessionEventType.Exported);
        Assert.Contains(vm.Messages, m => m.SessionId == "abc12345"
            && m.SessionTimeline.Any(e => e.Type == RemediationSessionEventType.Exported));
    }

    [AvaloniaFact]
    public async Task ExportSessionCommand_WhenSaveIsCancelled_DoesNotMarkSessionExported()
    {
        var agent = new SessionResultAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "guided fix FW-001"
        };
        vm.RequestExportSession = _ => Task.FromResult(false);

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        vm.ExportSessionCommand.Execute(null);
        await vm.ExportSessionCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(0, agent.MarkExportedCallCount);
        Assert.DoesNotContain(vm.LastResult!.RemediationSession!.Timeline, e => e.Type == RemediationSessionEventType.Exported);
    }

    [AvaloniaFact]
    public async Task SuggestionCommand_AuditIntent_RoutesToRunAuditAsync()
    {
        var agent = new SuggestionRoutingAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask;
        FlushDispatcher();

        var message = vm.Messages.FirstOrDefault(m => m.HasSuggestions);
        Assert.NotNull(message);

        var showAll = message.Suggestions.First(s => s.Label == "Show all findings");
        Assert.Equal(AgentIntent.FullAudit, showAll.Intent);

        message.SuggestionCommand!.Execute(showAll);
        await agent.LastCommandTask;
        FlushDispatcher();

        Assert.Equal(AgentIntent.FullAudit, agent.LastRunAuditIntent);
        Assert.Null(agent.LastAskQuery);
    }

    [AvaloniaFact]
    public async Task SuggestionCommand_NonAuditIntent_RoutesToAskAsync()
    {
        var agent = new SuggestionRoutingAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "explain TEST-001"
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var message = vm.Messages.FirstOrDefault(m => m.HasSuggestions);
        Assert.NotNull(message);

        var fixIt = message.Suggestions.First(s => s.Label == "Fix it");
        Assert.Equal(AgentIntent.FixFinding, fixIt.Intent);

        message.SuggestionCommand!.Execute(fixIt);
        await agent.LastCommandTask;
        FlushDispatcher();

        Assert.Equal("fix TEST-001", agent.LastAskQuery);
        Assert.Null(agent.LastRunAuditIntent);
    }

    [AvaloniaFact]
    public async Task RunLatestSuggestedFollowUpCommand_UsesNewestSourceSuggestion()
    {
        var agent = new SuggestionRoutingAgent();
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask;
        FlushDispatcher();

        Assert.True(vm.HasLatestSuggestedFollowUp);
        Assert.Equal("Show all findings", vm.LatestSuggestedFollowUpLabel);
        Assert.True(vm.RunLatestSuggestedFollowUpCommand.CanExecute(null));

        vm.RunLatestSuggestedFollowUpCommand.Execute(null);
        await vm.RunLatestSuggestedFollowUpCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal(AgentIntent.FullAudit, agent.LastRunAuditIntent);
        Assert.Contains(vm.Messages, message =>
            message.IsUser && message.Text == "show all findings");
    }

    [AvaloniaFact]
    public void Constructor_MemoryStoreWarning_AddsInfoMessage()
    {
        var memoryStore = new InMemoryAgentMemoryStore("Memory persistence is unavailable for testing.");
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), memoryStore: memoryStore);

        Assert.Contains(vm.Messages, m => m.IsInfo && m.Text.Contains("Memory persistence is unavailable"));
    }

    [AvaloniaFact]
    public void QueryHistory_UpDown_RecallsSentQueries()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "first query";
        vm.SendQueryCommand.Execute(null);

        vm.UserQuery = "second query";
        vm.SendQueryCommand.Execute(null);

        Assert.Empty(vm.UserQuery);

        vm.RecallPreviousQuery();
        Assert.Equal("second query", vm.UserQuery);

        vm.RecallPreviousQuery();
        Assert.Equal("first query", vm.UserQuery);

        vm.RecallNextQuery();
        Assert.Equal("second query", vm.UserQuery);

        vm.RecallNextQuery();
        Assert.Empty(vm.UserQuery);
    }

    [AvaloniaFact]
    public void QueryHistory_UpAtTop_KeepsOldest()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "only query";
        vm.SendQueryCommand.Execute(null);

        vm.RecallPreviousQuery();
        Assert.Equal("only query", vm.UserQuery);

        vm.RecallPreviousQuery();
        Assert.Equal("only query", vm.UserQuery);
    }

    [AvaloniaFact]
    public void QueryHistory_NewQueryAfterRecall_ResetsIndex()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.UserQuery = "first";
        vm.SendQueryCommand.Execute(null);
        vm.UserQuery = "second";
        vm.SendQueryCommand.Execute(null);

        vm.RecallPreviousQuery();
        Assert.Equal("second", vm.UserQuery);

        vm.UserQuery = "third";
        vm.SendQueryCommand.Execute(null);

        vm.RecallPreviousQuery();
        Assert.Equal("third", vm.UserQuery);
        vm.RecallPreviousQuery();
        Assert.Equal("second", vm.UserQuery);
    }

    [AvaloniaFact]
    public void ChatSearch_FiltersMessagesByText()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });
        vm.Messages.Add(new AgentMessageViewModel { Text = "network port open", IsVisible = true });

        vm.ChatSearchQuery = "firewall";

        Assert.True(vm.Messages[0].IsVisible);
        Assert.False(vm.Messages[1].IsVisible);
        Assert.False(vm.HasNoSearchMatches);
    }

    [AvaloniaFact]
    public void ChatSearch_FiltersMessagesByDetails()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.Messages.Add(new AgentMessageViewModel { Text = "finding", Details = "ssh exposed", IsVisible = true });
        vm.Messages.Add(new AgentMessageViewModel { Text = "finding", Details = "password aging", IsVisible = true });

        vm.ChatSearchQuery = "ssh";

        Assert.True(vm.Messages[0].IsVisible);
        Assert.False(vm.Messages[1].IsVisible);
    }

    [AvaloniaFact]
    public void ChatSearch_ComposesWithCategoryFilter()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.ChatCategoryFilters.Add(ChatFilterConstants.AllCategoriesFilter);
        vm.ChatCategoryFilters.Add("Firewall");
        vm.ChatCategoryFilters.Add("Network");
        vm.Messages.Add(new AgentMessageViewModel { Text = "firewall finding", Category = "Firewall", IsVisible = true });
        vm.Messages.Add(new AgentMessageViewModel { Text = "network finding", Category = "Network", IsVisible = true });

        vm.SelectedChatCategoryFilter = "Firewall";
        vm.ChatSearchQuery = "network";

        Assert.False(vm.Messages[0].IsVisible);
        Assert.False(vm.Messages[1].IsVisible);
        Assert.True(vm.HasNoSearchMatches);
        Assert.Equal("No visible messages match your search and active filters.", vm.ChatSearchEmptyStateText);
    }

    [AvaloniaFact]
    public void ChatSearch_Clear_RestoresVisibility()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });
        vm.Messages.Add(new AgentMessageViewModel { Text = "network port open", IsVisible = true });

        vm.ChatSearchQuery = "firewall";
        Assert.False(vm.Messages[1].IsVisible);

        vm.ClearChatSearchCommand.Execute(null);

        Assert.True(vm.Messages[0].IsVisible);
        Assert.True(vm.Messages[1].IsVisible);
        Assert.False(vm.HasNoSearchMatches);
    }

    [AvaloniaFact]
    public void ClearCommand_ClearsSearchQueryAndHistoryIndex()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.UserQuery = "hello";
        vm.SendQueryCommand.Execute(null);
        vm.ChatSearchQuery = "hello";

        vm.UserQuery = "/clear";
        vm.SendQueryCommand.Execute(null);

        Assert.Empty(vm.ChatSearchQuery);
        Assert.False(vm.HasNoSearchMatches);
    }

    [AvaloniaFact]
    public void AgentViewXaml_ExposesSearchControls()
    {
        var xaml = ReadAgentViewXaml();

        Assert.Contains("AutomationProperties.AutomationId=\"AgentChatSearchInput\"", xaml);
        Assert.Contains("AutomationProperties.AutomationId=\"AgentChatSearchClearButton\"", xaml);
        Assert.Contains("Text=\"{Binding ChatSearchEmptyStateText}\"", xaml);
    }

    [AvaloniaFact]
    public void AgentViewXaml_OverlaysShareTranscriptRowAfterSearchRow()
    {
        var xaml = ReadAgentViewXaml();

        Assert.Contains("<ListBox x:Name=\"ChatListBox\"\n               Grid.Row=\"4\"", xaml);
        Assert.Contains("<!-- Welcome suggestions overlay -->\n        <!-- Intentionally stretches to fill the chat cell so the list's own welcome bubble cannot show through. -->\n        <Border Grid.Row=\"4\"", xaml);
        Assert.Contains("<controls:FilterEmptyStateView Grid.Row=\"4\"", xaml);
        Assert.Contains("IsVisible=\"{Binding HasNoVisibleFilterMessages}\"", xaml);
    }

    [AvaloniaFact]
    public void AgentViewXaml_StreamingTextUsesConstrainedGridForWrapping()
    {
        var xaml = ReadAgentViewXaml();

        Assert.Contains("AutomationProperties.AutomationId=\"AgentStreamingMessage\"", xaml);
        Assert.Contains("<Grid ColumnDefinitions=\"*,Auto\"", xaml);
        Assert.Contains("<TextBlock Grid.Column=\"0\"\n                                 Text=\"{Binding StreamingText}\"\n                                 TextWrapping=\"Wrap\"", xaml);
        Assert.Contains("<Border Grid.Column=\"1\"\n                              Width=\"2\"", xaml);
    }

    [AvaloniaFact]
    public void AgentViewXaml_MessageAutomationIdUsesStableMessageIdentity()
    {
        var xaml = ReadAgentViewXaml();

        Assert.Contains(
            "AutomationProperties.AutomationId=\"{Binding MessageId, StringFormat='AgentMessage_{0}'}\"",
            xaml);
        Assert.DoesNotContain(
            "AutomationProperties.AutomationId=\"{Binding Text, StringFormat='AgentMessage_{0}'}\"",
            xaml);
    }

    [AvaloniaFact]
    public void AgentViewXaml_ExposesStableLatestSuggestionAction()
    {
        var xaml = ReadAgentViewXaml();

        Assert.Contains(
            "AutomationProperties.AutomationId=\"AgentLatestSuggestionButton\"",
            xaml);
        Assert.Contains(
            "AutomationProperties.Name=\"Run latest suggested follow-up\"",
            xaml);
        Assert.Contains(
            "Command=\"{Binding RunLatestSuggestedFollowUpCommand}\"",
            xaml);
    }

    [AvaloniaFact]
    public void ClearSearchCommand_CanExecute_UpdatesWhenQueryChanges()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.False(vm.ClearChatSearchCommand.CanExecute(null));

        vm.ChatSearchQuery = "firewall";

        Assert.True(vm.ClearChatSearchCommand.CanExecute(null));

        vm.ChatSearchQuery = string.Empty;

        Assert.False(vm.ClearChatSearchCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void ChatSearch_NoSearchMatches_MessageSearchMatchesSearchWording()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });
        vm.ChatSearchQuery = "network";

        Assert.True(vm.HasNoSearchMatches);
        Assert.Equal("No messages match your search.", vm.ChatSearchEmptyStateText);
        Assert.False(vm.HasNoVisibleFilterMessages);
    }

    [AvaloniaFact]
    public void FilterEmptyState_IsHiddenWhileSearchEmptyStateIsActive()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.ChatCategoryFilters.Add(ChatFilterConstants.AllCategoriesFilter);
        vm.ChatCategoryFilters.Add("Firewall");
        vm.Messages.Add(new AgentMessageViewModel { Text = "network finding", Category = "Network", IsVisible = true });

        vm.SelectedChatCategoryFilter = "Firewall";

        Assert.True(vm.HasNoVisibleFilterMessages);
        Assert.True(vm.HasNoVisibleMessages);

        vm.ChatSearchQuery = "network";

        Assert.False(vm.HasNoVisibleFilterMessages);
        Assert.True(vm.HasNoSearchMatches);
        Assert.Equal("No visible messages match your search and active filters.", vm.ChatSearchEmptyStateText);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_ProseMessage_StreamsText()
    {
        var scheduler = new ManualTypewriterScheduler();
        var agent = new StreamingAgent("Summary line.", "Narrative paragraph one. Narrative paragraph two.");
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "audit",
            TypewriterScheduler = scheduler
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var proseMessages = vm.Messages.Where(m => m.IsProse).ToList();
        Assert.Equal(2, proseMessages.Count);

        var summary = proseMessages[0];
        var narrative = proseMessages[1];
        Assert.True(summary.IsStreaming);
        Assert.Equal("Summary line.", summary.StreamingFinalText);
        Assert.Equal(string.Empty, summary.StreamingText);

        scheduler.Tick();
        Assert.Equal("Sum", summary.StreamingText);

        scheduler.Tick();
        Assert.Equal("Summar", summary.StreamingText);

        scheduler.Tick();
        Assert.Equal("Summary l", summary.StreamingText);

        scheduler.Tick();
        Assert.Equal("Summary line", summary.StreamingText);

        scheduler.Tick();
        Assert.Equal("Summary line.", summary.Text);
        Assert.False(summary.IsStreaming);

        // Narrative should now be streaming.
        Assert.True(narrative.IsStreaming);
        scheduler.Tick();
        Assert.Equal("Nar", narrative.StreamingText);
    }

    [Theory]
    [InlineData(null, 30)]
    [InlineData("", 30)]
    [InlineData("0", 30)]
    [InlineData("60001", 30)]
    [InlineData("not-a-number", 30)]
    [InlineData("5000", 5000)]
    public void TypewriterTickInterval_UiTestOverrideIsBounded(
        string? value,
        int expectedMilliseconds)
    {
        Assert.Equal(
            TimeSpan.FromMilliseconds(expectedMilliseconds),
            AgentViewModel.ResolveTypewriterTickInterval(value));
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_Cancel_FlushesStreamingText()
    {
        var scheduler = new ManualTypewriterScheduler();
        var agent = new StreamingAgent("Summary line.", narrative: null);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "audit",
            TypewriterScheduler = scheduler
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var prose = Assert.Single(vm.Messages, m => m.IsProse);
        Assert.True(prose.IsStreaming);

        scheduler.Tick();
        Assert.Equal("Sum", prose.StreamingText);

        vm.CancelQueryCommand.Execute(null);
        FlushDispatcher();

        Assert.Equal("Summary line.", prose.Text);
        Assert.False(prose.IsStreaming);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_NewQuery_CancelsPreviousStreamer()
    {
        var scheduler = new ManualTypewriterScheduler();
        var agent = new StreamingAgent("First reply.", narrative: null);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "first",
            TypewriterScheduler = scheduler
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var first = Assert.Single(vm.Messages, m => m.IsProse);
        scheduler.Tick();
        Assert.Equal("Fir", first.StreamingText);

        vm.UserQuery = "second";
        agent.NextSummary = "Second reply.";
        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        Assert.Equal("First reply.", first.Text);
        Assert.False(first.IsStreaming);

        var second = vm.Messages.Last(m => m.IsProse);
        Assert.True(second.IsStreaming);
        Assert.Equal("Second reply.", second.StreamingFinalText);
    }

    [AvaloniaFact]
    public async Task FullAuditCommand_WhileStreaming_FlushesPreviousTextBeforeAuditCompletes()
    {
        var scheduler = new ManualTypewriterScheduler();
        var agent = new StreamingAgent("First reply.", narrative: null);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "first",
            TypewriterScheduler = scheduler
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var first = Assert.Single(vm.Messages, m => m.IsProse);
        scheduler.Tick();
        Assert.Equal("Fir", first.StreamingText);

        var pendingAudit = new TaskCompletionSource<AgentResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        agent.NextRunAuditResult = pendingAudit;

        vm.FullAuditCommand.Execute(null);
        FlushDispatcher();

        Assert.Equal("First reply.", first.Text);
        Assert.False(first.IsStreaming);
        Assert.Equal("Run a full audit", vm.Messages.Last(m => m.IsUser).Text);

        pendingAudit.SetResult(new AgentResult { Intent = AgentIntent.FullAudit, Summary = "Second reply." });
        await vm.FullAuditCommand.ExecutionTask;
        FlushDispatcher();

        var second = vm.Messages.Last(m => m.IsProse);
        Assert.True(second.IsStreaming);
        Assert.Equal("Second reply.", second.StreamingFinalText);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_SlashQuickAudit_WhileStreaming_FlushesPreviousTextBeforeAuditCompletes()
    {
        var scheduler = new ManualTypewriterScheduler();
        var agent = new StreamingAgent("First reply.", narrative: null);
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "first",
            TypewriterScheduler = scheduler
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var first = Assert.Single(vm.Messages, m => m.IsProse);
        scheduler.Tick();
        Assert.Equal("Fir", first.StreamingText);

        var pendingAudit = new TaskCompletionSource<AgentResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        agent.NextRunAuditResult = pendingAudit;

        vm.UserQuery = "/fullaudit";
        vm.SendQueryCommand.Execute(null);
        FlushDispatcher();

        Assert.Equal("First reply.", first.Text);
        Assert.False(first.IsStreaming);
        Assert.Equal("Run a full audit", vm.Messages.Last(m => m.IsUser).Text);

        pendingAudit.SetResult(new AgentResult { Intent = AgentIntent.FullAudit, Summary = "Second reply." });
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var second = vm.Messages.Last(m => m.IsProse);
        Assert.True(second.IsStreaming);
        Assert.Equal("Second reply.", second.StreamingFinalText);
    }

    private sealed class ManualTypewriterScheduler : ITypewriterScheduler
    {
        private Action? _tick;

        public IDisposable Start(TimeSpan interval, Action tick)
        {
            _tick = tick;
            return new ActionDisposable(() => _tick = null);
        }

        public void Tick() => _tick?.Invoke();
    }

    private sealed class StreamingAgent : IAgent
    {
        public StreamingAgent(string summary, string? narrative)
        {
            NextSummary = summary;
            NextNarrative = narrative;
        }

        public string NextSummary { get; set; }
        public string? NextNarrative { get; set; }
        public TaskCompletionSource<AgentResult>? NextRunAuditResult { get; set; }

        public Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult());

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            NextRunAuditResult?.Task ?? Task.FromResult(CreateResult());

        public Task<AgentResult> ExplainFindingAsync(Finding finding, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult());

        public Task<AgentResult> SetBaselineAsync(string name, string? description, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.SetBaseline, Summary = "baseline set" });

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.CheckDrift, Summary = "drift checked" });

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ShowBaseline, Summary = "baseline shown" });

        public Task<AgentResult> StartRemediationAsync(string findingReference, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.StartRemediation, Summary = "remediation started" });

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.VerifyRemediation, Summary = "remediation verified" });

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.StartRemediation, Summary = "exported" });

        public Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ListRemediationSessions, Summary = "sessions" });

        public Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ResumeRemediation, Summary = "loaded" });

        public Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ListRemediationSessions, Summary = "deleted" });

        public Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.AddSessionNote, Summary = "note added" });

        public Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.AddStepNote, Summary = "step note added" });

        private AgentResult CreateResult() =>
            new()
            {
                Intent = AgentIntent.FullAudit,
                Summary = NextSummary,
                Narrative = string.IsNullOrWhiteSpace(NextNarrative) ? null : new Narrative { Summary = NextNarrative }
            };
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_ProseReveal_HidesQueuedUntilItsTurn()
    {
        var scheduler = new ManualTypewriterScheduler();
        var agent = new StreamingAgent("Summary line.", "Narrative body.");
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "audit",
            TypewriterScheduler = scheduler
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var prose = vm.Messages.Where(m => m.IsProse).ToList();
        var summary = prose[0];
        var narrative = prose[1];

        // Summary is the active streamer; narrative is queued and therefore hidden.
        Assert.True(summary.IsStreaming);
        Assert.False(summary.IsStreamingPending);
        Assert.False(narrative.IsStreaming);
        Assert.True(narrative.IsStreamingPending);

        // Finishing the summary must promote the narrative to active (no full-text flash first).
        while (summary.IsStreaming)
            scheduler.Tick();
        FlushDispatcher();

        Assert.False(summary.IsStreaming);
        Assert.True(narrative.IsStreaming);
        Assert.False(narrative.IsStreamingPending);

        // Finish the narrative; everything is revealed with nothing left streaming or pending.
        while (narrative.IsStreaming)
            scheduler.Tick();
        FlushDispatcher();

        Assert.False(summary.IsStreaming);
        Assert.False(summary.IsStreamingPending);
        Assert.False(narrative.IsStreaming);
        Assert.False(narrative.IsStreamingPending);
        Assert.Equal("Summary line.", summary.Text);
        Assert.Equal("Narrative body.", narrative.Text);
    }

    [AvaloniaFact]
    public async Task SendQueryCommand_Cancel_MidStream_RevealsQueueWithoutAdvancing()
    {
        var scheduler = new ManualTypewriterScheduler();
        var agent = new StreamingAgent("Summary line.", "Narrative body.");
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "audit",
            TypewriterScheduler = scheduler
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var prose = vm.Messages.Where(m => m.IsProse).ToList();
        var summary = prose[0];
        var narrative = prose[1];
        scheduler.Tick(); // partial summary
        Assert.True(summary.IsStreaming);

        vm.CancelQueryCommand.Execute(null);
        FlushDispatcher();

        // Cancel stops the typewriter and reveals the whole result; it must not start the next bubble.
        Assert.False(summary.IsStreaming);
        Assert.Equal("Summary line.", summary.Text);
        Assert.False(narrative.IsStreaming);
        Assert.False(narrative.IsStreamingPending);
    }

    [AvaloniaFact]
    public async Task Dispose_WhileStreaming_FlushesAndRevealsQueue()
    {
        var scheduler = new ManualTypewriterScheduler();
        var agent = new StreamingAgent("Summary line.", "Narrative body.");
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()))
        {
            UserQuery = "audit",
            TypewriterScheduler = scheduler
        };

        vm.SendQueryCommand.Execute(null);
        await vm.SendQueryCommand.ExecutionTask;
        FlushDispatcher();

        var prose = vm.Messages.Where(m => m.IsProse).ToList();
        scheduler.Tick(); // start the summary

        vm.Dispose(); // must flush and reveal, without advancing or leaking a running timer

        Assert.False(prose[0].IsStreaming);
        Assert.False(prose[0].IsStreamingPending);
        Assert.False(prose[1].IsStreaming);
        Assert.False(prose[1].IsStreamingPending);
    }



    private static string ReadAgentViewXaml()
    {
        var currentDirectoryPath = Path.Combine(Directory.GetCurrentDirectory(), "VulcansTrace.Linux.Avalonia", "Views", "AgentView.axaml");
        if (File.Exists(currentDirectoryPath))
            return File.ReadAllText(currentDirectoryPath);

        var baseDirectoryPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "VulcansTrace.Linux.Avalonia",
            "Views",
            "AgentView.axaml"));
        return File.ReadAllText(baseDirectoryPath);
    }

    private static Finding CreateFinding() => new()
    {
        Category = "Firewall",
        Severity = Severity.High,
        SourceHost = "localhost",
        Target = "22/tcp",
        TimeRangeStart = DateTime.UnixEpoch,
        TimeRangeEnd = DateTime.UnixEpoch,
        ShortDescription = "SSH exposed",
        Details = "detail",
        RuleId = "FW-001"
    };

    private class StubAgent : IAgent
    {
        public virtual Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = "stub"
            });

        public virtual Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = intent,
                Summary = "stub"
            });

        public virtual Task<AgentResult> ExplainFindingAsync(Finding finding, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "stub",
                AgentFindings = new[] { finding }
            });

        public virtual Task<AgentResult> SetBaselineAsync(string name, string? description, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "stub"
            });

        public virtual Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "stub"
            });

        public virtual Task<AgentResult> GetBaselineAsync(AgentIntent intent, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "stub"
            });

        public virtual Task<AgentResult> StartRemediationAsync(string findingReference, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "stub"
            });

        public virtual Task<AgentResult> VerifyRemediationAsync(string sessionId, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = "stub"
            });

        public virtual Task<AgentResult> VerifyFindingAsync(string ruleId, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = $"stub verify {ruleId}",
                AgentFindings = Array.Empty<Finding>()
            });

        public virtual Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "stub"
            });

        public virtual Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "stub"
            });

        public virtual Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ResumeRemediation,
                Summary = "stub"
            });

        public virtual Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "stub"
            });

        public virtual Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.AddSessionNote,
                Summary = "stub"
            });

        public virtual Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = "stub"
            });
    }

    private sealed class SessionResultAgent : StubAgent
    {
        private readonly Finding _finding = CreateFinding();
        private readonly RemediationSession _session;

        public SessionResultAgent()
        {
            _session = new RemediationSession
            {
                SessionId = "abc12345",
                SourceFindings = new[] { _finding },
                RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
                StepStates = new Dictionary<string, RemediationStepState>(),
                BlockedReasons = Array.Empty<string>(),
                Timeline = new[]
                {
                    new RemediationSessionEvent
                    {
                        TimestampUtc = DateTime.UtcNow,
                        Type = RemediationSessionEventType.Created,
                        Title = "Session started"
                    }
                }
            };
        }

        public int MarkExportedCallCount { get; private set; }

        public override Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "session created",
                AgentFindings = new[] { _finding },
                RemediationSession = _session
            });
        }

        public override Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct)
        {
            MarkExportedCallCount++;
            var exportedSession = _session with
            {
                Timeline = _session.Timeline.Append(new RemediationSessionEvent
                {
                    TimestampUtc = DateTime.UtcNow,
                    Type = RemediationSessionEventType.Exported,
                    Title = $"Session {sessionId} exported"
                }).ToArray()
            };

            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "session exported",
                AgentFindings = new[] { _finding },
                RemediationSession = exportedSession
            });
        }
    }

    private sealed class CapabilityReportAgent : IAgent
    {
        private readonly string _capabilityReport;

        public CapabilityReportAgent(string capabilityReport)
        {
            _capabilityReport = capabilityReport;
        }

        public Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.FullAudit));

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(intent));

        public Task<AgentResult> ExplainFindingAsync(Finding finding, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ExplainFinding));

        public Task<AgentResult> SetBaselineAsync(string name, string? description, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.SetBaseline));

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.CheckDrift));

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ShowBaseline));

        public Task<AgentResult> StartRemediationAsync(string findingReference, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.StartRemediation));

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.VerifyRemediation));

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.StartRemediation));

        public Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ListRemediationSessions));

        public Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ResumeRemediation));

        public Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ListRemediationSessions));

        public Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.AddSessionNote));

        public Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.AddStepNote));

        private AgentResult CreateResult(AgentIntent intent) => new()
        {
            Intent = intent,
            Summary = "stub",
            CapabilityReport = _capabilityReport
        };
    }

    /// <summary>Reports one progress phase and returns immediately.</summary>
    private sealed class ProgressReportingAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            progress?.Report(new AgentAuditProgress
            {
                Phase = "Scanning system",
                Detail = "Test scanner",
                StepIndex = 0,
                TotalSteps = 4
            });
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.FullAudit,
                Summary = "progress test",
                AgentFindings = Array.Empty<Finding>()
            });
        }
    }

    private sealed class TrackingAgent : IAgent
    {
        private readonly AgentIntent _auditIntent;

        public TrackingAgent(AgentIntent auditIntent)
        {
            _auditIntent = auditIntent;
        }

        public AgentIntent? LastDriftIntent { get; private set; }
        public AgentIntent? LastBaselineIntent { get; private set; }
        public AgentIntent? LastRunAuditIntent { get; private set; }

        public Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(_auditIntent));

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            LastRunAuditIntent = intent;
            return Task.FromResult(CreateResult(intent));
        }

        public Task<AgentResult> ExplainFindingAsync(Finding finding, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ExplainFinding));

        public Task<AgentResult> SetBaselineAsync(string name, string? description, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.SetBaseline));

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            LastDriftIntent = intent;
            return Task.FromResult(CreateResult(AgentIntent.CheckDrift));
        }

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            LastBaselineIntent = intent;
            return Task.FromResult(CreateResult(AgentIntent.ShowBaseline));
        }

        public Task<AgentResult> StartRemediationAsync(string findingReference, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.StartRemediation));

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.VerifyRemediation));

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.StartRemediation));

        public Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ListRemediationSessions));

        public Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ResumeRemediation));

        public Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.ListRemediationSessions));

        public Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.AddSessionNote));

        public Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(CreateResult(AgentIntent.AddStepNote));

        private static AgentResult CreateResult(AgentIntent intent) => new()
        {
            Intent = intent,
            Summary = "stub",
            UtcTimestamp = DateTime.UtcNow
        };
    }

    private sealed class ErrorAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            throw new InvalidOperationException("boom");
        }
    }

    private sealed class CancellableAgent : StubAgent
    {
        public override async Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return new AgentResult { Intent = AgentIntent.Help, Summary = "unreachable" };
        }
    }

    private sealed class SetBaselineErrorAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override Task<AgentResult> SetBaselineAsync(string name, string? description, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            throw new InvalidOperationException("baseline boom");
        }
    }

    private sealed class CancellableDriftAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override async Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return new AgentResult { Intent = AgentIntent.CheckDrift, Summary = "unreachable" };
        }
    }

    private sealed class NoisyBaselineAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override Task<AgentResult> GetBaselineAsync(AgentIntent intent, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "baseline summary",
                CapabilityReport = "hidden capability report",
                PassedCount = 4,
                Warnings = new[] { "hidden warning" }
            });
    }

    private sealed class ExplainFindingAgent : StubAgent
    {
        private readonly Finding _finding;

        public ExplainFindingAgent(Finding finding)
        {
            _finding = finding;
        }

        public override Task<AgentResult> ExplainFindingAsync(Finding finding, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "explanation summary",
                AgentFindings = new[] { _finding }
            });
    }

    private sealed class VerifyFindingAgent : StubAgent
    {
        private readonly string _ruleId;

        public VerifyFindingAgent(string ruleId)
        {
            _ruleId = ruleId;
        }

        public override Task<AgentResult> VerifyFindingAsync(string ruleId, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = $"verified {ruleId}",
                AgentFindings = Array.Empty<Finding>()
            });
    }

    private sealed class SetBaselineSuccessAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override Task<AgentResult> SetBaselineAsync(string name, string? description, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "baseline saved"
            });
    }

    [AvaloniaFact]
    public void Constructor_WithSessionStore_PopulatesSessions()
    {
        var store = new InMemorySessionStore();
        var session = new RemediationSession
        {
            SessionId = "abc12345",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>(),
            CreatedAtUtc = DateTime.UtcNow
        };
        store.Save(session);

        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), store);

        Assert.Single(vm.Sessions);
        Assert.Equal("abc12345", vm.Sessions[0].SessionId);
    }

    [AvaloniaFact]
    public void SetAgent_WithSessionStore_ReplacesSessionBrowserStore()
    {
        var firstStore = new InMemorySessionStore();
        firstStore.Save(new RemediationSession
        {
            SessionId = "first111",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>()
        });
        var secondStore = new InMemorySessionStore();
        secondStore.Save(new RemediationSession
        {
            SessionId = "second22",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>()
        });
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), firstStore);

        vm.SetAgent(new StubAgent(), secondStore);

        Assert.Single(vm.Sessions);
        Assert.Equal("second22", vm.Sessions[0].SessionId);
        Assert.Null(vm.SelectedSession);
    }

    [AvaloniaFact]
    public void SelectedSession_Set_RaisesCanExecuteChanged()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        var resumed = false;
        var deleted = false;
        vm.ResumeSessionCommand.CanExecuteChanged += (_, _) => resumed = true;
        vm.DeleteSessionCommand.CanExecuteChanged += (_, _) => deleted = true;

        vm.SelectedSession = new RemediationSession
        {
            SessionId = "test",
            SourceFindings = Array.Empty<Finding>(),
            RemediationPlan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() },
            StepStates = new Dictionary<string, RemediationStepState>()
        };

        Assert.True(resumed);
        Assert.True(deleted);
    }

    [AvaloniaFact]
    public void AddCountermeasureMessage_DuplicateSection_IsNotAddedTwice()
    {
        var section = new RemediationSection
        {
            RuleId = "COUNTERMEASURE",
            FindingSummary = "[Critical] Incident response",
            RiskNote = "Active defense countermeasures.",
            CountermeasureCommands = new[]
            {
                new CountermeasureCommand
                {
                    Command = "sudo iptables -A INPUT -s 10.0.0.5 -j DROP",
                    RollbackCommand = "sudo iptables -D INPUT -s 10.0.0.5 -j DROP",
                    Safety = CommandSafety.ConfigChange,
                    Analysis = new CommandAnalysis { RequiresSudo = true },
                    Type = CountermeasureType.IptablesDrop,
                    TargetHost = "10.0.0.5"
                }
            },
            HasExplicitRollbackGuidance = true
        };
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.AddCountermeasureMessage(section);
        vm.AddCountermeasureMessage(section);

        Assert.Single(vm.Messages, message => message.RemediationSection?.RuleId == "COUNTERMEASURE");
    }

    [AvaloniaFact]
    public void AddCountermeasureMessage_RespectsActiveSearch()
    {
        var section = new RemediationSection
        {
            RuleId = "COUNTERMEASURE",
            FindingSummary = "[Critical] Incident response",
            RiskNote = "Active defense countermeasures.",
            CountermeasureCommands = Array.Empty<CountermeasureCommand>()
        };
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        vm.Messages.Clear();
        vm.Messages.Add(new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true });
        vm.ChatSearchQuery = "firewall";

        vm.AddCountermeasureMessage(section);

        var countermeasureMessage = Assert.Single(vm.Messages, message => message.RemediationSection?.RuleId == "COUNTERMEASURE");
        Assert.False(countermeasureMessage.IsVisible);
    }

    private sealed class DriftResultAgent : StubAgent
    {
        public override Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SshCheck,
                Summary = "audit",
                UtcTimestamp = DateTime.UtcNow
            });

        public override Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "drift summary",
                CapabilityReport = "hidden capability report",
                PassedCount = 3
            });
    }

    [AvaloniaFact]
    public async Task DeployCountermeasuresCommand_DryRun_PostsSummaryMessage()
    {
        var section = new RemediationSection
        {
            RuleId = "COUNTERMEASURE",
            FindingSummary = "[Critical] Incident response: Beaconing → LateralMovement → PrivilegeEscalation on 192.168.1.100",
            RiskNote = "Active defense countermeasures.",
            CountermeasureCommands = new[]
            {
                new CountermeasureCommand
                {
                    Command = "sudo iptables -A INPUT -s 10.0.0.5 -j DROP",
                    RollbackCommand = "sudo iptables -D INPUT -s 10.0.0.5 -j DROP",
                    Safety = CommandSafety.ConfigChange,
                    Analysis = new CommandAnalysis { RequiresSudo = true },
                    Type = CountermeasureType.IptablesDrop,
                    TargetHost = "10.0.0.5"
                }
            },
            ApplyCommands = new[]
            {
                new RemediationCommand { Command = "sudo iptables -A INPUT -s 10.0.0.5 -j DROP", Safety = CommandSafety.ConfigChange, Analysis = new CommandAnalysis { RequiresSudo = true } }
            },
            RollbackCommands = new[]
            {
                new RemediationCommand { Command = "sudo iptables -D INPUT -s 10.0.0.5 -j DROP", Safety = CommandSafety.ConfigChange, Analysis = new CommandAnalysis { RequiresSudo = true } }
            },
            HasExplicitRollbackGuidance = true
        };

        var fakeRunner = new FakeProcessRunner();
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(fakeRunner));
        vm.DeployCountermeasuresCommand.Execute(section);
        await vm.DeployCountermeasuresCommand.ExecutionTask!;

        var texts = vm.Messages.Select(m => m.Text).ToList();
        Assert.Contains(texts, t => t.Contains("DRY-RUN"));
        Assert.Contains(texts, t => t.Contains("Dialog service unavailable"));
        // Dry-run does not invoke the process runner (commands are skipped internally)
        Assert.False(fakeRunner.WasCalled);
    }

    [AvaloniaFact]
    public async Task DeployCountermeasuresCommand_LiveRun_WithConfirmation_Executes()
    {
        var section = new RemediationSection
        {
            RuleId = "COUNTERMEASURE",
            FindingSummary = "[Critical] Incident response",
            RiskNote = "Active defense countermeasures.",
            CountermeasureCommands = new[]
            {
                new CountermeasureCommand
                {
                    Command = "echo test",
                    RollbackCommand = "echo rollback",
                    Safety = CommandSafety.ReadOnly,
                    Analysis = new CommandAnalysis(),
                    Type = CountermeasureType.IptablesDrop,
                    TargetHost = "10.0.0.5"
                }
            },
            ApplyCommands = new[]
            {
                new RemediationCommand { Command = "echo test", Safety = CommandSafety.ReadOnly, Analysis = new CommandAnalysis() }
            },
            RollbackCommands = new[]
            {
                new RemediationCommand { Command = "echo rollback", Safety = CommandSafety.ReadOnly, Analysis = new CommandAnalysis() }
            },
            HasExplicitRollbackGuidance = true
        };

        var fakeRunner = new FakeProcessRunner();
        var executor = new RemediationExecutor(fakeRunner);
        var dialog = new FakeDialogService(confirmIndex: 0); // "Deploy Live"
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, executor, dialogService: dialog);
        vm.DeployCountermeasuresCommand.Execute(section);
        await vm.DeployCountermeasuresCommand.ExecutionTask!;

        Assert.Contains(vm.Messages, m => m.Text.Contains("DRY-RUN"));
        Assert.Contains(vm.Messages, m => m.Text.Contains("LIVE"));
        // Verify the fake runner was actually invoked for both dry-run AND live execution
        Assert.True(fakeRunner.WasCalled);
    }

    [AvaloniaFact]
    public void BatchAutoFixCommand_NoFindings_IsDisabled()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        Assert.False(vm.CanBatchAutoFix);
        Assert.False(vm.BatchAutoFixCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task BatchAutoFixCommand_AfterAuditWithFindings_RunsDryRun()
    {
        var agent = new FindingAuditAgent(CreateFinding());
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));

        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask!;

        Assert.True(vm.CanBatchAutoFix);

        vm.BatchAutoFixCommand.Execute(null);
        await vm.BatchAutoFixCommand.ExecutionTask!;

        Assert.Contains(vm.Messages, m => m.Text.Contains("batch auto-fix dry-run"));
        Assert.Contains(vm.Messages, m => m.Text.Contains("[DRY-RUN]"));
        Assert.Contains(vm.Messages, m => m.Text.Contains("Dialog service unavailable"));
    }

    [AvaloniaFact]
    public async Task BatchAutoFixCommand_LiveRun_WithConfirmation_Executes()
    {
        var agent = new FindingAuditAgent(CreateFindingWithFix());
        var fakeRunner = new FakeProcessRunner();
        var dialog = new FakeDialogService(confirmIndex: 0); // "Deploy Live"
        var vm = new AgentViewModel(agent, new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(fakeRunner), dialogService: dialog);

        vm.FullAuditCommand.Execute(null);
        await vm.FullAuditCommand.ExecutionTask!;

        Assert.True(vm.CanBatchAutoFix);

        vm.BatchAutoFixCommand.Execute(null);
        await vm.BatchAutoFixCommand.ExecutionTask!;

        Assert.Contains(vm.Messages, m => m.Text.Contains("[DRY-RUN]"));
        Assert.Contains(vm.Messages, m => m.Text.Contains("[LIVE]"));
        Assert.True(fakeRunner.WasCalled);
    }

    private static Finding CreateFindingWithFix() => new()
    {
        Category = "Firewall",
        Severity = Severity.High,
        SourceHost = "localhost",
        Target = "22/tcp",
        TimeRangeStart = DateTime.UnixEpoch,
        TimeRangeEnd = DateTime.UnixEpoch,
        ShortDescription = "SSH exposed",
        Details = "**Suggested next action:**\n1. Inspect exposure with `cat /etc/passwd`",
        RuleId = "FW-001"
    };

    private sealed class FindingAuditAgent : StubAgent
    {
        private readonly Finding _finding;

        public FindingAuditAgent(Finding finding)
        {
            _finding = finding;
        }

        public override Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult
            {
                Intent = intent,
                Summary = "audit",
                AgentFindings = new[] { _finding }
            });
    }

    private sealed class FakeDialogService : IDialogService
    {
        private readonly int? _confirmIndex;
        private readonly string? _openFileResult;

        public FakeDialogService(int? confirmIndex = null, string? openFileResult = null)
        {
            _confirmIndex = confirmIndex;
            _openFileResult = openFileResult;
        }

        public void ShowMessage(string message, string title) { }
        public void ShowError(string message, string title) { }
        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName) => Task.FromResult<string?>(null);
        public Task<string?> ShowOpenFileDialogAsync(string title, string filter) => Task.FromResult(_openFileResult);
        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "") => Task.FromResult<string?>(null);
        public Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel) => Task.FromResult<bool?>(null);
        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0) => Task.FromResult<int?>(_confirmIndex);
    }

    private sealed class SuggestionRoutingAgent : IAgent
    {
        public AgentIntent? LastRunAuditIntent { get; private set; }
        public string? LastAskQuery { get; private set; }
        public Task LastCommandTask { get; private set; } = Task.CompletedTask;

        public Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            LastAskQuery = query;
            LastCommandTask = Task.CompletedTask;
            var result = new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "Explanation",
                AgentFindings = new[] { CreateFinding() },
                Suggestions = new[]
                {
                    new SuggestedFollowUp { Label = "Fix it", Query = "fix TEST-001", Intent = AgentIntent.FixFinding }
                }
            };
            return Task.FromResult(result);
        }

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            LastRunAuditIntent = intent;
            LastCommandTask = Task.CompletedTask;
            var result = new AgentResult
            {
                Intent = intent,
                Summary = "Audit result",
                AgentFindings = new[] { CreateFinding() },
                Suggestions = new[]
                {
                    new SuggestedFollowUp { Label = "Show all findings", Query = "show all findings", Intent = intent }
                }
            };
            return Task.FromResult(result);
        }

        public Task<AgentResult> ExplainFindingAsync(Finding finding, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ExplainFinding, Summary = "stub" });

        public Task<AgentResult> SetBaselineAsync(string name, string? description, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.SetBaseline, Summary = "stub" });

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.CheckDrift, Summary = "stub" });

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ShowBaseline, Summary = "stub" });

        public Task<AgentResult> StartRemediationAsync(string findingReference, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.StartRemediation, Summary = "stub" });

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, IProgress<AgentAuditProgress>? progress, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.VerifyRemediation, Summary = "stub" });

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.StartRemediation, Summary = "stub" });

        public Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ListRemediationSessions, Summary = "stub" });

        public Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ResumeRemediation, Summary = "stub" });

        public Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.ListRemediationSessions, Summary = "stub" });

        public Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.AddSessionNote, Summary = "stub" });

        public Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct) =>
            Task.FromResult(new AgentResult { Intent = AgentIntent.AddStepNote, Summary = "stub" });
    }

    private sealed class FakeProcessRunner : IProcessRunner
    {
        public bool WasCalled { get; private set; }
        public List<string> ExecutedCommands { get; } = new();

        public Task<ProcessResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct = default)
        {
            WasCalled = true;
            ExecutedCommands.Add(command);
            return Task.FromResult(new ProcessResult
            {
                Success = true,
                ExitCode = 0,
                StdOut = "",
                StdErr = ""
            });
        }
    }

    [AvaloniaFact]
    public void Constructor_WithPinnedMessageStore_LoadsPinnedMessages()
    {
        var store = new InMemoryPinnedMessageStore();
        var message = new AgentMessageViewModel
        {
            Text = "saved message",
            Timestamp = new DateTime(2026, 7, 2, 14, 30, 0, DateTimeKind.Utc)
        };
        store.Pin(message.ToPinnedMessage());

        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: store);

        Assert.Single(vm.PinnedMessages);
        Assert.Equal("saved message", vm.PinnedMessages[0].Text);
        Assert.True(vm.PinnedMessages[0].IsPinned);
        Assert.Equal(1, vm.PinnedMessageCount);
        Assert.True(vm.HasPinnedMessages);
    }

    [AvaloniaFact]
    public void LatestPinnableMessage_TracksNewestCompletedAgentMessage()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: new InMemoryPinnedMessageStore());
        var welcome = Assert.Single(vm.Messages);
        var user = new AgentMessageViewModel { Text = "user question", IsUser = true };
        var streaming = new AgentMessageViewModel { Text = "pending reply", IsStreaming = true };
        var completed = new AgentMessageViewModel { Text = "completed reply" };

        vm.Messages.Add(user);
        vm.Messages.Add(streaming);
        vm.Messages.Add(completed);

        Assert.True(vm.HasLatestPinnableMessage);
        Assert.Same(completed, vm.LatestPinnableMessage);

        completed.IsStreaming = true;
        Assert.Same(welcome, vm.LatestPinnableMessage);

        streaming.IsStreaming = false;
        Assert.Same(streaming, vm.LatestPinnableMessage);
    }

    [AvaloniaFact]
    public async Task TogglePinMessageCommand_PinsAndUnpinsMessage()
    {
        var store = new InMemoryPinnedMessageStore();
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: store);
        var message = vm.Messages[0]; // welcome message

        Assert.True(vm.TogglePinMessageCommand.CanExecute(message));
        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;

        Assert.True(message.IsPinned);
        Assert.Single(vm.PinnedMessages);
        Assert.True(store.IsPinned(message.MessageId));

        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;

        Assert.False(message.IsPinned);
        Assert.Empty(vm.PinnedMessages);
        Assert.False(store.IsPinned(message.MessageId));
    }

    [AvaloniaFact]
    public async Task TogglePinMessageCommand_DoesNothingWhenStoreUnavailable()
    {
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()));
        var message = vm.Messages[0];

        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;

        Assert.False(message.IsPinned);
        Assert.Empty(vm.PinnedMessages);
    }

    [AvaloniaFact]
    public async Task PinMessage_WithStoreWarning_SurfacesStatus()
    {
        var store = new WarningPinnedMessageStore("Could not save pinned messages to disk: boom. Pins will last only for this session.");
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: store);
        var message = vm.Messages[0];

        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;

        Assert.True(message.IsPinned);
        Assert.True(vm.HasPinMessageStatusMessage);
        Assert.Contains("Pins will last only for this session", vm.PinMessageStatusMessage);
    }

    [AvaloniaFact]
    public async Task PinMessage_WhenStoreRejectsPin_DoesNotMarkPinned()
    {
        // A persistent store can reject a pin (e.g. validation failure on oversized text) without
        // throwing. The VM must treat the store as the source of truth: no pin bubble, no clone,
        // no count bump — while still surfacing the persistence warning.
        var store = new RejectingPinnedMessageStore();
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: store);
        var message = vm.Messages[0];

        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;

        Assert.False(message.IsPinned);
        Assert.Empty(vm.PinnedMessages);
        Assert.Equal(0, vm.PinnedMessageCount);
        Assert.True(vm.HasPinMessageStatusMessage);
    }

    [AvaloniaFact]
    public async Task UnpinFromPinnedPanelClone_AlsoUnpinsTranscriptMessage()
    {
        var store = new InMemoryPinnedMessageStore();
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: store);
        var message = vm.Messages[0];

        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;
        Assert.True(message.IsPinned);

        // Unpin via the clone rendered in the Pinned-messages panel, not the transcript bubble,
        // and verify the transcript twin is kept in sync.
        var clone = Assert.Single(vm.PinnedMessages);
        var unpinCommand = clone.TogglePinCommand;
        Assert.NotNull(unpinCommand);
        unpinCommand.Execute(clone);
        await ((AsyncRelayCommand<AgentMessageViewModel>)unpinCommand).ExecutionTask;

        Assert.False(message.IsPinned);
        Assert.Empty(vm.PinnedMessages);
        Assert.False(store.IsPinned(message.MessageId));
    }

    [AvaloniaFact]
    public async Task PinMessage_WhenStoreThrows_ReconcilesToStoreState()
    {
        // If the store throws, the VM must not crash and must not optimistically show pinned.
        // SafeIsPinned falls back to false when even the read path throws.
        var store = new ThrowingPinnedMessageStore();
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: store);
        var message = vm.Messages[0];

        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;

        Assert.False(message.IsPinned);
        Assert.Empty(vm.PinnedMessages);
        Assert.Equal(0, vm.PinnedMessageCount);
        Assert.Contains("Could not pin message", vm.PinMessageStatusMessage);
    }

    [AvaloniaFact]
    public async Task PinMessage_CommittedButNotPersisted_SurfacesWarningAndKeepsPin()
    {
        // JsonFilePinnedMessageStore can successfully commit to memory but fail the file write.
        // The pin is real for this session, so the UI should show it pinned and surface the warning.
        var store = new CommittedButNotPersistedStore();
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: store);
        var message = vm.Messages[0];

        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;

        Assert.True(message.IsPinned);
        Assert.Single(vm.PinnedMessages);
        Assert.Equal(1, vm.PinnedMessageCount);
        Assert.Contains("Pins will last only for this session", vm.PinMessageStatusMessage);
    }

    [AvaloniaFact]
    public async Task UnpinMessage_WhenStoreThrows_ReconcilesToStoreState()
    {
        // Start with a healthy pinned message, then swap in a throwing store for unpin.
        var healthyStore = new InMemoryPinnedMessageStore();
        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: healthyStore);
        var message = vm.Messages[0];

        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;
        Assert.True(message.IsPinned);

        var throwingStore = new ThrowingPinnedMessageStore();
        // Use reflection to swap the store so we can test the unpin throw path without exposing it publicly.
        var field = typeof(AgentViewModel).GetField("_pinnedMessageStore", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        field?.SetValue(vm, throwingStore);

        vm.TogglePinMessageCommand.Execute(message);
        await vm.TogglePinMessageCommand.ExecutionTask;

        // IsPinned read throws, so SafeIsPinned returns false; UI should remove the pin and clone.
        Assert.False(message.IsPinned);
        Assert.Empty(vm.PinnedMessages);
        Assert.Equal(0, vm.PinnedMessageCount);
        Assert.Contains("Could not unpin message", vm.PinMessageStatusMessage);
    }

    [AvaloniaFact]
    public async Task LoadedPinnedMessage_PreservesOrFallsBackSeverity()
    {
        var store = new InMemoryPinnedMessageStore();
        store.Pin(new PinnedMessage
        {
            MessageId = "valid-sev",
            Text = "msg",
            Severity = "Critical",
            TimestampUtc = DateTime.UtcNow,
            PinnedAtUtc = DateTime.UtcNow
        });
        store.Pin(new PinnedMessage
        {
            MessageId = "bad-sev",
            Text = "msg",
            Severity = "not-a-real-severity",
            TimestampUtc = DateTime.UtcNow,
            PinnedAtUtc = DateTime.UtcNow
        });

        var vm = new AgentViewModel(new StubAgent(), new InMemoryAuditHistoryStore(), PlanBuilder, new RemediationExecutor(new ProcessRunner()), pinnedMessageStore: store);

        var byId = vm.PinnedMessages.ToDictionary(m => m.MessageId);
        Assert.Equal(Severity.Critical, byId["valid-sev"].Severity);
        Assert.Equal(Severity.Info, byId["bad-sev"].Severity);
    }

    private sealed class WarningPinnedMessageStore : IPinnedMessageStore
    {
        private readonly Dictionary<string, PinnedMessage> _entries = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _warning;

        public WarningPinnedMessageStore(string warning)
        {
            _warning = warning;
        }

        public string? PersistenceWarning { get; private set; }

        public void Pin(PinnedMessage message)
        {
            _entries[message.MessageId] = message;
            PersistenceWarning = _warning;
        }

        public void Unpin(string messageId)
        {
            _entries.Remove(messageId);
            PersistenceWarning = _warning;
        }

        public bool IsPinned(string messageId) => _entries.ContainsKey(messageId);

        public IReadOnlyList<PinnedMessage> GetAll() => _entries.Values.ToList();
    }

    private sealed class WarningThreatIntelStore : IThreatIntelStore
    {
        private readonly InMemoryThreatIntelStore _inner = new();
        private readonly string _warning;

        public WarningThreatIntelStore(string warning)
        {
            _warning = warning;
        }

        public string? PersistenceWarning { get; private set; }

        public int Count => _inner.Count;

        public void Import(IEnumerable<IocEntry> entries)
        {
            _inner.Import(entries);
            PersistenceWarning = _warning;
        }

        public void Clear()
        {
            _inner.Clear();
            PersistenceWarning = _warning;
        }

        public bool Remove(string storageKey)
        {
            var removed = _inner.Remove(storageKey);
            if (removed)
                PersistenceWarning = _warning;
            return removed;
        }

        public int CountByType(IocType type) => _inner.CountByType(type);

        public IReadOnlyList<IocEntry> GetByType(IocType type) => _inner.GetByType(type);

        public IReadOnlyList<IocEntry> GetAll() => _inner.GetAll();
    }

    /// <summary>
    /// A store that simulates a persistent store rejecting pins (e.g. a validation failure) without
    /// throwing: entries are never retained (so IsPinned always reports false) and a persistence
    /// warning is recorded only after a Pin attempt, mirroring JsonFilePinnedMessageStore's
    /// CommitCandidate failure path.
    /// </summary>
    private sealed class RejectingPinnedMessageStore : IPinnedMessageStore
    {
        public string? PersistenceWarning { get; private set; }

        public void Pin(PinnedMessage message)
        {
            PersistenceWarning = "Could not save pinned messages to disk: validation failed. Invalid pins were not saved.";
        }

        public void Unpin(string messageId)
        {
        }

        public bool IsPinned(string messageId) => false;

        public IReadOnlyList<PinnedMessage> GetAll() => Array.Empty<PinnedMessage>();
    }

    /// <summary>
    /// A store that keeps the pin in memory but reports a persistence warning, matching
    /// JsonFilePinnedMessageStore's committed-but-not-saved-to-disk path.
    /// </summary>
    private sealed class CommittedButNotPersistedStore : IPinnedMessageStore
    {
        private readonly Dictionary<string, PinnedMessage> _entries = new(StringComparer.OrdinalIgnoreCase);

        public string? PersistenceWarning { get; private set; }

        public void Pin(PinnedMessage message)
        {
            _entries[message.MessageId] = message;
            PersistenceWarning = "Could not save pinned messages to disk: disk full. Pins will last only for this session.";
        }

        public void Unpin(string messageId)
        {
            _entries.Remove(messageId);
        }

        public bool IsPinned(string messageId) => _entries.ContainsKey(messageId);

        public IReadOnlyList<PinnedMessage> GetAll() => _entries.Values.ToList();
    }
}

public class ThrowingPinnedMessageStore : IPinnedMessageStore
{
    public string? PersistenceWarning { get; }

    public void Pin(PinnedMessage message) => throw new InvalidOperationException("Pin threw");

    public void Unpin(string messageId) => throw new InvalidOperationException("Unpin threw");

    public bool IsPinned(string messageId) => throw new InvalidOperationException("IsPinned threw");

    public IReadOnlyList<PinnedMessage> GetAll() => throw new InvalidOperationException("GetAll threw");
}
