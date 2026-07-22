using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Reflection;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Findings;
using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Rules;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Security;
using VulcansTrace.Linux.Core.ThreatIntel;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;
using VulcansTrace.Linux.Engine.Live;
using VulcansTrace.Linux.Evidence;
using VulcansTrace.Linux.Evidence.Formatters;
using Xunit;
using static VulcansTrace.Linux.Tests.Avalonia.TestDispatcher;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class MainViewModelTests : IAsyncLifetime
{
    private MainViewModel _vm = null!;

    public ValueTask InitializeAsync()
    {
        _vm = BuildViewModel();
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        _vm.Dispose();
        return ValueTask.CompletedTask;
    }

    [AvaloniaFact]
    public void Constructor_WiresFindingsCommands()
    {
        Assert.Same(_vm.InvestigateCommand, _vm.Findings.InvestigateCommand);
        Assert.Same(_vm.SuppressCommand, _vm.Findings.SuppressCommand);
        Assert.Same(_vm.ResolveCommand, _vm.Findings.ResolveCommand);
        Assert.Same(_vm.VerifyFindingCommand, _vm.Findings.VerifyFindingCommand);
    }

    [AvaloniaFact]
    public void AppStateJson_InitialSnapshot_ReflectsAgentHomeIdleState()
    {
        using var doc = JsonDocument.Parse(_vm.AppStateJson);
        var root = doc.RootElement;
        Assert.Equal("Agent", root.GetProperty("view").GetString());
        Assert.False(root.GetProperty("busy").GetBoolean());
        Assert.False(root.GetProperty("agent_busy").GetBoolean());
        Assert.Equal(_vm.SummaryText, root.GetProperty("summary").GetString());
        Assert.Equal(0, root.GetProperty("findings").GetInt32());
    }

    [AvaloniaFact]
    public void AppStateJson_UpdatesOnSummaryBusyAndNavigation()
    {
        _vm.SummaryText = "Analysis complete: 3 findings";
        _vm.IsBusy = true;
        _vm.KpiNavigateCommand.Execute("findings");

        using var doc = JsonDocument.Parse(_vm.AppStateJson);
        var root = doc.RootElement;
        Assert.Equal("Findings", root.GetProperty("view").GetString());
        Assert.True(root.GetProperty("busy").GetBoolean());
        Assert.Equal("Analysis complete: 3 findings", root.GetProperty("summary").GetString());
    }

    [AvaloniaFact]
    public void AppStateJson_TracksActiveLeafInsideNavigationHub()
    {
        _vm.SelectedNavigationItem = _vm.NavigationItems.First(item => item.Label == "Investigations");
        _vm.InvestigationsHub.SelectSection("Timeline");

        using var doc = JsonDocument.Parse(_vm.AppStateJson);
        Assert.Equal("Timeline", doc.RootElement.GetProperty("view").GetString());
        Assert.Equal("Investigations", _vm.SelectedNavigationItem?.Label);
    }

    [AvaloniaFact]
    public void IsAgentHomeVisible_TracksSelectedContent()
    {
        Assert.True(_vm.IsAgentHomeVisible);

        _vm.SelectedNavigationItem = _vm.NavigationItems.First(i => i.Label == "Investigations");
        Assert.False(_vm.IsAgentHomeVisible);

        _vm.SelectedNavigationItem = _vm.NavigationItems.First(i => i.Label == "Agent");
        Assert.True(_vm.IsAgentHomeVisible);
    }

    [AvaloniaFact]
    public void ShowStatusBar_RemainsAvailableForMainAnalysisOnAgentPage()
    {
        Assert.True(_vm.IsAgentHomeVisible);
        Assert.False(_vm.ShowStatusBar);

        _vm.IsBusy = true;

        Assert.True(_vm.ShowStatusBar);

        _vm.IsBusy = false;
        _vm.SelectedNavigationItem = _vm.NavigationItems.First(i => i.Label == "Investigations");
        Assert.True(_vm.ShowStatusBar);
    }

    [AvaloniaFact]
    public void NavigationItems_ExposeFiveDestinationsWithCapabilityHubs()
    {
        Assert.Equal(
            new[] { "Agent", "Investigations", "Policy & Intelligence", "Operations", "System" },
            _vm.NavigationItems.Select(item => item.Label).ToArray());
        Assert.Equal(
            new[] { "Findings", "Timeline", "Incident Story" },
            _vm.InvestigationsHub.Sections.Select(section => section.Label).ToArray());
        Assert.Contains(_vm.PolicyIntelligenceHub.Sections, section => section.Label == "Threat Intel");
        Assert.Contains(_vm.OperationsHub.Sections, section => section.Label == "Live Stream");
        Assert.Contains(_vm.SystemHub.Sections, section => section.Label == "Analyst Action Log");
        Assert.All(_vm.NavigationItems, item => Assert.False(string.IsNullOrWhiteSpace(item.AutomationId)));
    }

    [AvaloniaFact]
    public void KpiNavigate_Findings_ResetsSeverityFilterAndSelectsFindings()
    {
        _vm.Findings.SelectedSeverityFilter = _vm.Findings.SeverityFilters[1];

        _vm.KpiNavigateCommand.Execute("findings");

        Assert.Equal("Investigations", _vm.SelectedNavigationItem?.Label);
        Assert.Equal("Findings", _vm.InvestigationsHub.ActiveSectionLabel);
        Assert.Equal("All severities", _vm.Findings.SelectedSeverityFilter?.Display);
    }

    [AvaloniaFact]
    public void KpiNavigate_HighCritical_AppliesSeverityFilterAndSelectsFindings()
    {
        _vm.KpiNavigateCommand.Execute("high-critical");

        Assert.Equal("Investigations", _vm.SelectedNavigationItem?.Label);
        Assert.Equal("Findings", _vm.InvestigationsHub.ActiveSectionLabel);
        Assert.Equal("High & Critical only", _vm.Findings.SelectedSeverityFilter?.Display);
    }

    [AvaloniaFact]
    public void KpiNavigate_WarningsAndParseErrors_SelectFindingsView(){
        // The dedicated Warnings / Parse Errors nav items are gone (UI v2 Phase 2);
        // both routes land on Findings, where the banner cards live.
        _vm.KpiNavigateCommand.Execute("warnings");
        Assert.Equal("Investigations", _vm.SelectedNavigationItem?.Label);
        Assert.Equal("Findings", _vm.InvestigationsHub.ActiveSectionLabel);

        _vm.KpiNavigateCommand.Execute("parse-errors");
        Assert.Equal("Investigations", _vm.SelectedNavigationItem?.Label);
        Assert.Equal("Findings", _vm.InvestigationsHub.ActiveSectionLabel);

        Assert.DoesNotContain(_vm.NavigationItems, i => i.Label is "Warnings" or "Parse Errors");
    }

    [AvaloniaFact]
    public void KpiNavigate_Skipped_SelectsLogsView()
    {
        _vm.KpiNavigateCommand.Execute("skipped");

        Assert.Equal("System", _vm.SelectedNavigationItem?.Label);
        Assert.Equal("Logs", _vm.SystemHub.ActiveSectionLabel);
    }

    [AvaloniaFact]
    public void SelectedIntensity_UpdatesAgentInspectorProfile()
    {
        _vm.SelectedIntensity = _vm.Intensities[2];

        Assert.Equal("High - Deep Hunt / Forensics", _vm.Agent.ScanProfileName);
        Assert.Contains("all severities", _vm.Agent.ScanProfileDescription, StringComparison.OrdinalIgnoreCase);
    }

    [AvaloniaFact]
    public void AdvancedScanOptionsCommand_InvokesWiredAction()
    {
        var invoked = 0;
        _vm.ShowAdvancedScanOptionsAction = () => invoked++;

        _vm.AdvancedScanOptionsCommand.Execute(null);

        Assert.Equal(1, invoked);
    }

    [AvaloniaFact]
    public void KpiNavigate_UnknownKey_IsANoOp()
    {
        var before = _vm.SelectedNavigationItem;

        _vm.KpiNavigateCommand.Execute("nonsense");

        Assert.Same(before, _vm.SelectedNavigationItem);
    }

    [AvaloniaFact]
    public void AppStateJson_SurfacesLatestJournalEntryAsLastAction()
    {
        var store = new InMemoryAnalystActionStore();
        using var vm = BuildViewModel(analystActionStore: store);

        store.Append(new AnalystActionEntry
        {
            Id = "abc123",
            TimestampUtc = new DateTime(2026, 7, 18, 12, 0, 0, DateTimeKind.Utc),
            Actor = "avalonia",
            ActionType = AnalystActionType.EvidenceExported,
            Target = "/tmp/evidence.zip"
        });
        FlushDispatcher();

        using var doc = JsonDocument.Parse(vm.AppStateJson);
        var lastAction = doc.RootElement.GetProperty("last_action");
        Assert.Equal(AnalystActionType.EvidenceExported, lastAction.GetProperty("op").GetString());
        Assert.Equal("/tmp/evidence.zip", lastAction.GetProperty("target").GetString());
    }

    [AvaloniaFact]
    public void NavigateToThreatIntel_RefreshesAlreadySelectedThreatIntelTab()
    {
        var store = new InMemoryThreatIntelStore();
        using var vm = BuildViewModel(threatIntelStore: store);
        var threatIntelNav = vm.NavigationItems.First(i => i.Label == "Policy & Intelligence");

        vm.SelectedNavigationItem = threatIntelNav;
        vm.PolicyIntelligenceHub.SelectSection("Threat Intel");
        Assert.Empty(vm.ThreatIntel.FilteredEntries);

        store.Import(new[]
        {
            new IocEntry { Type = IocType.IPv4, Value = "10.0.0.99", Source = "STIX" }
        });
        vm.Agent.NavigateToThreatIntelAction?.Invoke();

        Assert.Same(threatIntelNav, vm.SelectedNavigationItem);
        var entry = Assert.Single(vm.ThreatIntel.FilteredEntries);
        Assert.Equal("10.0.0.99", entry.Value);
    }

    [AvaloniaFact]
    public void VerifyFindingCommand_CanExecute_WhenFindingHasRuleId()
    {
        var withRuleId = new FindingItemViewModel(new Finding { RuleId = "FW-001" });
        var withoutRuleId = new FindingItemViewModel(new Finding { RuleId = "" });

        Assert.True(_vm.VerifyFindingCommand.CanExecute(withRuleId));
        Assert.False(_vm.VerifyFindingCommand.CanExecute(withoutRuleId));
        Assert.False(_vm.VerifyFindingCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task VerifyFindingCommand_Executes_AndSwitchesToAgentTab()
    {
        var item = new FindingItemViewModel(new Finding { RuleId = "FW-001" });
        _vm.Findings.SelectedItem = item;

        _vm.VerifyFindingCommand.Execute(item);
        await _vm.VerifyFindingCommand.ExecutionTask;

        Assert.Equal("Agent", _vm.SelectedNavigationItem?.Label);
        Assert.Contains("FW-001", _vm.SummaryText);
    }

    [AvaloniaFact]
    public void InvestigateCommand_CanExecute_WhenParameterIsFindingItem()
    {
        var item = new FindingItemViewModel(new Finding { RuleId = "FW-001" });
        Assert.True(_vm.InvestigateCommand.CanExecute(item));
        Assert.False(_vm.InvestigateCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void SuppressCommand_CanExecute_WhenFindingHasRuleId()
    {
        var withRuleId = new FindingItemViewModel(new Finding { RuleId = "FW-001" });
        var withoutRuleId = new FindingItemViewModel(new Finding { RuleId = "" });

        Assert.True(_vm.SuppressCommand.CanExecute(withRuleId));
        Assert.False(_vm.SuppressCommand.CanExecute(withoutRuleId));
        Assert.False(_vm.SuppressCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void ResolveCommand_CanExecute_WhenFindingHasRuleId()
    {
        var withRuleId = new FindingItemViewModel(new Finding { RuleId = "FW-001" });
        var withoutRuleId = new FindingItemViewModel(new Finding { RuleId = "" });

        Assert.True(_vm.ResolveCommand.CanExecute(withRuleId));
        Assert.False(_vm.ResolveCommand.CanExecute(withoutRuleId));
        Assert.False(_vm.ResolveCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void CompareLogsCommand_CanExecute_WhenNotBusy()
    {
        Assert.False(_vm.IsBusy);
        Assert.True(_vm.CompareLogsCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void MainWindowXaml_CompareLogsButton_UsesCommandBinding()
    {
        var xaml = ReadMainWindowXaml();
        var button = ExtractSelfClosingElementWithAutomationId(xaml, "CompareLogsButton");

        // The Compare Logs button binds directly to the VM command (consistent
        // with every sibling toolbar button) rather than routing through a
        // code-behind Click handler. The custom AsyncRelayCommand raises
        // CanExecuteChanged on subscribe and on IsBusy transitions, so the
        // binding gates the button correctly without code-behind help.
        Assert.Contains("Command=\"{Binding CompareLogsCommand}\"", button);
        Assert.DoesNotContain("Click=\"CompareLogsButton_Click\"", button);
    }

    [AvaloniaFact]
    public async Task BuildLogDiffDemoResultAsync_ProducesDiffResult()
    {
        var diffResult = await _vm.BuildLogDiffDemoResultAsync();

        Assert.NotNull(diffResult);
        Assert.False(_vm.IsBusy);
        Assert.Contains("Demo baseline log", diffResult.BaselineLabel);
        Assert.Contains("Demo incident log", diffResult.IncidentLabel);
    }

    [AvaloniaFact]
    public void AnalyzeCommand_RequiresLogText()
    {
        Assert.False(_vm.AnalyzeCommand.CanExecute(null));

        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        Assert.True(_vm.AnalyzeCommand.CanExecute(null));
    }

    [AvaloniaFact]
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

    [AvaloniaFact]
    public async Task AnalyzeAsync_PostsSummaryCardToAgentThread()
    {
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        var card = _vm.Agent.Messages.OfType<AnalysisSummaryCardMessageViewModel>().Single();
        Assert.StartsWith("Analysis ·", card.HeaderLine);
        // Posting the card ends the welcome state: the overlay must not cover the thread,
        // and the stale welcome hint is removed from the transcript.
        Assert.False(_vm.Agent.HasOnlyWelcomeMessage);
        Assert.DoesNotContain(_vm.Agent.Messages, m => m.Text.StartsWith("I'm the VulcansTrace", StringComparison.Ordinal));
        // Hero compaction: the intro and advisor tip collapse once the thread exists.
        Assert.True(_vm.IsAgentThreadActive);
        Assert.False(_vm.ShowHeroIntro);
        Assert.False(_vm.ShowAdvisorTip);
        Assert.StartsWith("Done.", card.SummaryLine);
        Assert.Equal(4, card.Chips.Count);
        Assert.Equal("SummaryFindingsChip", card.Chips[0].AutomationId);
        Assert.Equal("SummaryHighCriticalChip", card.Chips[1].AutomationId);
        Assert.Equal("SummaryWarningsChip", card.Chips[2].AutomationId);
        Assert.Equal("SummaryParseErrorsChip", card.Chips[3].AutomationId);
        Assert.Same(_vm.KpiNavigateCommand, card.NavigateCommand);

        // Chip click-through mirrors the KPI strip: navigate to Findings.
        card.NavigateCommand!.Execute(card.Chips[0].CommandParameter);
        Assert.Equal("Investigations", _vm.SelectedNavigationItem?.Label);
        Assert.Equal("Findings", _vm.InvestigationsHub.ActiveSectionLabel);
    }

    [AvaloniaFact]
    public async Task AgentAuditCompleted_PostsSummaryCardToAgentThread()
    {
        _vm.Agent.FullAuditCommand.Execute(null);
        await _vm.Agent.FullAuditCommand.ExecutionTask!;

        var card = _vm.Agent.Messages.OfType<AnalysisSummaryCardMessageViewModel>().Single();
        Assert.Contains("Agent audit", card.HeaderLine);
        Assert.Equal(4, card.Chips.Count);
    }

    [AvaloniaFact]
    public async Task AnalyzeAsync_PostsFindingCardsAndMoreLink()
    {
        var now = DateTime.UtcNow;
        Finding MakeFinding(string ruleId, Severity severity) => new()
        {
            RuleId = ruleId,
            Category = "Firewall",
            Severity = severity,
            Confidence = DetectionConfidence.High,
            SourceHost = "localhost",
            Target = "target",
            TimeRangeStart = now,
            TimeRangeEnd = now,
            ShortDescription = $"{ruleId} description",
            Details = "details"
        };
        var detector = new StaticFindingsDetector(
            MakeFinding("FW-LOW", Severity.Low),
            MakeFinding("FW-CRIT", Severity.Critical),
            MakeFinding("FW-HIGH", Severity.High),
            MakeFinding("FW-MED", Severity.Medium));
        using var vm = BuildViewModel(baselineDetectors: [detector]);
        vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        vm.SelectedIntensity = vm.Intensities[2];

        vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(vm);

        // Cards mirror the top-3 by severity of whatever the Findings view holds,
        // one per rule, wired to the deep-link and suppress commands.
        var cards = vm.Agent.Messages.OfType<FindingCardMessageViewModel>().ToList();
        var expectedTop = vm.Findings.Items
            .OrderByDescending(i => i.Finding.Severity)
            .Take(3)
            .Select(i => i.RuleId)
            .ToList();
        Assert.Equal(expectedTop, cards.Select(c => c.Item.RuleId).ToList());
        Assert.All(cards, c => Assert.Same(vm.OpenFindingCommand, c.OpenCommand));
        Assert.All(cards, c => Assert.Same(vm.SuppressCommand, c.SuppressCommand));
        Assert.All(cards, c => Assert.Contains(vm.Findings.Items, i => ReferenceEquals(i, c.Item)));

        var link = vm.Agent.Messages.OfType<MoreFindingsLinkMessageViewModel>().Single();
        Assert.Equal(vm.Findings.Items.Count - 3, link.RemainingCount);
        Assert.Same(vm.KpiNavigateCommand, link.OpenCommand);

        // Deep link lands on the Findings view with the card's finding selected.
        cards[1].OpenCommand!.Execute(cards[1].Item);
        Assert.Equal("Investigations", vm.SelectedNavigationItem?.Label);
        Assert.Equal("Findings", vm.InvestigationsHub.ActiveSectionLabel);
        Assert.Same(cards[1].Item, vm.Findings.SelectedItem);
    }

    [AvaloniaFact]
    [Trait("Category", "Timing")]
    public async Task CancelCommand_CancelsActiveAnalysis()
    {
        _vm.Dispose();
        _vm = BuildViewModel(baselineDetectors: [new BlockingDetector()]);
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
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

    [AvaloniaFact]
    public void SelectedIntensity_ChangesAnalyzeCommandState()
    {
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

        _vm.SelectedIntensity = null;
        Assert.False(_vm.AnalyzeCommand.CanExecute(null));

        _vm.SelectedIntensity = _vm.Intensities[0];
        Assert.True(_vm.AnalyzeCommand.CanExecute(null));
    }

    [AvaloniaFact]
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

    [AvaloniaFact]
    public async Task ParseErrors_AffectSummaryText()
    {
        _vm.LogText = "not a valid log line at all\nmore garbage";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.Contains("parse error", _vm.SummaryText);
    }

    [AvaloniaFact]
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

    [AvaloniaFact]
    public async Task SkippedLines_SingularPluralization_WhenOneLineSkipped()
    {
        // Exactly one unparseable line: the summary must say "1 line skipped"
        // (singular), not the old always-plural "1 lines skipped".
        _vm.LogText = @"kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22
not a firewall line";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.NotNull(_vm.LastResult);
        Assert.Equal(1, _vm.LastResult.SkippedLineCount);
        Assert.Contains("1 line skipped", _vm.SummaryText);
        Assert.DoesNotContain("1 lines skipped", _vm.SummaryText);
    }

    [AvaloniaFact]
    public async Task LogTextChangedAfterAnalysis_InvalidatesExportContext()
    {
        _vm.LogText = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";
        _vm.SelectedIntensity = _vm.Intensities[2];

        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.NotNull(_vm.LastResult);
        Assert.True(_vm.Evidence.ExportEvidenceCommand.CanExecute(null));
        Assert.NotEmpty(_vm.Evidence.SigningKey);

        // Replacing the logs with new log content (UI v2 Phase 3: log-intent
        // text, ≥3 log-looking lines) marks the previous results stale.
        _vm.LogText = """
            kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.20 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=443
            kernel: Jan 19 10:15:33 server IN=eth0 SRC=192.168.1.20 DST=192.168.1.1 PROTO=TCP SPT=54322 DPT=443
            kernel: Jan 19 10:15:34 server IN=eth0 SRC=192.168.1.20 DST=192.168.1.1 PROTO=TCP SPT=54323 DPT=443
            """;

        Assert.Null(_vm.LastResult);
        Assert.False(_vm.Evidence.ExportEvidenceCommand.CanExecute(null));
        Assert.Empty(_vm.Evidence.SigningKey);
        Assert.Equal(0, _vm.Findings.FindingsCount);
        Assert.Contains("Log changed", _vm.SummaryText);
    }

    [AvaloniaFact]
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

    [AvaloniaFact]
    public void DemoCompleted_ReplacesStaleFindingsWithDemoFindings()
    {
        var oldFinding = CreateFinding(FindingCategories.PortScan, "10.0.0.1");
        var demoFinding = CreateFinding(FindingCategories.Flood, "10.99.99.100");
        _vm.Findings.AddFinding(oldFinding);

        var method = typeof(MainViewModel).GetMethod("OnDemoCompleted", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);
        method.Invoke(_vm, new object[]
        {
            new DemoCompletedEventArgs(
                "Demo: SSH Brute Force",
                new[] { demoFinding },
                true,
                TimeSpan.FromSeconds(60),
                DateTime.UtcNow.AddSeconds(-60),
                DateTime.UtcNow)
        });

        Assert.Single(_vm.Findings.Items);
        Assert.Equal(FindingCategories.Flood, _vm.Findings.Items[0].Finding.Category);
        Assert.DoesNotContain(_vm.Findings.Items, item => item.Finding.Category == FindingCategories.PortScan);
        Assert.True(_vm.Evidence.ExportEvidenceCommand.CanExecute(null));
    }

    // ── UI v2 Phase 3: unified hero input (Chat ↔ Analyze intent flip) ──────

    private const string HeroSyslogLine = "kernel: Jan 19 10:15:32 server IN=eth0 SRC=192.168.1.10 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22";

    [AvaloniaFact]
    public void HeroInput_ChatText_KeepsChatIntent()
    {
        _vm.LogText = "Why is port 443 flagged?";

        Assert.False(_vm.IsLogIntent);
        Assert.Equal("Chat", _vm.HeroPrimaryLabel);
        Assert.Equal("mdi-chat-processing-outline", _vm.HeroPrimaryIcon);
    }

    [AvaloniaFact]
    public void HeroInput_LogSnippet_FlipsToAnalyzeIntentAndBack()
    {
        _vm.LogText = string.Join('\n', HeroSyslogLine, HeroSyslogLine, HeroSyslogLine);

        Assert.True(_vm.IsLogIntent);
        Assert.Equal("Analyze", _vm.HeroPrimaryLabel);
        Assert.Equal("mdi-rocket-launch-outline", _vm.HeroPrimaryIcon);

        _vm.LogText = "just a question now";

        Assert.False(_vm.IsLogIntent);
        Assert.Equal("Chat", _vm.HeroPrimaryLabel);
    }

    [AvaloniaFact]
    public void HeroInput_MirrorsIntoAgentUserQuery()
    {
        _vm.LogText = "check ssh";

        Assert.Equal("check ssh", _vm.Agent.UserQuery);
        // Chat text is not handed to agent operations as log context.
        Assert.Equal(string.Empty, _vm.Agent.LogText);
    }

    [AvaloniaFact]
    public void HeroInput_LogSnippet_MirrorsIntoAgentLogContext()
    {
        var text = string.Join('\n', HeroSyslogLine, HeroSyslogLine, HeroSyslogLine);

        _vm.LogText = text;

        Assert.Equal(text, _vm.Agent.LogText);
        Assert.Equal(text, _vm.Agent.UserQuery);
    }

    [AvaloniaFact]
    public void AgentUserQuery_BackMirror_UpdatesHeroInput()
    {
        _vm.Agent.UserQuery = "/firewall";
        Assert.Equal("/firewall", _vm.LogText);

        // Send-clears and slash-command clears flow back into the hero box.
        _vm.Agent.UserQuery = string.Empty;
        Assert.Equal(string.Empty, _vm.LogText);
    }

    [AvaloniaFact]
    public void HeroPrimaryCommand_EmptyInput_IsDisabled()
    {
        Assert.False(_vm.HeroPrimaryCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public async Task HeroPrimaryCommand_ChatText_DispatchesChatAndClearsInput()
    {
        _vm.LogText = "is my system secure?";
        Assert.True(_vm.HeroPrimaryCommand.CanExecute(null));

        _vm.HeroPrimaryCommand.Execute(null);
        await _vm.Agent.SendQueryCommand.ExecutionTask;

        // SendQueryAsync cleared UserQuery; the back-mirror cleared the hero input.
        Assert.Equal(string.Empty, _vm.LogText);
        Assert.Equal(string.Empty, _vm.Agent.UserQuery);
        Assert.Contains(_vm.Agent.Messages, m => m.IsUser && m.Text == "is my system secure?");
    }

    [AvaloniaFact]
    public async Task HeroPrimaryCommand_LogText_DispatchesAnalysisAndKeepsInput()
    {
        var text = string.Join('\n', HeroSyslogLine, HeroSyslogLine, HeroSyslogLine);
        _vm.LogText = text;
        _vm.SelectedIntensity = _vm.Intensities[2];
        Assert.True(_vm.HeroPrimaryCommand.CanExecute(null));

        _vm.HeroPrimaryCommand.Execute(null);
        await WaitForBusyAsync(_vm);

        Assert.NotNull(_vm.LastResult);
        // Analyze keeps the input (re-runnable); the summary card records what ran.
        Assert.Equal(text, _vm.LogText);
    }

    [AvaloniaFact]
    public async Task ChatSendAfterAnalysis_KeepsAnalysisContext()
    {
        _vm.LogText = string.Join('\n', HeroSyslogLine, HeroSyslogLine, HeroSyslogLine);
        _vm.SelectedIntensity = _vm.Intensities[2];
        _vm.AnalyzeCommand.Execute(null);
        await WaitForBusyAsync(_vm);
        Assert.NotNull(_vm.LastResult);
        var summaryAfterAnalysis = _vm.SummaryText;

        // Asking a follow-up question is not a log change — results must survive.
        _vm.LogText = "what should I look at first?";
        Assert.NotNull(_vm.LastResult);

        _vm.HeroPrimaryCommand.Execute(null);
        await _vm.Agent.SendQueryCommand.ExecutionTask;

        Assert.NotNull(_vm.LastResult);
        Assert.Equal(summaryAfterAnalysis, _vm.SummaryText);
    }

    [AvaloniaFact]
    public void PromptChip_FillsInputWithoutSending()
    {
        var chip = _vm.PromptChips[1];

        _vm.PromptChipCommand.Execute(chip);

        Assert.Equal(chip.Label, _vm.LogText);
        Assert.Equal(chip.Label, _vm.Agent.UserQuery);
        Assert.False(_vm.IsLogIntent);
        // Fill-only: nothing was sent — the thread is still welcome-only.
        Assert.True(_vm.Agent.HasOnlyWelcomeMessage);
    }

    [AvaloniaFact]
    public void PromptChips_HaveUniqueAutomationIds()
    {
        Assert.Equal(3, _vm.PromptChips.Count);
        Assert.Equal(_vm.PromptChips.Count, _vm.PromptChips.Select(c => c.AutomationId).Distinct().Count());
    }

    // ── UI v2 Phase 3: icon rail ─────────────────────────────────────────────

    [AvaloniaFact]
    public void ToggleSidebarCommand_TogglesCollapsedStateAndIcon()
    {
        if (MachineMode.IsEnabled)
        {
            // Machine mode pins the sidebar expanded (a11y contract stability).
            Assert.False(_vm.ShowSidebarCollapseToggle);
            _vm.ToggleSidebarCommand.Execute(null);
            Assert.False(_vm.IsSidebarCollapsed);
            return;
        }

        Assert.True(_vm.ShowSidebarCollapseToggle);
        Assert.False(_vm.IsSidebarCollapsed);
        Assert.Equal("mdi-chevron-double-left", _vm.SidebarCollapseToggleIcon);

        _vm.ToggleSidebarCommand.Execute(null);
        Assert.True(_vm.IsSidebarCollapsed);
        Assert.Equal("mdi-chevron-double-right", _vm.SidebarCollapseToggleIcon);

        _vm.ToggleSidebarCommand.Execute(null);
        Assert.False(_vm.IsSidebarCollapsed);
    }

    [AvaloniaFact]
    public void NavigationItems_HaveNavigateCommand()
    {
        Assert.All(_vm.NavigationItems, item => Assert.NotNull(item.NavigateCommand));

        var investigations = _vm.NavigationItems.First(i => i.Label == "Investigations");
        investigations.NavigateCommand!.Execute(investigations);
        Assert.Same(investigations, _vm.SelectedNavigationItem);
        Assert.True(investigations.IsSelected);
        Assert.False(_vm.NavigationItems.First(i => i.Label == "Agent").IsSelected);
    }

    [AvaloniaFact]
    public void NavigationItems_ExposeRailMetadata()
    {
        Assert.Equal("NavAgent", _vm.NavigationItems[0].AutomationId);
        Assert.Equal("mdi-robot", _vm.NavigationItems[0].Icon);
        Assert.All(_vm.NavigationItems, item => Assert.False(string.IsNullOrEmpty(item.Icon)));
    }

    private static async Task WaitForBusyAsync(MainViewModel vm, int timeoutMs = 10000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (vm.IsBusy && Environment.TickCount64 < deadline)
        {
            await Task.Delay(50);
        }
    }

    private static Finding CreateFinding(string category, string sourceHost)
    {
        var now = DateTime.UtcNow;
        return new Finding
        {
            Category = category,
            Severity = Severity.High,
            Confidence = DetectionConfidence.High,
            SourceHost = sourceHost,
            Target = "demo-target",
            TimeRangeStart = now,
            TimeRangeEnd = now.AddSeconds(1),
            ShortDescription = $"{category} test finding",
            Details = $"{category} test details"
        };
    }

    private static MainViewModel BuildViewModel(
        ISuppressionStore? suppressionStore = null,
        IAgent? agent = null,
        IDetector[]? baselineDetectors = null,
        IThreatIntelStore? threatIntelStore = null,
        IAnalystActionStore? analystActionStore = null)
    {
        var logNormalizer = new LogNormalizer();
        var profileProvider = new AnalysisProfileProvider();

        baselineDetectors ??= new IDetector[]
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
        var evidenceBuilder = new EvidenceBuilder(
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
            traceMapJsonFormatter: new TraceMapJsonFormatter(),
            incidentStoryFormatter: new IncidentStoryFormatter());

        var liveStreamAnalyzer = new LiveStreamAnalyzer(analyzer, profileProvider);
        var remediationExecutor = new RemediationExecutor(new ProcessRunner());

        return new MainViewModel(
            analyzer,
            evidenceBuilder,
            new TestDialogService(),
            profileProvider,
            agent ?? new MockAgent(),
            suppressionStore ?? new InMemorySuppressionStore(),
            new InMemoryPinnedFindingStore(),
            new InMemoryPinnedMessageStore(),
            new InMemoryAuditHistoryStore(),
            new RemediationPlanBuilder(new ExplanationProvider()),
            remediationExecutor,
            new TraceMapCorrelator(),
            liveStreamAnalyzer,
            threatIntelStore: threatIntelStore,
            analystActionStore: analystActionStore);
    }

    private static string ReadMainWindowXaml()
    {
        var path = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "../../../../VulcansTrace.Linux.Avalonia/MainWindow.axaml"));
        return File.ReadAllText(path);
    }

    private static string ExtractSelfClosingElementWithAutomationId(string xaml, string automationId)
    {
        var automationIdIndex = xaml.IndexOf($"AutomationProperties.AutomationId=\"{automationId}\"", StringComparison.Ordinal);
        Assert.True(automationIdIndex >= 0, $"Could not find automation id {automationId}.");

        var elementStart = xaml.LastIndexOf('<', automationIdIndex);
        var elementEnd = xaml.IndexOf("/>", automationIdIndex, StringComparison.Ordinal);
        Assert.True(elementStart >= 0 && elementEnd > elementStart, $"Could not extract element for automation id {automationId}.");

        return xaml[elementStart..(elementEnd + 2)];
    }

    private sealed class MockAgent : IAgent
    {
        public Task<AgentResult> AskAsync(string query, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.Help,
                Summary = "Mock agent response",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = intent,
                Summary = "Mock audit complete",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> ExplainFindingAsync(Finding finding, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ExplainFinding,
                Summary = "Mock explanation",
                AgentFindings = new List<Finding> { finding },
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> SetBaselineAsync(string name, string? description, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.SetBaseline,
                Summary = "Mock baseline set",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.CheckDrift,
                Summary = "Mock drift check",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ShowBaseline,
                Summary = "Mock baseline",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> StartRemediationAsync(string findingReference, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Mock remediation session",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = "Mock verification",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> VerifyFindingAsync(string ruleId, IProgress<AgentAuditProgress>? progress, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.VerifyRemediation,
                Summary = $"Mock verify {ruleId}",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.StartRemediation,
                Summary = "Mock export",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "Mock list",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ResumeRemediation,
                Summary = "Mock resume",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.ListRemediationSessions,
                Summary = "Mock deleted",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.AddSessionNote,
                Summary = "Mock session note",
                AgentFindings = Array.Empty<Finding>(),
                Warnings = Array.Empty<string>()
            });
        }

        public Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
        {
            return Task.FromResult(new AgentResult
            {
                Intent = AgentIntent.AddStepNote,
                Summary = "Mock step note",
                AgentFindings = Array.Empty<Finding>(),
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

    private sealed class BlockingDetector : IDetector
    {
        public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Thread.Sleep(10);
            }
        }
    }

    private sealed class StaticFindingsDetector : IDetector
    {
        private readonly IReadOnlyList<Finding> _findings;

        public StaticFindingsDetector(params Finding[] findings) => _findings = findings;

        public DetectionResult Detect(IReadOnlyList<UnifiedEvent> events, AnalysisProfile profile, CancellationToken cancellationToken) =>
            new(new List<Finding>(_findings));
    }
}
