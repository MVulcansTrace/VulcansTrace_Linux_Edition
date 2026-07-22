using System.Xml.Linq;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class MainWindowAccessibilityContractTests
{
    [Fact]
    public void PrimaryAnalysisControls_ExposeStableAccessibleNamesAndLabels()
    {
        // The unified hero input, flipping primary action, slash surfaces, and
        // scan options live in the agent-home hero panel (UI v2 Phase 3).
        var document = LoadAvaloniaDocument("Controls/HeroPanel.axaml");

        AssertAutomationName(document, "HeroInputBox", "Agent input");
        // The primary button's accessible name is intent-bound (Chat ↔ Analyze);
        // the flip is deterministic — same content, same label.
        var primary = document.Descendants().Single(element =>
            Attribute(element, "AutomationProperties.AutomationId")?.Value
                == "HeroPrimaryButton");
        Assert.Equal(
            "{Binding HeroPrimaryLabel}",
            Attribute(primary, "AutomationProperties.Name")?.Value);
        AssertAutomationName(document, "AgentSlashHelpButton", "Command help");
        AssertAutomationName(
            document,
            "AgentSlashCommandPaletteList",
            "Agent slash command palette");
        AssertAutomationName(document, "PromptChipItems", "Suggested prompts");
        AssertLabeledControl(
            document,
            "IntensityComboBox",
            "Scan intensity",
            "ScanIntensityLabel",
            "Scan intensity:");
        AssertLabeledControl(
            document,
            "MachineRoleComboBox",
            "Machine role",
            "MachineRoleLabel",
            "Machine role:");

        // The advanced numerics live in a dialog since Phase 2; the hero keeps
        // only intensity + role plus the dialog launcher.
        AssertAutomationName(document, "AdvancedScanOptionsButton", "Advanced scan options");
    }

    [Fact]
    public void AdvancedScanOptionsDialog_ExposesStableAccessibleMetadata()
    {
        var dialog = LoadAvaloniaDocument("Views/AdvancedScanOptionsWindow.axaml");

        AssertAutomationName(dialog, "AdvancedScanOptionsCloseButton", "Close advanced scan options");
        AssertAutomationName(dialog, "PortScanMinPortsInput", "Port scan minimum distinct ports");
        AssertAutomationName(dialog, "FloodMinEventsInput", "Flood minimum events");
    }

    [Fact]
    public void RepeatedVisibleLabels_ExposeContextSpecificAccessibleNames()
    {
        var mainWindow = LoadAvaloniaDocument("MainWindow.axaml");
        AssertAutomationName(mainWindow, "CancelButton", "Cancel audit");
        // Agent-query cancel moved to the status bar when the bottom chat input
        // was retired (UI v2 Phase 3) — same accessible name, single home.
        AssertAutomationName(mainWindow, "CancelAgentQueryButton", "Cancel agent query");

        var suppressions = LoadAvaloniaDocument("Views/SuppressionView.axaml");
        AssertCommandName(
            suppressions,
            "{Binding $parent[ItemsControl].DataContext.RemoveSuppressionCommand}",
            "Remove active suppression");

        var agent = LoadAvaloniaDocument("Views/AgentView.axaml");
        AssertAutomationName(
            agent,
            "AgentRemediationSessionsRefreshButton",
            "Refresh remediation sessions");
        AssertAutomationName(
            agent,
            "AgentRemediationSessionDeleteButton",
            "Delete remediation session");
        AssertAutomationName(
            agent,
            "AgentChatSeverityFilter",
            "Agent chat severity filter");
        AssertCommandName(agent, "{Binding CopyCommand}", "Copy code block");

        var findings = LoadAvaloniaDocument("Views/FindingsView.axaml");
        AssertAutomationName(
            findings,
            "SeverityFilterComboBox",
            "Findings severity filter");

        var commandRow = LoadAvaloniaDocument("Views/CommandRow.axaml");
        AssertHandlerName(commandRow, "OnCopyClick", "Copy command");
    }

    [Fact]
    public void ScheduleAndThreatIntelActions_ExposeStableContextualMetadata()
    {
        var schedules = LoadAvaloniaDocument("Views/ScheduleView.axaml");
        AssertAutomationName(schedules, "ScheduleAddButton", "Add schedule");
        AssertAutomationName(schedules, "ScheduleDeleteButton", "Delete schedule");
        AssertAutomationName(
            schedules,
            "ScheduleRunNowButton",
            "Run schedule now");

        var threatIntel = LoadAvaloniaDocument("Views/ThreatIntelView.axaml");
        AssertAutomationName(
            threatIntel,
            "ThreatIntelRemoveButton",
            "Remove threat intelligence");
        AssertAutomationName(
            threatIntel,
            "ThreatIntelRefreshButton",
            "Refresh threat intelligence");

        var actionLog = LoadAvaloniaDocument("Views/AnalystActionLogView.axaml");
        AssertAutomationName(
            actionLog,
            "AnalystActionLogRefreshButton",
            "Refresh analyst action log");
    }

    [Fact]
    public void SidebarNavigation_GroupsExposeBoundToggleMetadata()
    {
        var sidebar = LoadAvaloniaDocument("Controls/NavigationSidebar.axaml");

        AssertAutomationName(sidebar, "PrimaryNavigationList", "Primary navigation");

        // Group expand/collapse toggles get their automation metadata from the
        // NavigationGroup model (verified concretely in MainViewModelTests).
        var toggle = sidebar.Descendants().Single(element =>
            Attribute(element, "AutomationProperties.AutomationId")?.Value
                == "{Binding ToggleAutomationId}");
        Assert.Equal(
            "{Binding ToggleAccessibleName}",
            Attribute(toggle, "AutomationProperties.Name")?.Value);
        Assert.Equal("ToggleButton", toggle.Name.LocalName);

        // Each group's item list gets a per-group id the same way.
        var list = sidebar.Descendants().Single(element =>
            Attribute(element, "AutomationProperties.AutomationId")?.Value
                == "{Binding ListAutomationId}");
        Assert.Equal("ListBox", list.Name.LocalName);

        // Icon rail (UI v2 Phase 3): the collapse toggle is the single home for
        // rail expand/collapse; rail group buttons bind per-group metadata and
        // open flyouts with the same item labels.
        AssertAutomationName(sidebar, "SidebarCollapseToggle", "Toggle sidebar");
        var railButton = sidebar.Descendants().Single(element =>
            Attribute(element, "AutomationProperties.AutomationId")?.Value
                == "{Binding RailAutomationId}");
        Assert.Equal(
            "{Binding ToggleAccessibleName}",
            Attribute(railButton, "AutomationProperties.Name")?.Value);
    }

    [Fact]
    public void LinuxAtSpiTargets_DoNotDependOnAutomationIdAlone()
    {
        var agent = LoadAvaloniaDocument("Views/AgentView.axaml");
        AssertAutomationName(agent, "AgentAuditProgressBar", "Audit progress");
        AssertAutomationName(
            agent,
            "AgentSlashHelpSearchInput",
            "Search Agent commands");
        AssertAutomationName(
            agent,
            "AgentFilterEmptyState",
            "Agent chat filter empty state");

        var notifications = LoadAvaloniaDocument(
            "Views/NotificationSettingsView.axaml");
        AssertAutomationName(
            notifications,
            "NotificationEmailHostTextBox",
            "SMTP host");

        var rules = LoadAvaloniaDocument("Views/RuleCatalogView.axaml");
        AssertAutomationName(rules, "RulesSearchTextBox", "Search rules");
        AssertAutomationName(
            rules,
            "RulesFilterEmptyState",
            "Rule catalog filter empty state");

        var threatIntel = LoadAvaloniaDocument("Views/ThreatIntelView.axaml");
        AssertAutomationName(
            threatIntel,
            "ThreatIntelTypeFilterComboBox",
            "Threat intelligence type filter");

        var findings = LoadAvaloniaDocument("Views/FindingsView.axaml");
        AssertAutomationName(
            findings,
            "FindingsFilterEmptyState",
            "Findings filter empty state");
        var emptyAction = findings.Descendants().Single(element =>
            Attribute(element, "ActionAutomationId")?.Value
                == "FindingsEmptyStateAnalyzeButton");
        Assert.Equal(
            "Analyze logs from empty findings",
            Attribute(emptyAction, "ActionAutomationName")?.Value);
    }

    private static void AssertAutomationName(
        XDocument document,
        string automationId,
        string expectedName)
    {
        var control = FindByAutomationId(document, automationId);
        Assert.Equal(
            expectedName,
            Attribute(control, "AutomationProperties.Name")?.Value);
    }

    private static void AssertLabeledControl(
        XDocument document,
        string automationId,
        string expectedName,
        string labelName,
        string expectedLabelText)
    {
        var control = FindByAutomationId(document, automationId);
        Assert.Equal(
            expectedName,
            Attribute(control, "AutomationProperties.Name")?.Value);
        Assert.Equal(
            $"{{Binding ElementName={labelName}}}",
            Attribute(control, "AutomationProperties.LabeledBy")?.Value);

        var label = document.Descendants().Single(element =>
            Attribute(element, "Name")?.Value == labelName);
        Assert.Equal(expectedLabelText, Attribute(label, "Text")?.Value);
    }

    private static void AssertCommandName(
        XDocument document,
        string command,
        string expectedName)
    {
        var control = document.Descendants().Single(element =>
            Attribute(element, "Command")?.Value == command);
        Assert.Equal(
            expectedName,
            Attribute(control, "AutomationProperties.Name")?.Value);
    }

    private static void AssertHandlerName(
        XDocument document,
        string handler,
        string expectedName)
    {
        var control = document.Descendants().Single(element =>
            Attribute(element, "Click")?.Value == handler);
        Assert.Equal(
            expectedName,
            Attribute(control, "AutomationProperties.Name")?.Value);
    }

    private static XElement FindByAutomationId(
        XDocument document,
        string automationId)
    {
        return document.Descendants().Single(element =>
            Attribute(element, "AutomationProperties.AutomationId")?.Value
                == automationId);
    }

    private static XAttribute? Attribute(XElement element, string localName)
    {
        return element.Attributes().SingleOrDefault(attribute =>
            attribute.Name.LocalName == localName);
    }

    private static XDocument LoadMainWindow()
    {
        return LoadAvaloniaDocument("MainWindow.axaml");
    }

    private static XDocument LoadAvaloniaDocument(string relativePath)
    {
        var currentDirectoryPath = Path.Combine(
            Directory.GetCurrentDirectory(),
            "VulcansTrace.Linux.Avalonia",
            relativePath);
        if (File.Exists(currentDirectoryPath))
            return XDocument.Load(currentDirectoryPath);

        var baseDirectoryPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "../../../../VulcansTrace.Linux.Avalonia",
            relativePath));
        return XDocument.Load(baseDirectoryPath);
    }

    // ── Automation-id / accessible-name ratchet ─────────────────────────
    // Baselines for the UI v2 accessibility contract: every actionable
    // control that ships WITHOUT an AutomationProperties.AutomationId, and
    // every accessible name that is not unique. Both lists only SHRINK:
    // fixing a control means deleting its line; a new violation fails the
    // build. Entry format: "{file}|{tag}|{key}" where the key is the best
    // stable attribute (x:Name, accessible name, Content/Header literal,
    // Command, Click, ToolTip).
    private static readonly string[] MissingAutomationIdBaseline =
    {
        "Controls/HeroPanel.axaml|Button|{Binding CommandText}",
        "Views/AgentView.axaml|Expander|Audit History",
        "Views/AgentView.axaml|Expander|Remediation Sessions",
        "Views/AgentView.axaml|Button|{Binding PinTooltip}",
        "Views/AgentView.axaml|Button|{Binding Label}",
        "Views/AgentView.axaml|Button|{Binding Label}",
        "Views/AgentView.axaml|ListBox|ChatListBox",
        "Views/AgentView.axaml|Button|Copy code block",
        "Views/AgentView.axaml|Button|{Binding CommandText}",
        "Views/CommandRow.axaml|Button|Copy command",
        "Views/IncidentStoryView.axaml|Button|Copy Markdown",
        "Views/LiveStreamView.axaml|Button|Start",
        "Views/LiveStreamView.axaml|Button|Stop",
        "Views/RemediationPreviewWindow.axaml|Button|ExecuteButton",
        "Views/RemediationPreviewWindow.axaml|Button|CloseButton",
        "Views/RulePolicyEditWindow.axaml|CheckBox|Override Enabled",
        "Views/RulePolicyEditWindow.axaml|CheckBox|Enabled",
        "Views/RulePolicyEditWindow.axaml|CheckBox|Override Severity",
        "Views/RulePolicyEditWindow.axaml|CheckBox|Override Auto-Pass",
        "Views/RulePolicyEditWindow.axaml|CheckBox|Auto-Pass",
        "Views/ScheduleEditWindow.axaml|CheckBox|Notify on critical findings",
        "Views/ScheduleEditWindow.axaml|CheckBox|Enabled",
        "Views/ScheduleEditWindow.axaml|CheckBox|Autonomous drift response",
        "Views/ScheduleEditWindow.axaml|CheckBox|Require signed alerts (skip unsigned drift alerts when no signing key is set)",
        "Views/ScheduleEditWindow.axaml|CheckBox|Allow human-approved remediation",
        "Views/ScheduleEditWindow.axaml|CheckBox|Permit service restarts",
        "Views/ScheduleEditWindow.axaml|CheckBox|Permit package install/remove",
        "Views/SuppressionView.axaml|Button|Renew suppression",
        "Views/SuppressionView.axaml|Button|Convert suppression duration",
        "Views/SuppressionView.axaml|Button|Edit suppression reason",
        "Views/SuppressionView.axaml|Button|Remove suppression",
        "Views/TimelineView.axaml|ToggleButton|TraceMapToggle",
        "Views/TimelineView.axaml|ToggleButton|HostGroupToggle",
    };

    private static readonly string[] DuplicateAccessibleNameBaseline =
    {
        "Enabled",
    };

    [Fact]
    public void ActionableControls_WithoutAutomationId_MatchRatchetBaseline()
    {
        var violations = CollectMissingAutomationIds()
            .OrderBy(v => v, StringComparer.Ordinal)
            .ToArray();
        var expected = MissingAutomationIdBaseline
            .OrderBy(v => v, StringComparer.Ordinal)
            .ToArray();
        if (expected.SequenceEqual(violations))
            return;

        var added = violations.Except(expected, StringComparer.Ordinal).ToArray();
        var stale = expected.Except(violations, StringComparer.Ordinal).ToArray();
        Assert.Fail(
            "automation-id ratchet drifted.\n"
                + "New violations (give the control an AutomationId; "
                + "do NOT grow the baseline):\n  "
                + string.Join("\n  ", added)
                + "\nFixed or moved (shrink MissingAutomationIdBaseline):\n  "
                + string.Join("\n  ", stale));
    }

    [Fact]
    public void AccessibleNames_AreUniqueExceptRatchetBaseline()
    {
        var duplicated = CollectAccessibleNames()
            .GroupBy(name => name, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
        var expected = DuplicateAccessibleNameBaseline
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
        if (expected.SequenceEqual(duplicated))
            return;

        var added = duplicated.Except(expected, StringComparer.Ordinal).ToArray();
        var stale = expected.Except(duplicated, StringComparer.Ordinal).ToArray();
        Assert.Fail(
            "accessible-name uniqueness ratchet drifted.\n"
                + "New duplicate names (rename one control; "
                + "do NOT grow the baseline):\n  "
                + string.Join("\n  ", added)
                + "\nResolved duplicates (shrink DuplicateAccessibleNameBaseline):\n  "
                + string.Join("\n  ", stale));
    }

    private static readonly HashSet<string> ActionableTags = new(StringComparer.Ordinal)
    {
        "Button", "ToggleButton", "ComboBox", "TextBox", "Expander", "MenuItem",
        "NumericUpDown", "ListBox", "DataGrid", "AutoCompleteBox", "TabItem",
        "RadioButton", "CheckBox", "Slider",
    };

    private static readonly HashSet<string> ContentNamedTags = new(StringComparer.Ordinal)
    {
        "Button", "ToggleButton", "MenuItem", "RadioButton", "CheckBox", "TabItem",
    };

    private static IEnumerable<string> CollectMissingAutomationIds()
    {
        foreach (var (relativePath, document) in LoadAllAvaloniaDocuments())
        {
            foreach (var element in document.Descendants())
            {
                if (!ActionableTags.Contains(element.Name.LocalName))
                    continue;
                if (Attribute(element, "AutomationProperties.AutomationId") is not null)
                    continue;
                var key = Attribute(element, "Name")?.Value
                    ?? Attribute(element, "AutomationProperties.Name")?.Value
                    ?? Literal(Attribute(element, "Content")?.Value)
                    ?? Literal(Attribute(element, "Header")?.Value)
                    ?? Attribute(element, "Command")?.Value
                    ?? Attribute(element, "Click")?.Value
                    ?? Attribute(element, "ToolTip.Tip")?.Value
                    ?? "?";
                yield return $"{relativePath}|{element.Name.LocalName}|{key}";
            }
        }
    }

    private static IEnumerable<string> CollectAccessibleNames()
    {
        foreach (var (_, document) in LoadAllAvaloniaDocuments())
        {
            foreach (var element in document.Descendants())
            {
                if (!ActionableTags.Contains(element.Name.LocalName))
                    continue;
                var automationName = Attribute(element, "AutomationProperties.Name")?.Value;
                if (!string.IsNullOrEmpty(automationName) && Literal(automationName) is not null)
                {
                    yield return automationName;
                    continue;
                }
                if (!ContentNamedTags.Contains(element.Name.LocalName))
                    continue;
                var content = Literal(Attribute(element, "Content")?.Value);
                if (content is not null)
                    yield return content;
            }
        }
    }

    private static string? Literal(string? value)
    {
        return !string.IsNullOrEmpty(value) && !value.StartsWith('{') ? value : null;
    }

    private static IEnumerable<(string RelativePath, XDocument Document)> LoadAllAvaloniaDocuments()
    {
        var root = AvaloniaProjectDirectory();
        var files = Directory.GetFiles(root, "*.axaml", SearchOption.AllDirectories)
            .OrderBy(file => file, StringComparer.Ordinal);
        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(root, file)
                .Replace(Path.DirectorySeparatorChar, '/');
            if (relative.StartsWith("bin/") || relative.StartsWith("obj/"))
                continue;
            yield return (relative, XDocument.Load(file));
        }
    }

    private static string AvaloniaProjectDirectory()
    {
        var currentDirectoryPath = Path.Combine(
            Directory.GetCurrentDirectory(),
            "VulcansTrace.Linux.Avalonia");
        if (Directory.Exists(currentDirectoryPath))
            return currentDirectoryPath;
        return Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "../../../../VulcansTrace.Linux.Avalonia"));
    }
}
