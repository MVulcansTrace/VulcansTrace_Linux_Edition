using System.Xml.Linq;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class MainWindowAccessibilityContractTests
{
    [Fact]
    public void PrimaryAnalysisControls_ExposeStableAccessibleNamesAndLabels()
    {
        var document = LoadMainWindow();

        AssertAutomationName(document, "AnalyzeButton", "Analyze");
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
    }

    [Fact]
    public void RepeatedVisibleLabels_ExposeContextSpecificAccessibleNames()
    {
        var mainWindow = LoadAvaloniaDocument("MainWindow.axaml");
        AssertAutomationName(mainWindow, "CancelButton", "Cancel audit");
        AssertCommandName(
            mainWindow,
            "{Binding $parent[ItemsControl].DataContext.Suppressions.RemoveSuppressionCommand}",
            "Remove suppression");

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
        AssertAutomationName(
            agent,
            "AgentCancelButton",
            "Cancel agent query");
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
}
