using System.Xml.Linq;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class DataGridXamlContractTests
{
    [Fact]
    public void LiveStream_TimeColumn_PreservesMillisecondPrecision()
    {
        var document = LoadView("LiveStreamView.axaml");
        var timeColumn = document.Descendants()
            .Single(element =>
                element.Name.LocalName == "DataGridTextColumn" &&
                (string?)element.Attribute("Header") == "Time");

        Assert.Contains("HH:mm:ss.fff", (string?)timeColumn.Attribute("Binding") ?? string.Empty);
    }

    [Theory]
    [InlineData("Enabled")]
    [InlineData("Notify on critical")]
    [InlineData("Autonomous drift response")]
    [InlineData("Allow auto-remediate")]
    [InlineData("Installed in cron")]
    public void Schedule_IconColumns_KeepTextAndAutomationNames(string expectedName)
    {
        var document = LoadView("ScheduleView.axaml");
        var column = document.Descendants()
            .Single(element =>
                element.Name.LocalName == "DataGridCheckBoxColumn" &&
                (string?)element.Attribute("Header") == expectedName);

        Assert.Contains(column.Elements(), element =>
            element.Name.LocalName == "DataGridCheckBoxColumn.HeaderTemplate");

        var icon = column.Descendants().Single(element => element.Name.LocalName == "Icon");
        var automationName = icon.Attributes()
            .Single(attribute => attribute.Name.LocalName == "AutomationProperties.Name");
        Assert.Equal(expectedName, automationName.Value);
    }

    private static XDocument LoadView(string fileName)
    {
        var currentDirectoryPath = Path.Combine(
            Directory.GetCurrentDirectory(),
            "VulcansTrace.Linux.Avalonia",
            "Views",
            fileName);
        if (File.Exists(currentDirectoryPath))
            return XDocument.Load(currentDirectoryPath);

        var baseDirectoryPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "../../../../VulcansTrace.Linux.Avalonia/Views",
            fileName));
        return XDocument.Load(baseDirectoryPath);
    }
}
