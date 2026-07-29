using System;
using VulcansTrace.Linux.Avalonia.Services;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

[Collection(AvaloniaUiTestCollection.Name)]
public class ScenarioExportTests : IDisposable
{
    public ScenarioExportTests()
    {
        Environment.SetEnvironmentVariable("VT_SCENARIO_ID", null);
        Environment.SetEnvironmentVariable("VT_UI_TEST_EXPORT_PATH", null);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("VT_SCENARIO_ID", null);
        Environment.SetEnvironmentVariable("VT_UI_TEST_EXPORT_PATH", null);
    }

    [Fact]
    public void ResolvePath_WithoutScenarioIdentity_ReturnsNull()
    {
        Environment.SetEnvironmentVariable("VT_UI_TEST_EXPORT_PATH", "/tmp/export.zip");

        Assert.Null(ScenarioExport.ResolvePath());
    }

    [Fact]
    public void ResolvePath_WithoutExportPath_ReturnsNull()
    {
        Environment.SetEnvironmentVariable("VT_SCENARIO_ID", "audit-exported-ready");

        Assert.Null(ScenarioExport.ResolvePath());
    }

    [Fact]
    public void ResolvePath_WithScenarioIdentityAndPath_ReturnsOverride()
    {
        Environment.SetEnvironmentVariable("VT_SCENARIO_ID", "audit-exported-ready");
        Environment.SetEnvironmentVariable("VT_UI_TEST_EXPORT_PATH", "/tmp/export.zip");

        Assert.Equal("/tmp/export.zip", ScenarioExport.ResolvePath());
    }
}
