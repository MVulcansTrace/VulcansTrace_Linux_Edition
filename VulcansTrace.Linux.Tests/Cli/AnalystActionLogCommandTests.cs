using System.Text.Json;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Cli;

namespace VulcansTrace.Linux.Tests.Cli;

[Collection(CliCommandTestCollection.Name)]
public class AnalystActionLogCommandTests : IDisposable
{
    private readonly string _configDir;

    public AnalystActionLogCommandTests()
    {
        _configDir = Path.Combine(Path.GetTempPath(), $"vt-test-config-{Guid.NewGuid()}");
        Directory.CreateDirectory(_configDir);
    }

    [Fact]
    public async Task Main_AnalystActionLog_NoSubcommand_ListIsDefault()
    {
        var result = await Program.Main(["analyst-action-log", "--config-dir", _configDir]);
        Assert.Equal(0, result);
    }

    [Fact]
    public async Task Main_AnalystActionLog_List_WritesJson()
    {
        var jsonPath = Path.Combine(_configDir, "actions.json");
        var store = JsonFileAnalystActionStore.CreateDefault(_configDir);
        store.Append(new AnalystActionEntry
        {
            Id = "a1",
            TimestampUtc = DateTime.UtcNow,
            Actor = "cli",
            ActionType = AnalystActionType.AuditRan,
            Target = "FullAudit"
        });
        store.Dispose();

        var result = await Program.Main(["analyst-action-log", "list", "--config-dir", _configDir, "--json", jsonPath]);

        Assert.Equal(0, result);
        Assert.True(File.Exists(jsonPath));
        var json = await File.ReadAllTextAsync(jsonPath);
        Assert.Contains("AuditRan", json);
        Assert.Contains("FullAudit", json);
    }

    [Fact]
    public async Task Main_AnalystActionLog_Export_WritesAllActions()
    {
        var exportPath = Path.Combine(_configDir, "exported.json");
        var store = JsonFileAnalystActionStore.CreateDefault(_configDir);
        store.Append(new AnalystActionEntry
        {
            Id = "b1",
            TimestampUtc = DateTime.UtcNow,
            Actor = "cli",
            ActionType = AnalystActionType.SuppressionAdded,
            Target = "FW-001"
        });
        store.Dispose();

        var result = await Program.Main(["analyst-action-log", "export", "--config-dir", _configDir, "--output", exportPath]);

        Assert.Equal(0, result);
        Assert.True(File.Exists(exportPath));
        var json = await File.ReadAllTextAsync(exportPath);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal(JsonValueKind.Array, root.ValueKind);
        Assert.Single(root.EnumerateArray());
    }

    [Fact]
    public async Task Main_AnalystActionLog_Clear_RemovesActions()
    {
        var store = JsonFileAnalystActionStore.CreateDefault(_configDir);
        store.Append(new AnalystActionEntry
        {
            Id = "c1",
            TimestampUtc = DateTime.UtcNow,
            Actor = "cli",
            ActionType = AnalystActionType.AuditRan
        });
        store.Dispose();

        var result = await Program.Main(["analyst-action-log", "clear", "--config-dir", _configDir, "--yes"]);

        Assert.Equal(0, result);
        using var fresh = JsonFileAnalystActionStore.CreateDefault(_configDir);
        Assert.Empty(fresh.GetAll());
    }

    [Fact]
    public async Task Main_AnalystActionLog_Export_MissingOutput_ReturnsError()
    {
        var result = await Program.Main(["analyst-action-log", "export", "--config-dir", _configDir]);
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task Main_AnalystActionLog_List_JsonTargetIsDirectory_ReturnsError()
    {
        var result = await Program.Main(["analyst-action-log", "list", "--config-dir", _configDir, "--json", _configDir]);
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task Main_AnalystActionLog_Export_OutputIsDirectory_ReturnsError()
    {
        var result = await Program.Main(["analyst-action-log", "export", "--config-dir", _configDir, "--output", _configDir]);
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task Main_AnalystActionLog_UnknownSubcommand_ReturnsError()
    {
        var result = await Program.Main(["analyst-action-log", "frobnicate", "--config-dir", _configDir]);
        Assert.Equal(1, result);
    }

    public void Dispose()
    {
        VulcansTraceConfig.OverrideDirectory = null;
        try { if (Directory.Exists(_configDir)) Directory.Delete(_configDir, recursive: true); }
        catch { /* best-effort cleanup */ }
    }
}
