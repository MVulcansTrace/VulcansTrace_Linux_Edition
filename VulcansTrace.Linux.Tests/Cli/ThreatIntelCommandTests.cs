using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Cli;

namespace VulcansTrace.Linux.Tests.Cli;

[Collection(CliCommandTestCollection.Name)]
public sealed class ThreatIntelCommandTests : IDisposable
{
    private readonly string _configDir;

    public ThreatIntelCommandTests()
    {
        _configDir = Path.Combine(Path.GetTempPath(), $"vt-threat-intel-cli-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_configDir);
    }

    [Fact]
    public async Task Main_ThreatIntelClear_PrintsPersistenceWarning()
    {
        // Simulate a save failure by placing a directory where the JSON file should be.
        Directory.CreateDirectory(Path.Combine(_configDir, "VulcansTrace", "threat-intel.json"));

        var originalOut = Console.Out;
        using var writer = new StringWriter();

        try
        {
            Console.SetOut(writer);

            var result = await Program.Main(["threat-intel", "clear", "--config-dir", _configDir, "--yes"]);

            Assert.Equal(0, result);
        }
        finally
        {
            Console.SetOut(originalOut);
        }

        var output = writer.ToString();
        Assert.Contains("All threat intelligence IOCs cleared.", output);
        Assert.Contains("Note:", output);
        Assert.Contains("Threat intel changes will last only for this session", output);
    }

    public void Dispose()
    {
        VulcansTraceConfig.OverrideDirectory = null;
        try
        {
            if (Directory.Exists(_configDir))
                Directory.Delete(_configDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}
