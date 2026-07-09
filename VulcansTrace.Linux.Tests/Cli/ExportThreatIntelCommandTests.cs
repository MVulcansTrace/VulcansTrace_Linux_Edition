using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Cli;

namespace VulcansTrace.Linux.Tests.Cli;

[Collection(CliCommandTestCollection.Name)]
public class ExportThreatIntelCommandTests : IDisposable
{
    private readonly string _configDir;

    public ExportThreatIntelCommandTests()
    {
        _configDir = Path.Combine(Path.GetTempPath(), $"vt-export-ti-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_configDir);
    }

    [Fact]
    public async Task Main_ExportThreatIntel_MissingLogFile_ReturnsError()
    {
        var result = await Program.Main(["export-threat-intel", "--config-dir", _configDir, "--format", "stix", "--output", "out.json"]);
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task Main_ExportThreatIntel_MissingFormat_ReturnsError()
    {
        var logFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(logFile, SampleLog());
            var result = await Program.Main(["export-threat-intel", "--config-dir", _configDir, "--log-file", logFile, "--output", "out.json"]);
            Assert.Equal(1, result);
        }
        finally
        {
            File.Delete(logFile);
        }
    }

    [Fact]
    public async Task Main_ExportThreatIntel_InvalidFormat_ReturnsError()
    {
        var logFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(logFile, SampleLog());
            var result = await Program.Main(["export-threat-intel", "--config-dir", _configDir, "--log-file", logFile, "--format", "yaml", "--output", "out.json"]);
            Assert.Equal(1, result);
        }
        finally
        {
            File.Delete(logFile);
        }
    }

    [Fact]
    public async Task Main_ExportThreatIntel_MissingOutput_ReturnsError()
    {
        var logFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(logFile, SampleLog());
            var result = await Program.Main(["export-threat-intel", "--config-dir", _configDir, "--log-file", logFile, "--format", "stix"]);
            Assert.Equal(1, result);
        }
        finally
        {
            File.Delete(logFile);
        }
    }

    [Fact]
    public async Task Main_ExportThreatIntel_Stix_WritesFile()
    {
        var logFile = Path.GetTempFileName();
        var output = Path.GetTempFileName() + ".stix.json";
        try
        {
            await File.WriteAllTextAsync(logFile, SampleLog());
            var result = await Program.Main(["export-threat-intel", "--config-dir", _configDir, "--log-file", logFile, "--format", "stix", "--output", output, "--intensity", "High"]);
            Assert.Equal(0, result);
            Assert.True(File.Exists(output));
            var content = await File.ReadAllTextAsync(output);
            Assert.Contains("bundle", content);
        }
        finally
        {
            File.Delete(logFile);
            if (File.Exists(output)) File.Delete(output);
        }
    }

    [Fact]
    public async Task Main_ExportThreatIntel_Misp_WritesParseableFile()
    {
        var logFile = Path.GetTempFileName();
        var output = Path.GetTempFileName() + ".misp.json";
        try
        {
            await File.WriteAllTextAsync(logFile, SampleLog("10.0.0.2", 12346, 443));
            var result = await Program.Main(["export-threat-intel", "--config-dir", _configDir, "--log-file", logFile, "--format", "misp", "--output", output, "--intensity", "High"]);
            Assert.Equal(0, result);
            Assert.True(File.Exists(output));
            var content = await File.ReadAllTextAsync(output);
            Assert.Contains("Event", content);

            var importResult = MispParser.Parse(content);
            Assert.True(importResult.ImportedCount > 0);
        }
        finally
        {
            File.Delete(logFile);
            if (File.Exists(output)) File.Delete(output);
        }
    }

    private static string SampleLog(string sourceIp = "10.0.0.1", int startSourcePort = 12345, int startDestinationPort = 80)
    {
        var lines = new List<string>();
        for (var i = 0; i < 10; i++)
        {
            lines.Add($"Jan 01 12:00:0{i} localhost kernel: IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC={sourceIp} DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT={startSourcePort + i} DPT={startDestinationPort + i} WINDOW=29200 RES=0x00 SYN URGP=0");
        }
        return string.Join("\n", lines) + "\n";
    }

    public void Dispose()
    {
        VulcansTraceConfig.OverrideDirectory = null;
        try { if (Directory.Exists(_configDir)) Directory.Delete(_configDir, recursive: true); }
        catch { /* best-effort cleanup */ }
    }
}
