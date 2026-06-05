using VulcansTrace.Linux.Cli;

namespace VulcansTrace.Linux.Tests.Cli;

[Collection(CliCommandTestCollection.Name)]
public class DiffCommandTests
{
    [Fact]
    public async Task Main_UnknownCommand_ReturnsError()
    {
        var result = await Program.Main(["unknown"]);
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task Main_Diff_MissingBaseline_ReturnsError()
    {
        var result = await Program.Main(["diff", "--incident", "some.log"]);
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task Main_Diff_MissingIncident_ReturnsError()
    {
        var result = await Program.Main(["diff", "--baseline", "some.log"]);
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task Main_Diff_BaselineNotFound_ReturnsError()
    {
        var result = await Program.Main(["diff", "--baseline", "/nonexistent/baseline.log", "--incident", "/nonexistent/incident.log"]);
        Assert.Equal(1, result);
    }

    [Fact]
    public async Task Main_Diff_IdenticalLogs_ReturnsZero()
    {
        var baseline = Path.GetTempFileName();
        var incident = Path.GetTempFileName();
        try
        {
            var logContent =
                "Jan 01 12:00:00 localhost kernel: IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=10.0.0.1 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0\n";
            await File.WriteAllTextAsync(baseline, logContent);
            await File.WriteAllTextAsync(incident, logContent);

            var result = await Program.Main(["diff", "--baseline", baseline, "--incident", incident]);
            Assert.Equal(0, result);
        }
        finally
        {
            File.Delete(baseline);
            File.Delete(incident);
        }
    }

    [Fact]
    public async Task Main_Diff_DifferentLogs_ReturnsTwo()
    {
        var baseline = Path.GetTempFileName();
        var incident = Path.GetTempFileName();
        try
        {
            var baselineLog =
                "Jan 01 12:00:00 localhost kernel: IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=10.0.0.1 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0\n";
            var incidentLog =
                "Jan 01 12:00:00 localhost kernel: IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=10.0.0.2 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12346 DF PROTO=TCP SPT=12346 DPT=443 WINDOW=29200 RES=0x00 SYN URGP=0\n";
            await File.WriteAllTextAsync(baseline, baselineLog);
            await File.WriteAllTextAsync(incident, incidentLog);

            var result = await Program.Main(["diff", "--baseline", baseline, "--incident", incident]);
            Assert.Equal(2, result);
        }
        finally
        {
            File.Delete(baseline);
            File.Delete(incident);
        }
    }

    [Fact]
    public async Task Main_Diff_WritesJsonOutput()
    {
        var baseline = Path.GetTempFileName();
        var incident = Path.GetTempFileName();
        var outputJson = Path.GetTempFileName() + ".json";
        try
        {
            var baselineLog =
                "Jan 01 12:00:00 localhost kernel: IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=10.0.0.1 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0\n";
            var incidentLog =
                "Jan 01 12:00:00 localhost kernel: IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=10.0.0.2 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12346 DF PROTO=TCP SPT=12346 DPT=443 WINDOW=29200 RES=0x00 SYN URGP=0\n";
            await File.WriteAllTextAsync(baseline, baselineLog);
            await File.WriteAllTextAsync(incident, incidentLog);

            var result = await Program.Main(["diff", "--baseline", baseline, "--incident", incident, "--output-json", outputJson]);
            Assert.Equal(2, result);
            Assert.True(File.Exists(outputJson));
            var content = await File.ReadAllTextAsync(outputJson);
            Assert.Contains("addedCount", content);
        }
        finally
        {
            File.Delete(baseline);
            File.Delete(incident);
            if (File.Exists(outputJson)) File.Delete(outputJson);
        }
    }

    [Fact]
    public async Task Main_Diff_OutputEvidenceWithoutPath_ReturnsError()
    {
        var baseline = Path.GetTempFileName();
        var incident = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(baseline, SampleLog("10.0.0.1", 12345, 80));
            await File.WriteAllTextAsync(incident, SampleLog("10.0.0.2", 12346, 443));

            var result = await Program.Main(["diff", "--baseline", baseline, "--incident", incident, "--output-evidence"]);

            Assert.Equal(1, result);
        }
        finally
        {
            File.Delete(baseline);
            File.Delete(incident);
        }
    }

    [Fact]
    public async Task Main_Diff_WritesEvidenceOutputAndPrintsGeneratedSigningKey()
    {
        var baseline = Path.GetTempFileName();
        var incident = Path.GetTempFileName();
        var outputEvidence = Path.GetTempFileName() + ".zip";
        var originalOut = Console.Out;
        using var writer = new StringWriter();

        try
        {
            Console.SetOut(writer);
            await File.WriteAllTextAsync(baseline, SampleLog("10.0.0.1", 12345, 80));
            await File.WriteAllTextAsync(incident, SampleLog("10.0.0.2", 12346, 443));

            var result = await Program.Main(["diff", "--baseline", baseline, "--incident", incident, "--output-evidence", outputEvidence]);

            Assert.Equal(2, result);
            Assert.True(File.Exists(outputEvidence));
            Assert.Contains("Generated signing key", writer.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            File.Delete(baseline);
            File.Delete(incident);
            if (File.Exists(outputEvidence)) File.Delete(outputEvidence);
        }
    }

    private static string SampleLog(string sourceIp, int sourcePort, int destinationPort)
        => $"Jan 01 12:00:00 localhost kernel: IN=eth0 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC={sourceIp} DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT={sourcePort} DPT={destinationPort} WINDOW=29200 RES=0x00 SYN URGP=0\n";
}

[CollectionDefinition(CliCommandTestCollection.Name, DisableParallelization = true)]
public sealed class CliCommandTestCollection
{
    public const string Name = "CLI command tests";
}
