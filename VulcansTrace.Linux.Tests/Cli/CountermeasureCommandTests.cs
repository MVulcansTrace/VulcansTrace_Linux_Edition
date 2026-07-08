using System.Text.Json;
using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Actions;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Cli;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Cli;

public class CountermeasureCommandTests : IDisposable
{
    private readonly string _tempConfigDir;

    public CountermeasureCommandTests()
    {
        _tempConfigDir = Path.Combine(Path.GetTempPath(), $"vt-countermeasure-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempConfigDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempConfigDir))
                Directory.Delete(_tempConfigDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    [Fact]
    public async Task RunCountermeasureAsync_MissingLogFile_ReturnsError()
    {
        var exitCode = await Program.RunCountermeasureAsync(new[] { "countermeasure", "--baseline", "x.log" });

        Assert.Equal(1, exitCode);
    }

    [Fact]
    public async Task RunCountermeasureAsync_MissingBaseline_ReturnsError()
    {
        var exitCode = await Program.RunCountermeasureAsync(new[] { "countermeasure", "--log-file", "x.log" });

        Assert.Equal(1, exitCode);
    }

    [Fact]
    public async Task RunCountermeasureAsync_NoCriticalChains_ReturnsZero()
    {
        var baselinePath = WriteTempLog("baseline", "normal traffic");
        var incidentPath = WriteTempLog("incident", "normal traffic");

        var exitCode = await Program.RunCountermeasureAsync(new[]
        {
            "countermeasure",
            "--log-file", incidentPath,
            "--baseline", baselinePath,
            "--yes"
        });

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task RunCountermeasureAsync_DryRun_WithCriticalChain_ReturnsZero()
    {
        var baselinePath = WriteTempLog("baseline", "normal traffic");
        var incidentPath = WriteTempLog("incident", "beaconing");

        var exitCode = await Program.RunCountermeasureAsync(new[]
        {
            "countermeasure",
            "--log-file", incidentPath,
            "--baseline", baselinePath,
            "--dry-run"
        });

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task RunCountermeasureAsync_Yes_WithCriticalChain_Executes()
    {
        var baselinePath = WriteTempLog("baseline", "normal traffic");
        var incidentPath = WriteTempLog("incident", BuildCriticalChainLog());

        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "ok", StdErr = "" });
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "ok", StdErr = "" });

        var services = AgentFactory.Create(configDirectory: _tempConfigDir) with
        {
            ProcessRunner = runner,
            RemediationExecutor = new RemediationExecutor(runner)
        };

        var exitCode = await Program.RunCountermeasureAsync(
            new[] { "countermeasure", "--log-file", incidentPath, "--baseline", baselinePath, "--yes" },
            services);

        Assert.Equal(0, exitCode);
        Assert.True(runner.ExecutedCommands.Count > 0);
    }

    [Fact]
    public async Task RunCountermeasureAsync_Yes_WithFailure_LogsAnalystAction()
    {
        var baselinePath = WriteTempLog("baseline", "normal traffic");
        var incidentPath = WriteTempLog("incident", BuildCriticalChainLog());

        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = false, ExitCode = 1, StdOut = "", StdErr = "fail" });

        var services = AgentFactory.Create(configDirectory: _tempConfigDir) with
        {
            ProcessRunner = runner,
            RemediationExecutor = new RemediationExecutor(runner)
        };

        var exitCode = await Program.RunCountermeasureAsync(
            new[] { "countermeasure", "--log-file", incidentPath, "--baseline", baselinePath, "--yes" },
            services);

        Assert.Equal(3, exitCode);
        var entry = Assert.Single(services.AnalystActionStore.GetAll(), a => a.ActionType == AnalystActionType.CountermeasureDeployed);
        Assert.Contains("critical chains", entry.Details);
        Assert.Contains("success=False", entry.Details);
        Assert.Contains("failed=1", entry.Details);
    }

    private static string BuildCriticalChainLog()
    {
        // Produce a single-host log that triggers Beaconing → LateralMovement → PrivilegeEscalation
        // on the default Medium intensity profile.
        var lines = new List<string>();
        var start = new DateTime(2026, 1, 19, 10, 0, 0, DateTimeKind.Utc);
        const string compromisedHost = "192.168.1.100";
        const string attackerIp = "8.8.4.4";

        // Beaconing: 6 events to the same external IP at a regular 60-second interval.
        for (int i = 0; i < 6; i++)
        {
            lines.Add(FormatIptablesLine(start.AddSeconds(i * 60), compromisedHost, attackerIp, 80));
        }

        // Lateral movement: compromised host contacts 4 distinct internal hosts on admin port 22 within 10 minutes.
        var lateralTargets = new[] { "10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13" };
        for (int i = 0; i < lateralTargets.Length; i++)
        {
            lines.Add(FormatIptablesLine(start.AddSeconds(310 + i * 10), compromisedHost, lateralTargets[i], 22));
        }

        // Privilege escalation: 5 admin-port access attempts from the same source within 5 minutes.
        for (int i = 0; i < 5; i++)
        {
            lines.Add(FormatIptablesLine(start.AddSeconds(350 + i * 10), compromisedHost, "10.0.0.20", 22));
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatIptablesLine(DateTime timestamp, string srcIp, string dstIp, int dstPort)
    {
        return $"kernel: {timestamp:MMM dd HH:mm:ss} server IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={srcIp} DST={dstIp} PROTO=TCP SPT=54321 DPT={dstPort}";
    }

    private string WriteTempLog(string name, string content)
    {
        var path = Path.Combine(_tempConfigDir, $"{name}.log");
        File.WriteAllText(path, content);
        return path;
    }

    private sealed class FakeProcessRunner : IProcessRunner
    {
        private readonly Queue<ProcessResult> _results = new();
        public List<string> ExecutedCommands { get; } = new();

        public void QueueResult(ProcessResult result) => _results.Enqueue(result);

        public Task<ProcessResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct = default)
        {
            ExecutedCommands.Add(command);
            ct.ThrowIfCancellationRequested();
            var result = _results.Count > 0 ? _results.Dequeue() : new ProcessResult
            {
                Success = true,
                ExitCode = 0,
                StdOut = "",
                StdErr = ""
            };
            return Task.FromResult(result);
        }
    }
}
