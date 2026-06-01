using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Cli;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Cli;

public class AutoFixCliTests
{
    private static AgentServices CreateServicesWithFakeRunner(FakeProcessRunner runner)
    {
        var baseServices = AgentFactory.Create();
        return baseServices with
        {
            ProcessRunner = runner,
            RemediationExecutor = new RemediationExecutor(runner)
        };
    }

    [Fact]
    public async Task HandleAutoFixAsync_NoAutoFixFlag_ReturnsZero()
    {
        var services = AgentFactory.Create();
        var result = new AgentResult { AgentFindings = Array.Empty<Finding>() };

        var exitCode = await Program.HandleAutoFixAsync(new[] { "audit" }, result, services, default);

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task HandleAutoFixAsync_NoFindings_ReturnsZero()
    {
        var services = AgentFactory.Create();
        var result = new AgentResult { AgentFindings = Array.Empty<Finding>() };

        var exitCode = await Program.HandleAutoFixAsync(new[] { "audit", "--auto-fix" }, result, services, default);

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task HandleAutoFixAsync_DryRun_ReturnsZero()
    {
        var services = AgentFactory.Create();
        var result = new AgentResult
        {
            AgentFindings = new[]
            {
                new Finding { RuleId = "FW-001", Severity = Severity.High, ShortDescription = "Test", Details = "**Suggested next action:**\n1. `echo fix`" }
            }
        };

        var exitCode = await Program.HandleAutoFixAsync(
            new[] { "audit", "--auto-fix", "--dry-run" }, result, services, default);

        Assert.Equal(0, exitCode);
    }

    [Fact]
    public async Task HandleAutoFixAsync_AllBlockedByPolicy_ReturnsZero()
    {
        var runner = new FakeProcessRunner();
        var services = CreateServicesWithFakeRunner(runner);
        var result = new AgentResult
        {
            AgentFindings = new[]
            {
                new Finding { RuleId = "FW-001", Severity = Severity.High, ShortDescription = "Test", Details = "**Suggested next action:**\n1. `sudo iptables -P INPUT DROP`" }
            }
        };

        var exitCode = await Program.HandleAutoFixAsync(
            new[] { "audit", "--auto-fix", "--yes" }, result, services, default);

        Assert.Equal(0, exitCode);
        Assert.Empty(runner.ExecutedCommands); // ConfigChange blocked by conservative default
    }

    [Fact]
    public async Task HandleAutoFixAsync_Yes_ExecutesAndReturnsZeroOnSuccess()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "ok", StdErr = "" });
        var services = CreateServicesWithFakeRunner(runner);
        var result = new AgentResult
        {
            AgentFindings = new[]
            {
                new Finding { RuleId = "RO-001", Severity = Severity.Info, ShortDescription = "Test", Details = "**Suggested next action:**\n1. `cat /etc/passwd`" }
            }
        };

        var exitCode = await Program.HandleAutoFixAsync(
            new[] { "audit", "--auto-fix", "--yes" }, result, services, default);

        Assert.Equal(0, exitCode);
        Assert.Single(runner.ExecutedCommands);
    }

    [Fact]
    public async Task HandleAutoFixAsync_Yes_ReturnsThreeOnFailure()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = false, ExitCode = 1, StdOut = "", StdErr = "fail" });
        var services = CreateServicesWithFakeRunner(runner);
        var result = new AgentResult
        {
            AgentFindings = new[]
            {
                new Finding { RuleId = "RO-001", Severity = Severity.Info, ShortDescription = "Test", Details = "**Suggested next action:**\n1. `cat /etc/passwd`" }
            }
        };

        var exitCode = await Program.HandleAutoFixAsync(
            new[] { "audit", "--auto-fix", "--yes" }, result, services, default);

        Assert.Equal(3, exitCode);
    }

    [Fact]
    public async Task HandleAutoFixAsync_AllowRestart_ExpandsPolicy()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "", StdErr = "" });
        var services = CreateServicesWithFakeRunner(runner);
        var result = new AgentResult
        {
            AgentFindings = new[]
            {
                new Finding
                {
                    RuleId = "SRV-001",
                    Severity = Severity.High,
                    ShortDescription = "Test",
                    Details = "**Suggested next action:**\n1. `systemctl restart sshd`\n\n**Rollback commands:**\n1. `systemctl start sshd`"
                }
            }
        };

        var exitCode = await Program.HandleAutoFixAsync(
            new[] { "audit", "--auto-fix", "--yes", "--allow-restart" }, result, services, default);

        Assert.Equal(0, exitCode);
        Assert.Single(runner.ExecutedCommands);
        Assert.Equal("systemctl restart sshd", runner.ExecutedCommands[0]);
    }

    private class FakeProcessRunner : IProcessRunner
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
