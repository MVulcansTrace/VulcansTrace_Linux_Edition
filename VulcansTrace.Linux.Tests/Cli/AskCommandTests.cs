using VulcansTrace.Linux.Agent;
using VulcansTrace.Linux.Agent.Baselines;
using VulcansTrace.Linux.Agent.Dialogue;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Sessions;
using VulcansTrace.Linux.Cli;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Cli;

[Collection(CliCommandTestCollection.Name)]
public class AskCommandTests
{
    [Fact]
    public async Task RunAskAsync_MissingQuery_ReturnsError()
    {
        using var console = new ConsoleCapture();
        var result = await Program.RunAskAsync(["ask"]);

        Assert.Equal(1, result);
        Assert.Contains("Query required", console.ErrorOutput);
    }

    [Fact]
    public async Task RunAskAsync_QueryAsFlag_ReturnsError()
    {
        using var console = new ConsoleCapture();
        var result = await Program.RunAskAsync(["ask", "--audit-intent", "FirewallCheck"]);

        Assert.Equal(1, result);
        Assert.Contains("Query required", console.ErrorOutput);
    }

    [Fact]
    public async Task RunAskAsync_UnknownIntent_ReturnsError()
    {
        using var console = new ConsoleCapture();
        var agent = new FakeAgent();
        var result = await Program.RunAskAsync(["ask", "prove FW-004", "--audit-intent", "NotAnIntent"], agent);

        Assert.Equal(1, result);
        Assert.Contains("Unknown audit intent", console.ErrorOutput);
        Assert.False(agent.AskCalled);
    }

    [Fact]
    public async Task RunAskAsync_UnknownRole_ReturnsError()
    {
        using var console = new ConsoleCapture();
        var agent = new FakeAgent();
        var result = await Program.RunAskAsync(["ask", "prove FW-004", "--role", "NotARole"], agent);

        Assert.Equal(1, result);
        Assert.Contains("Unknown role", console.ErrorOutput);
        Assert.False(agent.AskCalled);
    }

    [Fact]
    public async Task RunAskAsync_MissingLogFile_ReturnsError()
    {
        using var console = new ConsoleCapture();
        var agent = new FakeAgent();
        var result = await Program.RunAskAsync(["ask", "prove FW-004", "--log-file", "/tmp/does-not-exist-ask-test.log"], agent);

        Assert.Equal(1, result);
        Assert.Contains("Log file not found", console.ErrorOutput);
        Assert.False(agent.AskCalled);
    }

    [Fact]
    public async Task RunAskAsync_ValidQuery_RunsAuditThenAskAndPrintsOutput()
    {
        using var console = new ConsoleCapture();
        var agent = new FakeAgent
        {
            ResolveQueryFunc = _ => new AgentQuery(AgentIntent.ShowEvidence, "FW-004", RawQuery: "prove FW-004"),
            AskResult = new AgentResult
            {
                Summary = "FW-004 failed.",
                Narrative = new Narrative { Summary = "FW-004 failed.", KeyFindingsParagraph = "Default drop is missing." },
                AgentFindings =
                [
                    new Finding
                    {
                        RuleId = "FW-004",
                        Severity = Severity.High,
                        Category = "Firewall",
                        SourceHost = "local",
                        Target = "default policy",
                        ShortDescription = "Firewall default drop policy is missing",
                        Details = "Default drop policy is missing",
                        TimeRangeStart = DateTime.UtcNow,
                        TimeRangeEnd = DateTime.UtcNow
                    }
                ]
            }
        };

        var result = await Program.RunAskAsync(["ask", "prove FW-004", "--audit-intent", "FirewallCheck"], agent);

        Assert.Equal(0, result);
        Assert.True(agent.AuditCalled);
        Assert.True(agent.AskCalled);
        Assert.Equal("FirewallCheck", agent.LastAuditIntent);
        Assert.Equal("prove FW-004", agent.LastAskQuery);
        Assert.Contains("FW-004 failed.", console.Output);
        Assert.Contains("Default drop is missing.", console.Output);
        Assert.Contains("Attached findings: 1", console.Output);
        Assert.Contains("[High] FW-004  Firewall default drop policy is missing", console.Output);
    }

    [Fact]
    public async Task RunAskAsync_UnquotedMultiWordQuery_PreservesWholeQuery()
    {
        using var console = new ConsoleCapture();
        var agent = new FakeAgent
        {
            ResolveQueryFunc = query =>
            {
                Assert.Equal("prove FW-004", query);
                return new AgentQuery(AgentIntent.ShowEvidence, "FW-004", RawQuery: query);
            }
        };

        var result = await Program.RunAskAsync(["ask", "prove", "FW-004", "--audit-intent", "FirewallCheck"], agent);

        Assert.Equal(0, result);
        Assert.Equal("prove FW-004", agent.LastAskQuery);
        Assert.True(agent.AuditCalled);
    }

    [Fact]
    public async Task RunAskAsync_CriticalFinding_ReturnsExitCodeTwo()
    {
        using var console = new ConsoleCapture();
        var agent = new FakeAgent
        {
            AskResult = new AgentResult
            {
                Summary = "Critical finding detected.",
                AgentFindings =
                [
                    new Finding
                    {
                        RuleId = "KERN-001",
                        Severity = Severity.Critical,
                        Category = "Kernel",
                        SourceHost = "local",
                        Target = "kernel",
                        ShortDescription = "ASLR is disabled",
                        Details = "ASLR is disabled",
                        TimeRangeStart = DateTime.UtcNow,
                        TimeRangeEnd = DateTime.UtcNow
                    }
                ]
            }
        };

        var result = await Program.RunAskAsync(["ask", "what is critical"], agent);

        Assert.Equal(2, result);
        Assert.Contains("Critical finding detected.", console.Output);
        Assert.Contains("[Critical] KERN-001  ASLR is disabled", console.Output);
    }

    [Fact]
    public async Task RunAskAsync_ConversationalQuery_WithLastResult_SkipsAudit()
    {
        using var console = new ConsoleCapture();
        var agent = new FakeAgent
        {
            LastResult = new AgentResult { Summary = "Prior audit.", AgentFindings = [] },
            ResolveQueryFunc = _ => new AgentQuery(AgentIntent.ReportStepResult, RawQuery: "step 1 worked")
        };

        var result = await Program.RunAskAsync(["ask", "step 1 worked"], agent);

        Assert.Equal(0, result);
        Assert.False(agent.AuditCalled);
        Assert.True(agent.AskCalled);
    }

    [Fact]
    public async Task RunAskAsync_AuditIntentQuery_DelegatesToAskWithoutPreAudit()
    {
        using var console = new ConsoleCapture();
        var agent = new FakeAgent
        {
            ResolveQueryFunc = _ => new AgentQuery(AgentIntent.FirewallCheck, RawQuery: "firewall check")
        };

        var result = await Program.RunAskAsync(["ask", "firewall check", "--audit-intent", "FirewallCheck"], agent);

        Assert.Equal(0, result);
        // Audit-intent queries are executed as audits by AskAsync, so the CLI must not
        // run a redundant pre-audit on top of it.
        Assert.False(agent.AuditCalled);
        Assert.True(agent.AskCalled);
    }

    [Fact]
    public async Task RunAskAsync_ContextDependentQuery_NoLastResult_RunsAudit()
    {
        using var console = new ConsoleCapture();
        var agent = new FakeAgent
        {
            ResolveQueryFunc = _ => new AgentQuery(AgentIntent.ExplainFinding, "FW-001", RawQuery: "explain FW-001")
        };

        var result = await Program.RunAskAsync(["ask", "explain FW-001"], agent);

        Assert.Equal(0, result);
        Assert.True(agent.AuditCalled);
        Assert.True(agent.AskCalled);
    }

    [Fact]
    public async Task RunAskAsync_LogFile_PassedToAuditAndAsk()
    {
        var logPath = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(logPath, "firewall log line");
            using var console = new ConsoleCapture();
            var agent = new FakeAgent
            {
                AskResult = new AgentResult
                {
                    Summary = "Log reviewed.",
                    AgentFindings = []
                }
            };

            var result = await Program.RunAskAsync(["ask", "explain this", "--log-file", logPath], agent);

            Assert.Equal(0, result);
            Assert.Equal("firewall log line", agent.LastRawLog);
        }
        finally
        {
            if (File.Exists(logPath)) File.Delete(logPath);
        }
    }

    private sealed class FakeAgent : IAgent
    {
        public bool AuditCalled { get; private set; }
        public bool AskCalled { get; private set; }
        public string? LastAuditIntent { get; private set; }
        public string? LastAskQuery { get; private set; }
        public string? LastRawLog { get; private set; }

        public AgentResult AskResult { get; init; } = new()
        {
            Summary = "Ok.",
            AgentFindings = []
        };

        public Func<string, AgentQuery>? ResolveQueryFunc { get; init; }
        public AgentResult? LastResult { get; init; }

        public AgentQuery ResolveQuery(string query)
        {
            if (ResolveQueryFunc != null)
                return ResolveQueryFunc(query);

            return new AgentQuery(AgentIntent.Help, RawQuery: query);
        }

        public Task<AgentResult> AskAsync(string query, string? rawLog, CancellationToken ct)
        {
            AskCalled = true;
            LastAskQuery = query;
            LastRawLog = rawLog;
            return Task.FromResult(AskResult);
        }

        public Task<AgentResult> RunAuditAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
        {
            AuditCalled = true;
            LastAuditIntent = intent.ToString();
            LastRawLog = rawLog;
            return Task.FromResult(new AgentResult { Summary = "Audit complete.", AgentFindings = [] });
        }

        public Task<AgentResult> ExplainFindingAsync(Finding finding, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Explanation.", AgentFindings = [finding] });

        public Task<AgentResult> SetBaselineAsync(string name, string? description, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Baseline set.", AgentFindings = [] });

        public Task<AgentResult> CheckDriftAsync(AgentIntent intent, string? rawLog, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Drift checked.", AgentFindings = [] });

        public Task<AgentResult> GetBaselineAsync(AgentIntent intent, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Baseline retrieved.", AgentFindings = [] });

        public Task<AgentResult> StartRemediationAsync(string findingReference, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Remediation started.", AgentFindings = [] });

        public Task<AgentResult> VerifyRemediationAsync(string sessionId, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Remediation verified.", AgentFindings = [] });

        public Task<AgentResult> MarkSessionExportedAsync(string sessionId, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Session marked exported.", AgentFindings = [] });

        public Task<AgentResult> ListRemediationSessionsAsync(CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Sessions listed.", AgentFindings = [] });

        public Task<AgentResult> LoadRemediationSessionAsync(string sessionId, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Session loaded.", AgentFindings = [] });

        public Task<AgentResult> DeleteRemediationSessionAsync(string sessionId, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Session deleted.", AgentFindings = [] });

        public Task<AgentResult> AddSessionNoteAsync(string sessionId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Note added.", AgentFindings = [] });

        public Task<AgentResult> AddStepNoteAsync(string sessionId, string ruleId, string text, IReadOnlyList<string>? evidenceLinks, CancellationToken ct)
            => Task.FromResult(new AgentResult { Summary = "Step note added.", AgentFindings = [] });
    }

    private sealed class ConsoleCapture : IDisposable
    {
        private readonly TextWriter _originalOut = Console.Out;
        private readonly TextWriter _originalError = Console.Error;
        private readonly StringWriter _outWriter = new();
        private readonly StringWriter _errorWriter = new();

        public ConsoleCapture()
        {
            Console.SetOut(_outWriter);
            Console.SetError(_errorWriter);
        }

        public string Output => _outWriter.ToString();
        public string ErrorOutput => _errorWriter.ToString();

        public void Dispose()
        {
            Console.SetOut(_originalOut);
            Console.SetError(_originalError);
            _outWriter.Dispose();
            _errorWriter.Dispose();
        }
    }
}
