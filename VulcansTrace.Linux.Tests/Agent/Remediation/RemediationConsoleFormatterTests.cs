using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Remediation;

public class RemediationConsoleFormatterTests
{
    [Fact]
    public void FormatDryRun_EmptyPlan_ReturnsHeaderAndFooter()
    {
        var plan = new RemediationPlan { Sections = Array.Empty<RemediationSection>() };
        var policy = AutoFixPolicy.Standard();

        var output = RemediationConsoleFormatter.FormatDryRun(plan, policy);

        Assert.Contains("DRY-RUN PREVIEW", output);
        Assert.Contains("NO CHANGES WERE MADE", output);
        Assert.Contains("Total findings: 0", output);
    }

    [Fact]
    public void FormatDryRun_WithSections_ShowsPermittedAndBlocked()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    RiskNote = "High risk",
                    HasExplicitRollbackGuidance = true,
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange },
                        new RemediationCommand { Command = "cat /etc/passwd", Safety = CommandSafety.ReadOnly }
                    }
                }
            }
        };
        var policy = AutoFixPolicy.Conservative(); // permits ReadOnly, blocks ConfigChange

        var output = RemediationConsoleFormatter.FormatDryRun(plan, policy);

        Assert.Contains("FW-001", output);
        Assert.Contains("Would execute 1 command(s)", output);
        Assert.Contains("[ ReadOnly ] cat /etc/passwd", output);
        Assert.Contains("Would SKIP 1 command(s) (policy)", output);
        Assert.Contains("[ ConfigChange ] sudo iptables -P INPUT DROP", output);
    }

    [Fact]
    public void FormatExecutionResult_AllSuccess_ShowsCheckmarks()
    {
        var result = new RemediationExecutionResult
        {
            IsDryRun = false,
            Sections = new[]
            {
                new SectionExecutionResult
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    BackupResults = new[]
                    {
                        new CommandExecutionResult { Command = "backup", Phase = RemediationPhase.Backup, Success = true, ExitCode = 0 }
                    },
                    ApplyResults = new[]
                    {
                        new CommandExecutionResult { Command = "apply", Phase = RemediationPhase.Apply, Success = true, ExitCode = 0 }
                    },
                    VerificationResults = new[]
                    {
                        new CommandExecutionResult { Command = "verify", Phase = RemediationPhase.Verify, Success = true, ExitCode = 0 }
                    }
                }
            }
        };

        var output = RemediationConsoleFormatter.FormatExecutionResult(result);

        Assert.Contains("✅ FW-001", output);
        Assert.Contains("[Backup] backup", output);
        Assert.Contains("[Apply] apply", output);
        Assert.Contains("[Verify] verify", output);
    }

    [Fact]
    public void FormatExecutionResult_WithFailures_ShowsCrosses()
    {
        var result = new RemediationExecutionResult
        {
            IsDryRun = false,
            Sections = new[]
            {
                new SectionExecutionResult
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    ApplyResults = new[]
                    {
                        new CommandExecutionResult { Command = "apply", Phase = RemediationPhase.Apply, Success = false, ExitCode = 1, StdErr = "permission denied" }
                    }
                }
            }
        };

        var output = RemediationConsoleFormatter.FormatExecutionResult(result);

        Assert.Contains("❌ FW-001", output);
        Assert.Contains("Exit code: 1", output);
        Assert.Contains("ERR: permission denied", output);
    }

    [Fact]
    public void FormatExecutionResult_SkippedSection_ShowsSkipReason()
    {
        var result = new RemediationExecutionResult
        {
            IsDryRun = false,
            Sections = new[]
            {
                new SectionExecutionResult
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    Skipped = true,
                    SkipReason = "Validation failed"
                }
            }
        };

        var output = RemediationConsoleFormatter.FormatExecutionResult(result);

        Assert.Contains("⏭️  FW-001: SKIPPED", output);
        Assert.Contains("Validation failed", output);
    }

    [Fact]
    public void FormatExecutionResult_RollbackTriggered_ShowsIndicator()
    {
        var result = new RemediationExecutionResult
        {
            IsDryRun = false,
            Sections = new[]
            {
                new SectionExecutionResult
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    ApplyResults = new[]
                    {
                        new CommandExecutionResult { Command = "apply", Phase = RemediationPhase.Apply, Success = false, ExitCode = 1 }
                    },
                    RollbackResults = new[]
                    {
                        new CommandExecutionResult { Command = "rollback", Phase = RemediationPhase.Rollback, Success = true, ExitCode = 0 }
                    }
                }
            }
        };

        var output = RemediationConsoleFormatter.FormatExecutionResult(result);

        Assert.Contains("🔄 Rollback triggered due to apply failure.", output);
        Assert.Contains("[Rollback] rollback", output);
    }

    [Fact]
    public void FormatExecutionResult_OutputTruncation_WhenMoreThan3Lines()
    {
        var result = new RemediationExecutionResult
        {
            IsDryRun = false,
            Sections = new[]
            {
                new SectionExecutionResult
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Default policy ACCEPT",
                    ApplyResults = new[]
                    {
                        new CommandExecutionResult
                        {
                            Command = "apply",
                            Phase = RemediationPhase.Apply,
                            Success = true,
                            ExitCode = 0,
                            StdOut = "line1\nline2\nline3\nline4\nline5"
                        }
                    }
                }
            }
        };

        var output = RemediationConsoleFormatter.FormatExecutionResult(result);

        Assert.Contains("line1", output);
        Assert.Contains("line2", output);
        Assert.Contains("line3", output);
        Assert.Contains("(2 more lines)", output);
    }
}
