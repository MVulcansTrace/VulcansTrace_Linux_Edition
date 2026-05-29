using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RemediationPlanValidatorTests
{
    [Fact]
    public void Validate_Passes_When_No_Dangerous_Commands()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "RO-001",
                    FindingSummary = "[Info] Read-only finding",
                    RiskNote = "Low risk",
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "cat /etc/passwd", Safety = CommandSafety.ReadOnly }
                    }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Validate_Passes_When_Dangerous_Command_Has_RollbackCommands()
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
                    HasExplicitRollbackGuidance = false,
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    },
                    RollbackCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT ACCEPT", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Validate_Passes_When_Dangerous_Command_Has_Explicit_RollbackHints()
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
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    },
                    RollbackHints = new[] { "Restore ACCEPT policy manually" }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Validate_Fails_When_Dangerous_Command_Has_Only_Generic_RollbackHints()
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
                    HasExplicitRollbackGuidance = false,
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    },
                    RollbackHints = new[] { "Generic fallback hint" }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
        Assert.Contains("FW-001", result.Errors[0]);
    }

    [Fact]
    public void Validate_Fails_When_Dangerous_Command_Has_No_Rollback()
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
                    HasExplicitRollbackGuidance = false,
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
    }

    [Fact]
    public void Validate_Fails_When_ConfigChange_Command_Lacks_Rollback()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-002",
                    FindingSummary = "[High] SSH exposed",
                    RiskNote = "High risk",
                    HasExplicitRollbackGuidance = false,
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -A INPUT -p tcp --dport 22 -s 10.0.0.1 -j ACCEPT", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
    }

    [Fact]
    public void Validate_Fails_When_Destructive_Command_Lacks_Rollback()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-003",
                    FindingSummary = "[Critical] Flush rules",
                    RiskNote = "Critical risk",
                    HasExplicitRollbackGuidance = false,
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -F", Safety = CommandSafety.Destructive }
                    }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
    }

    [Fact]
    public void Validate_Fails_When_Unclassified_ApplyCommand_Lacks_Rollback()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "UNK-001",
                    FindingSummary = "[High] Unclassified remediation",
                    RiskNote = "Unknown risk",
                    HasExplicitRollbackGuidance = false,
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "custom-hardening-tool --apply", Safety = CommandSafety.Unknown }
                    }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
        Assert.Contains("risky or unclassified", result.Errors[0]);
    }

    [Fact]
    public void Validate_Fails_When_BackupCommand_Is_Dangerous_And_Lacks_Rollback()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "FW-004",
                    FindingSummary = "[High] Backup dangerous",
                    RiskNote = "High risk",
                    HasExplicitRollbackGuidance = false,
                    ApplyCommands = Array.Empty<RemediationCommand>(),
                    BackupCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -F && sudo sh -c 'iptables-save > /root/rules.bak'", Safety = CommandSafety.Destructive }
                    }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
    }

    [Fact]
    public void Validate_Passes_When_Multiple_Sections_All_Valid()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "RO-001",
                    FindingSummary = "[Info] Read-only",
                    RiskNote = "Low",
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "cat /etc/passwd", Safety = CommandSafety.ReadOnly }
                    }
                },
                new RemediationSection
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Policy",
                    RiskNote = "High",
                    HasExplicitRollbackGuidance = true,
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Validate_Fails_When_One_Of_Multiple_Sections_Invalid()
    {
        var plan = new RemediationPlan
        {
            Sections = new[]
            {
                new RemediationSection
                {
                    RuleId = "RO-001",
                    FindingSummary = "[Info] Read-only",
                    RiskNote = "Low",
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "cat /etc/passwd", Safety = CommandSafety.ReadOnly }
                    }
                },
                new RemediationSection
                {
                    RuleId = "FW-001",
                    FindingSummary = "[High] Policy",
                    RiskNote = "High",
                    HasExplicitRollbackGuidance = false,
                    ApplyCommands = new[]
                    {
                        new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
                    }
                }
            }
        };

        var result = RemediationPlanValidator.Validate(plan);

        Assert.False(result.IsValid);
        Assert.Single(result.Errors);
        Assert.Contains("FW-001", result.Errors[0]);
    }
}
