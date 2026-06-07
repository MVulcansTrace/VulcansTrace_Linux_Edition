using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class RemediationImpactSimulatorTests
{
    [Fact]
    public void Simulate_DetectsRestartImpact_WhenSystemctlRestart()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo systemctl restart sshd", Safety = CommandSafety.ServiceRestart }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasRestartImpact);
        Assert.Contains("service restart", preview.RestartImpactDescription, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Simulate_DetectsRestartImpact_WhenSystemctlReload()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo systemctl reload nginx", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasRestartImpact);
        Assert.Contains("reload", preview.RestartImpactDescription, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Simulate_NoRestartImpact_WhenReadOnlyCommands()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo cat /etc/passwd", Safety = CommandSafety.ReadOnly }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.False(preview.HasRestartImpact);
        Assert.Empty(preview.RestartImpactDescription);
    }

    [Fact]
    public void Simulate_DetectsLockoutRisk_WhenIptablesDropInputPolicy()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo iptables -P INPUT DROP", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasLockoutRisk);
        Assert.Contains("DROP", preview.LockoutRiskDescription);
    }

    [Fact]
    public void Simulate_DetectsLockoutRisk_WhenIptablesBlocksPort22()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo iptables -A INPUT -p tcp --dport 22 -j DROP", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasLockoutRisk);
        Assert.Contains("port 22", preview.LockoutRiskDescription, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Simulate_DetectsLockoutRisk_WhenIptablesRejectsPort22()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo iptables -A INPUT -p tcp --dport 22 -j REJECT", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasLockoutRisk);
        Assert.Contains("port 22", preview.LockoutRiskDescription, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Simulate_DetectsLockoutRisk_WhenSshdConfigModified()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasLockoutRisk);
        Assert.Contains("SSH", preview.LockoutRiskDescription);
    }

    [Fact]
    public void Simulate_DetectsLockoutRisk_WhenUfwDeny22()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo ufw deny 22", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasLockoutRisk);
        Assert.Contains("SSH", preview.LockoutRiskDescription);
    }

    [Fact]
    public void Simulate_DetectsLockoutRisk_WhenUfwDefaultDenyIncoming()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo ufw default deny incoming", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasLockoutRisk);
        Assert.Contains("incoming", preview.LockoutRiskDescription, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Simulate_NoLockoutRisk_WhenBenignCommand()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo sysctl -w net.ipv4.ip_forward=0", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.False(preview.HasLockoutRisk);
        Assert.Empty(preview.LockoutRiskDescription);
    }

    [Fact]
    public void Simulate_CommandCount_IncludesApplyBackupAndCountermeasures()
    {
        var section = new RemediationSection
        {
            RuleId = "TEST-001",
            FindingSummary = "[Medium] Test finding",
            RiskNote = "Test risk note.",
            ApplyCommands = new[]
            {
                new RemediationCommand { Command = "cmd1", Safety = CommandSafety.ConfigChange },
                new RemediationCommand { Command = "cmd2", Safety = CommandSafety.ConfigChange }
            },
            BackupCommands = new[]
            {
                new RemediationCommand { Command = "backup1", Safety = CommandSafety.ReadOnly }
            },
            RollbackCommands = Array.Empty<RemediationCommand>(),
            RollbackHints = Array.Empty<string>(),
            VerificationCommands = Array.Empty<RemediationCommand>(),
            CountermeasureCommands = new[]
            {
                new CountermeasureCommand
                {
                    Command = "countermeasure1",
                    RollbackCommand = "rollback-countermeasure1",
                    Safety = CommandSafety.ConfigChange
                }
            }
        };

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.Equal(4, preview.CommandCount);
    }

    [Fact]
    public void Simulate_CommandCount_DeduplicatesMirroredCountermeasureApplyCommands()
    {
        var section = new RemediationSection
        {
            RuleId = "TEST-001",
            FindingSummary = "[Medium] Test finding",
            RiskNote = "Test risk note.",
            ApplyCommands = new[]
            {
                new RemediationCommand { Command = "sudo iptables -A INPUT -s 10.0.0.1 -j DROP", Safety = CommandSafety.ConfigChange }
            },
            BackupCommands = Array.Empty<RemediationCommand>(),
            RollbackCommands = Array.Empty<RemediationCommand>(),
            RollbackHints = Array.Empty<string>(),
            VerificationCommands = Array.Empty<RemediationCommand>(),
            CountermeasureCommands = new[]
            {
                new CountermeasureCommand
                {
                    Command = "sudo iptables -A INPUT -s 10.0.0.1 -j DROP",
                    RollbackCommand = "sudo iptables -D INPUT -s 10.0.0.1 -j DROP",
                    Safety = CommandSafety.ConfigChange
                }
            }
        };

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.Equal(1, preview.CommandCount);
    }

    [Fact]
    public void Simulate_RollbackAvailable_TrueWhenExplicitRollbackCommandsExist()
    {
        var section = CreateSection(
            applyCommands: new[] { new RemediationCommand { Command = "apply", Safety = CommandSafety.ConfigChange } },
            rollbackCommands: new[] { new RemediationCommand { Command = "rollback", Safety = CommandSafety.ConfigChange } },
            hasExplicitRollbackGuidance: true);

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.RollbackAvailable);
    }

    [Fact]
    public void Simulate_RollbackAvailable_TrueWhenExplicitHintsExist()
    {
        var section = CreateSection(
            applyCommands: new[] { new RemediationCommand { Command = "apply", Safety = CommandSafety.ConfigChange } },
            rollbackHints: new[] { "Revert manually." },
            hasExplicitRollbackGuidance: true);

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.RollbackAvailable);
    }

    [Fact]
    public void Simulate_RollbackAvailable_FalseWhenOnlyGenericHintsExist()
    {
        var section = CreateSection(
            applyCommands: new[] { new RemediationCommand { Command = "apply", Safety = CommandSafety.ConfigChange } },
            rollbackHints: new[] { "Document the change." },
            hasExplicitRollbackGuidance: false);

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.False(preview.RollbackAvailable);
    }

    [Fact]
    public void Simulate_ExpectedRiskAfter_ResolvedWhenApplyCommandsExist()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo ufw enable", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.Contains("resolved", preview.ExpectedRiskAfter, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Simulate_ExpectedRiskAfter_ManualReviewWhenNoApplyCommands()
    {
        var section = CreateSection(applyCommands: System.Array.Empty<RemediationCommand>());

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.Contains("Manual review required", preview.ExpectedRiskAfter);
    }

    [Fact]
    public void Simulate_ExpectedRiskAfter_DestructiveWarning()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo rm -rf /tmp/old", Safety = CommandSafety.Destructive }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.Contains("Destructive", preview.ExpectedRiskAfter);
    }

    [Fact]
    public void Simulate_ExpectedRiskAfter_ServiceRestartMention()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo systemctl restart sshd", Safety = CommandSafety.ServiceRestart }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.Contains("service restart", preview.ExpectedRiskAfter, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Simulate_RiskBefore_DerivedFromFindingSummaryAndRiskNote()
    {
        var section = new RemediationSection
        {
            RuleId = "FW-001",
            FindingSummary = "[High] SSH exposed",
            RiskNote = "Remote access is exposed.",
            ApplyCommands = Array.Empty<RemediationCommand>(),
            BackupCommands = Array.Empty<RemediationCommand>(),
            RollbackCommands = Array.Empty<RemediationCommand>(),
            RollbackHints = Array.Empty<string>(),
            VerificationCommands = Array.Empty<RemediationCommand>(),
            HasExplicitRollbackGuidance = false
        };

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.Contains("[High]", preview.RiskBefore);
        Assert.Contains("Remote access is exposed.", preview.RiskBefore);
    }

    [Fact]
    public void Simulate_PreservesExistingPreviewFields()
    {
        var existing = new RemediationImpactPreview
        {
            ExpectedImpact = "Will block traffic.",
            ExpectedImpactSource = RemediationImpactSource.SuggestedAction,
            RollbackPath = "sudo rollback",
            RollbackPathKind = RemediationPreviewTextKind.Command,
            VerificationCommand = "sudo verify",
            IsVerificationCommand = true,
            VerificationKind = RemediationPreviewTextKind.Command
        };

        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "apply", Safety = CommandSafety.ConfigChange }
        });

        var preview = RemediationImpactSimulator.Simulate(section, existing);

        Assert.Equal("Will block traffic.", preview.ExpectedImpact);
        Assert.Equal(RemediationImpactSource.SuggestedAction, preview.ExpectedImpactSource);
        Assert.Equal("sudo rollback", preview.RollbackPath);
        Assert.Equal(RemediationPreviewTextKind.Command, preview.RollbackPathKind);
        Assert.Equal("sudo verify", preview.VerificationCommand);
        Assert.True(preview.IsVerificationCommand);
        Assert.Equal(RemediationPreviewTextKind.Command, preview.VerificationKind);
    }

    [Fact]
    public void Simulate_AggregatesMultipleRestartDescriptions()
    {
        var section = CreateSection(applyCommands: new[]
        {
            new RemediationCommand { Command = "sudo systemctl restart sshd", Safety = CommandSafety.ServiceRestart },
            new RemediationCommand { Command = "sudo systemctl restart nginx", Safety = CommandSafety.ServiceRestart }
        });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasRestartImpact);
        Assert.Contains("service restart", preview.RestartImpactDescription, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Simulate_DetectsRestartImpact_FromBackupCommands()
    {
        var section = CreateSection(
            applyCommands: Array.Empty<RemediationCommand>(),
            backupCommands: new[]
            {
                new RemediationCommand { Command = "sudo systemctl restart sshd", Safety = CommandSafety.ServiceRestart }
            });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.True(preview.HasRestartImpact);
    }

    [Fact]
    public void Simulate_DoesNotDetectLockoutRisk_FromVerificationCommands()
    {
        var section = CreateSection(
            applyCommands: Array.Empty<RemediationCommand>(),
            verificationCommands: new[]
            {
                new RemediationCommand { Command = "sudo iptables -A INPUT -p tcp --dport 22 -j DROP", Safety = CommandSafety.ConfigChange }
            });

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.False(preview.HasLockoutRisk);
        Assert.Empty(preview.LockoutRiskDescription);
    }

    [Fact]
    public void Simulate_ExpectedRiskAfter_ManualReviewWhenOnlyCountermeasures()
    {
        var section = new RemediationSection
        {
            RuleId = "CM-001",
            FindingSummary = "[Critical] Incident response",
            RiskNote = "Active defense.",
            ApplyCommands = Array.Empty<RemediationCommand>(),
            BackupCommands = Array.Empty<RemediationCommand>(),
            RollbackCommands = Array.Empty<RemediationCommand>(),
            RollbackHints = Array.Empty<string>(),
            VerificationCommands = Array.Empty<RemediationCommand>(),
            CountermeasureCommands = new[]
            {
                new CountermeasureCommand
                {
                    Command = "sudo iptables -A INPUT -s 10.0.0.1 -j DROP",
                    RollbackCommand = "sudo iptables -D INPUT -s 10.0.0.1 -j DROP",
                    Safety = CommandSafety.ConfigChange
                }
            },
            HasExplicitRollbackGuidance = false
        };

        var preview = RemediationImpactSimulator.Simulate(section, new RemediationImpactPreview());

        Assert.Contains("Manual review required", preview.ExpectedRiskAfter);
        Assert.Equal(1, preview.CommandCount);
    }

    private static RemediationSection CreateSection(
        IReadOnlyList<RemediationCommand>? applyCommands = null,
        IReadOnlyList<RemediationCommand>? backupCommands = null,
        IReadOnlyList<RemediationCommand>? rollbackCommands = null,
        IReadOnlyList<RemediationCommand>? verificationCommands = null,
        IReadOnlyList<string>? rollbackHints = null,
        bool hasExplicitRollbackGuidance = false)
    {
        return new RemediationSection
        {
            RuleId = "TEST-001",
            FindingSummary = "[Medium] Test finding",
            RiskNote = "Test risk note.",
            ApplyCommands = applyCommands ?? Array.Empty<RemediationCommand>(),
            BackupCommands = backupCommands ?? Array.Empty<RemediationCommand>(),
            RollbackCommands = rollbackCommands ?? Array.Empty<RemediationCommand>(),
            RollbackHints = rollbackHints ?? Array.Empty<string>(),
            VerificationCommands = verificationCommands ?? Array.Empty<RemediationCommand>(),
            HasExplicitRollbackGuidance = hasExplicitRollbackGuidance
        };
    }
}
