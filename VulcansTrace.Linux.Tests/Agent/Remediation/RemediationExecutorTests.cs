using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Remediation;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Remediation;

public class RemediationExecutorTests
{
    private static RemediationPlan CreateSimplePlan(params RemediationSection[] sections)
    {
        return new RemediationPlan { Sections = sections };
    }

    private static RemediationSection CreateSection(string ruleId, params RemediationCommand[] applyCommands)
    {
        return new RemediationSection
        {
            RuleId = ruleId,
            FindingSummary = $"[High] {ruleId} finding",
            RiskNote = "High risk",
            HasExplicitRollbackGuidance = true,
            ApplyCommands = applyCommands,
            BackupCommands = Array.Empty<RemediationCommand>(),
            RollbackCommands = Array.Empty<RemediationCommand>(),
            VerificationCommands = Array.Empty<RemediationCommand>()
        };
    }

    private static RemediationCommand Cmd(string text, CommandSafety safety = CommandSafety.ReadOnly)
    {
        return new RemediationCommand
        {
            Command = text,
            Safety = safety,
            Analysis = new CommandAnalysis { Safety = safety }
        };
    }

    [Fact]
    public async Task ExecuteAsync_DryRun_SkipsAllCommands()
    {
        var runner = new FakeProcessRunner();
        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(CreateSection("FW-001", Cmd("iptables -L")));
        var policy = AutoFixPolicy.Standard();

        var result = await executor.ExecuteAsync(plan, policy, dryRun: true);

        Assert.True(result.IsDryRun);
        Assert.Empty(runner.ExecutedCommands);
        Assert.True(result.AllSucceeded);
        Assert.Single(result.Sections);
        Assert.True(result.Sections[0].ApplyResults[0].Skipped);
    }

    [Fact]
    public async Task ExecuteAsync_LiveRun_ExecutesPermittedCommands()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "ok", StdErr = "" });

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(CreateSection("FW-001", Cmd("iptables -L", CommandSafety.ReadOnly)));
        var policy = AutoFixPolicy.Standard();

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.False(result.IsDryRun);
        Assert.Single(runner.ExecutedCommands);
        Assert.Equal("iptables -L", runner.ExecutedCommands[0]);
        Assert.True(result.AllSucceeded);
    }

    [Fact]
    public async Task ExecuteAsync_BlocksNonPermittedCommands()
    {
        var runner = new FakeProcessRunner();
        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(CreateSection("FW-001", Cmd("iptables -P INPUT DROP", CommandSafety.ConfigChange)));
        var policy = AutoFixPolicy.Conservative(); // blocks config change

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Empty(runner.ExecutedCommands);
        Assert.Single(result.Sections[0].ApplyResults);
        Assert.True(result.Sections[0].ApplyResults[0].Skipped);
        Assert.Contains("Policy blocks", result.Sections[0].ApplyResults[0].SkipReason);
    }

    [Fact]
    public async Task ExecuteAsync_ValidationFailure_SkipsSection_WhenRequired()
    {
        var runner = new FakeProcessRunner();
        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-002",
                FindingSummary = "[High] No rollback",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = false,
                ApplyCommands = new[] { Cmd("iptables -P INPUT DROP", CommandSafety.ConfigChange) }
            });
        var policy = AutoFixPolicy.Standard();

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.True(result.Sections[0].Skipped);
        Assert.Contains("rollback", result.Sections[0].SkipReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExecuteAsync_ValidationFailure_RunsSection_WhenNotRequired()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "", StdErr = "" });

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-002",
                FindingSummary = "[High] No rollback",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = false,
                ApplyCommands = new[] { Cmd("iptables -P INPUT DROP", CommandSafety.ConfigChange) }
            });
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false, RequireRollbackGuidance = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.False(result.Sections[0].Skipped);
        Assert.Single(runner.ExecutedCommands);
    }

    [Fact]
    public async Task ExecuteAsync_BackupFailure_AbortsApply()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = false, ExitCode = 1, StdOut = "", StdErr = "backup failed" });

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-003",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                BackupCommands = new[] { Cmd("backup-cmd", CommandSafety.ReadOnly) },
                ApplyCommands = new[] { Cmd("apply-cmd", CommandSafety.ReadOnly) }
            });
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Single(runner.ExecutedCommands); // Only backup attempted
        Assert.True(result.Sections[0].Skipped);
        Assert.Contains("Backup failed", result.Sections[0].SkipReason);
    }

    [Fact]
    public async Task ExecuteAsync_MultipleSections_StopsOnApplyFailure()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "", StdErr = "" });
        runner.QueueResult(new ProcessResult { Success = false, ExitCode = 1, StdOut = "", StdErr = "error" });

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            CreateSection("FW-001", Cmd("cmd1", CommandSafety.ReadOnly)),
            CreateSection("FW-002", Cmd("cmd2", CommandSafety.ReadOnly)));
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Equal(2, result.Sections.Count);
        Assert.True(result.Sections[0].AllCommandsSucceeded);
        Assert.False(result.Sections[1].AllCommandsSucceeded);
    }

    [Fact]
    public async Task ExecuteAsync_PropagatesCancellation_PreCancelled()
    {
        var runner = new FakeProcessRunner();
        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(CreateSection("FW-001", Cmd("sleep 10", CommandSafety.ReadOnly)));
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => executor.ExecuteAsync(plan, policy, dryRun: false, cts.Token));
    }

    [Fact]
    public async Task ExecuteAsync_PropagatesCancellation_DuringExecution()
    {
        var runner = new FakeProcessRunner(delayMs: 200);
        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            CreateSection("FW-001", Cmd("cmd1", CommandSafety.ReadOnly)),
            CreateSection("FW-002", Cmd("cmd2", CommandSafety.ReadOnly)));
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };
        using var cts = new CancellationTokenSource();

        // Cancel after the first command starts but before it completes.
        cts.CancelAfter(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => executor.ExecuteAsync(plan, policy, dryRun: false, cts.Token));

        // The first command should have been started before cancellation fired.
        Assert.Single(runner.ExecutedCommands);
    }

    [Fact]
    public async Task ExecuteAsync_ApplyFailure_TriggersRollback()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "", StdErr = "" }); // apply cmd1 succeeds
        runner.QueueResult(new ProcessResult { Success = false, ExitCode = 1, StdOut = "", StdErr = "apply failed" }); // apply cmd2 fails
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "rolled back", StdErr = "" }); // rollback succeeds

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-004",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                ApplyCommands = new[] { Cmd("apply-cmd-1", CommandSafety.ReadOnly), Cmd("apply-cmd-2", CommandSafety.ReadOnly) },
                RollbackCommands = new[] { Cmd("rollback-cmd", CommandSafety.ReadOnly) }
            });
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Equal(3, runner.ExecutedCommands.Count);
        Assert.Equal("apply-cmd-1", runner.ExecutedCommands[0]);
        Assert.Equal("apply-cmd-2", runner.ExecutedCommands[1]);
        Assert.Equal("rollback-cmd", runner.ExecutedCommands[2]);

        Assert.Single(result.Sections[0].RollbackResults);
        Assert.True(result.Sections[0].RollbackResults[0].Success);
        Assert.Equal("rolled back", result.Sections[0].RollbackResults[0].StdOut);
    }

    [Fact]
    public async Task ExecuteAsync_RollbackBypassesPolicy()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = false, ExitCode = 1, StdOut = "", StdErr = "apply failed" }); // apply fails
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "", StdErr = "" }); // rollback succeeds

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-005",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                ApplyCommands = new[] { Cmd("apply-cmd", CommandSafety.ReadOnly) },
                RollbackCommands = new[] { Cmd("rollback-cmd", CommandSafety.ConfigChange) }
            });
        var policy = AutoFixPolicy.Conservative(); // blocks ConfigChange

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Equal(2, runner.ExecutedCommands.Count);
        Assert.Equal("apply-cmd", runner.ExecutedCommands[0]);
        Assert.Equal("rollback-cmd", runner.ExecutedCommands[1]); // rollback executed despite policy
    }

    [Fact]
    public async Task ExecuteAsync_DryRun_DoesNotTriggerRollback()
    {
        var runner = new FakeProcessRunner();
        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-006",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                ApplyCommands = new[] { Cmd("apply-cmd", CommandSafety.ReadOnly) },
                RollbackCommands = new[] { Cmd("rollback-cmd", CommandSafety.ReadOnly) }
            });
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: true);

        Assert.Empty(runner.ExecutedCommands);
        Assert.Empty(result.Sections[0].RollbackResults);
    }

    [Fact]
    public async Task ExecuteAsync_RollbackFailure_StillReported()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = false, ExitCode = 1, StdOut = "", StdErr = "apply failed" }); // apply fails
        runner.QueueResult(new ProcessResult { Success = false, ExitCode = 2, StdOut = "", StdErr = "rollback failed" }); // rollback also fails

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-007",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                ApplyCommands = new[] { Cmd("apply-cmd", CommandSafety.ReadOnly) },
                RollbackCommands = new[] { Cmd("rollback-cmd", CommandSafety.ReadOnly) }
            });
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.False(result.AllSucceeded);
        Assert.Single(result.Sections[0].RollbackResults);
        Assert.False(result.Sections[0].RollbackResults[0].Success);
        Assert.Equal("rollback failed", result.Sections[0].RollbackResults[0].StdErr);
    }

    [Fact]
    public async Task ExecuteAsync_NoApplyCommands_SkipsVerification()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "", StdErr = "" }); // backup

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-008",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                BackupCommands = new[] { Cmd("backup-cmd", CommandSafety.ReadOnly) },
                ApplyCommands = Array.Empty<RemediationCommand>(),
                VerificationCommands = new[] { Cmd("verify-cmd", CommandSafety.ReadOnly) }
            });
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Single(runner.ExecutedCommands); // Only backup ran
        Assert.Equal("backup-cmd", runner.ExecutedCommands[0]);
        Assert.Empty(result.Sections[0].VerificationResults);
    }

    [Fact]
    public async Task ExecuteAsync_AllApplySkipped_SkipsVerification()
    {
        var runner = new FakeProcessRunner();
        // No queued results — nothing should execute because apply is blocked by policy

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-009",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                ApplyCommands = new[] { Cmd("apply-cmd", CommandSafety.ConfigChange) },
                VerificationCommands = new[] { Cmd("verify-cmd", CommandSafety.ReadOnly) }
            });
        var policy = AutoFixPolicy.Conservative(); // blocks ConfigChange

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Empty(runner.ExecutedCommands); // Apply skipped by policy, verify skipped due to no applicable changes
        Assert.Single(result.Sections[0].ApplyResults);
        Assert.True(result.Sections[0].ApplyResults[0].Skipped);
        Assert.Empty(result.Sections[0].VerificationResults);
    }

    [Fact]
    public async Task ExecuteAsync_EmptyPlan_ReturnsSuccess()
    {
        var runner = new FakeProcessRunner();
        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan();
        var policy = AutoFixPolicy.Standard();

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.True(result.AllSucceeded);
        Assert.Empty(result.Sections);
    }

    [Fact]
    public async Task ExecuteAsync_VerificationOnlySection_NoApplyNoVerify()
    {
        var runner = new FakeProcessRunner();
        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-010",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                ApplyCommands = Array.Empty<RemediationCommand>(),
                VerificationCommands = new[] { Cmd("verify-cmd", CommandSafety.ReadOnly) }
            });
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Empty(runner.ExecutedCommands);
        Assert.Empty(result.Sections[0].VerificationResults);
    }

    [Fact]
    public async Task ExecuteAsync_ApplyFailure_SkipsVerification()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "", StdErr = "" }); // backup
        runner.QueueResult(new ProcessResult { Success = false, ExitCode = 1, StdOut = "", StdErr = "apply failed" }); // apply fails
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "", StdErr = "" }); // rollback

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-011",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                BackupCommands = new[] { Cmd("backup-cmd", CommandSafety.ReadOnly) },
                ApplyCommands = new[] { Cmd("apply-cmd", CommandSafety.ReadOnly) },
                VerificationCommands = new[] { Cmd("verify-cmd", CommandSafety.ReadOnly) },
                RollbackCommands = new[] { Cmd("rollback-cmd", CommandSafety.ReadOnly) }
            });
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Equal(3, runner.ExecutedCommands.Count);
        Assert.Equal("backup-cmd", runner.ExecutedCommands[0]);
        Assert.Equal("apply-cmd", runner.ExecutedCommands[1]);
        Assert.Equal("rollback-cmd", runner.ExecutedCommands[2]);
        Assert.Empty(result.Sections[0].VerificationResults); // Verify skipped because apply failed
    }

    [Fact]
    public async Task ExecuteAsync_MultipleCommandsPerPhase_ExecutesInOrder()
    {
        var runner = new FakeProcessRunner();
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "b1", StdErr = "" });
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "b2", StdErr = "" });
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "a1", StdErr = "" });
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "a2", StdErr = "" });
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "v1", StdErr = "" });
        runner.QueueResult(new ProcessResult { Success = true, ExitCode = 0, StdOut = "v2", StdErr = "" });

        var executor = new RemediationExecutor(runner);
        var plan = CreateSimplePlan(
            new RemediationSection
            {
                RuleId = "FW-012",
                FindingSummary = "[High] Test",
                RiskNote = "High risk",
                HasExplicitRollbackGuidance = true,
                BackupCommands = new[] { Cmd("backup-1", CommandSafety.ReadOnly), Cmd("backup-2", CommandSafety.ReadOnly) },
                ApplyCommands = new[] { Cmd("apply-1", CommandSafety.ReadOnly), Cmd("apply-2", CommandSafety.ReadOnly) },
                VerificationCommands = new[] { Cmd("verify-1", CommandSafety.ReadOnly), Cmd("verify-2", CommandSafety.ReadOnly) }
            });
        var policy = AutoFixPolicy.Standard() with { RequireValidation = false };

        var result = await executor.ExecuteAsync(plan, policy, dryRun: false);

        Assert.Equal(6, runner.ExecutedCommands.Count);
        Assert.Equal(new[] { "backup-1", "backup-2", "apply-1", "apply-2", "verify-1", "verify-2" }, runner.ExecutedCommands);
        Assert.Equal("b1", result.Sections[0].BackupResults[0].StdOut);
        Assert.Equal("a1", result.Sections[0].ApplyResults[0].StdOut);
        Assert.Equal("v1", result.Sections[0].VerificationResults[0].StdOut);
    }

    [Fact]
    public void ExecuteAsync_ZeroTimeout_ThrowsArgumentOutOfRange()
    {
        var runner = new FakeProcessRunner();
        Assert.Throws<ArgumentOutOfRangeException>(() => new RemediationExecutor(runner, TimeSpan.Zero));
    }

    private class FakeProcessRunner : IProcessRunner
    {
        private readonly Queue<ProcessResult> _results = new();
        private readonly int _delayMs;
        public List<string> ExecutedCommands { get; } = new();

        public FakeProcessRunner(int delayMs = 0)
        {
            _delayMs = delayMs;
        }

        public void QueueResult(ProcessResult result) => _results.Enqueue(result);

        public async Task<ProcessResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct = default)
        {
            ExecutedCommands.Add(command);

            if (_delayMs > 0)
            {
                try
                {
                    await Task.Delay(_delayMs, ct);
                }
                catch (TaskCanceledException)
                {
                    throw new OperationCanceledException(ct);
                }
            }
            else
            {
                ct.ThrowIfCancellationRequested();
            }

            var result = _results.Count > 0 ? _results.Dequeue() : new ProcessResult
            {
                Success = true,
                ExitCode = 0,
                StdOut = "",
                StdErr = ""
            };
            return result;
        }
    }
}
