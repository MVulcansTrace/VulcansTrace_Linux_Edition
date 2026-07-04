using VulcansTrace.Linux.Agent.Explanations;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class RemediationPreviewViewModelTests
{
    [AvaloniaFact]
    public async Task ExecuteCommand_WhileExecuting_DisablesExecutionAndIgnoresSecondClick()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executeCount = 0;
        var vm = new RemediationPreviewViewModel(
            CreatePlanWithPermittedCommand(),
            AutoFixPolicy.Standard(),
            async () =>
            {
                executeCount++;
                started.SetResult();
                await finish.Task;
                return CreateResult();
            });

        vm.ExecuteCommand.Execute(null);
        await started.Task;

        Assert.True(vm.IsExecuting);
        Assert.False(vm.CanExecute);
        Assert.False(vm.ExecuteCommand.CanExecute(null));

        vm.ExecuteCommand.Execute(null);
        Assert.Equal(1, executeCount);

        finish.SetResult();
        await vm.ExecuteCommand.ExecutionTask;

        Assert.False(vm.IsExecuting);
        Assert.True(vm.IsCompleted);
        Assert.False(vm.CanExecute);
        Assert.NotNull(vm.ExecutionResult);
    }

    [AvaloniaFact]
    public async Task ExecuteCommand_WhenExecutionFails_ResetsExecutingState()
    {
        var vm = new RemediationPreviewViewModel(
            CreatePlanWithPermittedCommand(),
            AutoFixPolicy.Standard(),
            () => throw new InvalidOperationException("boom"));

        vm.ExecuteCommand.Execute(null);
        await vm.ExecuteCommand.ExecutionTask;

        Assert.False(vm.IsExecuting);
        Assert.False(vm.IsCompleted);
        Assert.True(vm.CanExecute);
        Assert.Contains("boom", vm.StatusMessage);
    }

    private static RemediationPlan CreatePlanWithPermittedCommand() => new()
    {
        Sections = new[]
        {
            new RemediationSection
            {
                RuleId = "FW-001",
                FindingSummary = "Firewall rule needs tightening",
                RiskNote = "High",
                HasExplicitRollbackGuidance = true,
                ApplyCommands = new[]
                {
                    new RemediationCommand
                    {
                        Command = "ufw deny 23/tcp",
                        Safety = CommandSafety.ConfigChange
                    }
                },
                RollbackCommands = new[]
                {
                    new RemediationCommand
                    {
                        Command = "ufw allow 23/tcp",
                        Safety = CommandSafety.ConfigChange
                    }
                },
                VerificationCommands = new[]
                {
                    new RemediationCommand
                    {
                        Command = "ufw status",
                        Safety = CommandSafety.ReadOnly
                    }
                }
            }
        }
    };

    private static RemediationExecutionResult CreateResult() => new()
    {
        IsDryRun = false,
        CompletedAtUtc = DateTime.UtcNow,
        Summary = "ok",
        Sections = new[]
        {
            new SectionExecutionResult
            {
                RuleId = "FW-001",
                FindingSummary = "Firewall rule needs tightening",
                ApplyResults = new[]
                {
                    new CommandExecutionResult
                    {
                        Command = "ufw deny 23/tcp",
                        Phase = RemediationPhase.Apply,
                        Success = true
                    }
                }
            }
        }
    };
}
