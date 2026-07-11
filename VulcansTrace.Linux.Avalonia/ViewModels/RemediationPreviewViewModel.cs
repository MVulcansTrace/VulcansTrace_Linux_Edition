using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Remediation;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the remediation preview/confirmation dialog. Execution runs through an injected
/// callback so the dialog can stay open and surface the result to the operator before they dismiss it.
/// </summary>
public sealed class RemediationPreviewViewModel : ViewModelBase
{
    private readonly Func<Task<RemediationExecutionResult>> _executeAsync;
    private RemediationExecutionResult? _executionResult;
    private string _statusMessage = "";
    private bool _isExecuting;
    private bool _isCompleted;

    /// <summary>
    /// Initializes a new instance of the <see cref="RemediationPreviewViewModel"/> class.
    /// </summary>
    /// <param name="plan">The remediation plan being previewed.</param>
    /// <param name="policy">The safety policy applied to the plan.</param>
    /// <param name="executeAsync">Callback that executes the plan and returns the result.</param>
    public RemediationPreviewViewModel(RemediationPlan plan, AutoFixPolicy policy, Func<Task<RemediationExecutionResult>> executeAsync)
    {
        Plan = plan ?? throw new ArgumentNullException(nameof(plan));
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _executeAsync = executeAsync ?? throw new ArgumentNullException(nameof(executeAsync));
        Validation = RemediationPlanValidator.Validate(plan);

        var permitted = plan.Sections.Sum(s => s.ApplyCommands.Count(c => policy.IsPermitted(c.Safety)));
        var blocked = plan.Sections.Sum(s => s.ApplyCommands.Count(c => !policy.IsPermitted(c.Safety)));
        var restartCount = plan.Sections.Count(s => s.ImpactPreview?.HasRestartImpact == true);
        var lockoutCount = plan.Sections.Count(s => s.ImpactPreview?.HasLockoutRisk == true);

        var summary = new StringBuilder();
        summary.AppendLine($"Findings: {plan.TotalSections}");
        summary.AppendLine($"Commands permitted: {permitted}");
        if (blocked > 0)
            summary.AppendLine($"Commands blocked by policy: {blocked}");
        summary.AppendLine($"Policy: {policy.Describe()}");
        if (!Validation.IsValid)
            summary.AppendLine($"Validation warnings: {Validation.Errors.Count}");
        if (restartCount > 0)
            summary.AppendLine($"Sections with restart impact: {restartCount}");
        if (lockoutCount > 0)
            summary.AppendLine($"Sections with lockout risk: {lockoutCount}");

        Summary = summary.ToString().Trim();
        PreviewText = RemediationConsoleFormatter.FormatDryRun(plan, policy);

        ExecuteCommand = new AsyncRelayCommand(
            _ => ExecuteCoreAsync(),
            _ => CanExecute,
            ex => StatusMessage = $"Execution failed: {ErrorSanitizer.SanitizeException(ex)}");
    }

    /// <summary>The remediation plan being previewed.</summary>
    public RemediationPlan Plan { get; }

    /// <summary>The safety policy applied to the plan.</summary>
    public AutoFixPolicy Policy { get; }

    /// <summary>The validation result for the plan.</summary>
    public ValidationResult Validation { get; }

    /// <summary>A compact summary of the plan and policy.</summary>
    public string Summary { get; }

    /// <summary>The full dry-run preview text.</summary>
    public string PreviewText { get; }

    /// <summary>Command that executes the plan while the dialog remains open.</summary>
    public AsyncRelayCommand ExecuteCommand { get; }

    private int CommandsPermitted => Plan.Sections.Sum(s => s.ApplyCommands.Count(c => Policy.IsPermitted(c.Safety)));

    /// <summary>Gets or sets the execution result after the user confirms.</summary>
    public RemediationExecutionResult? ExecutionResult
    {
        get => _executionResult;
        set
        {
            if (SetField(ref _executionResult, value))
            {
                OnPropertyChanged(nameof(HasResult));
            }
        }
    }

    /// <summary>Gets or sets the status message text.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        set => SetField(ref _statusMessage, value);
    }

    /// <summary>Whether execution has completed.</summary>
    public bool IsCompleted
    {
        get => _isCompleted;
        set
        {
            if (SetField(ref _isCompleted, value))
            {
                OnPropertyChanged(nameof(CanExecute));
                ExecuteCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Whether execution is currently in progress (gates the Close button so a run cannot be dismissed mid-flight).</summary>
    public bool IsExecuting
    {
        get => _isExecuting;
        set
        {
            if (SetField(ref _isExecuting, value))
            {
                OnPropertyChanged(nameof(CanExecute));
                ExecuteCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>Whether execution has completed and produced a result.</summary>
    public bool HasResult => ExecutionResult != null;

    /// <summary>Whether the plan has any permitted commands to execute (pre-execution gate).</summary>
    public bool CanExecute => !IsExecuting && !IsCompleted && CommandsPermitted > 0;

    private async Task ExecuteCoreAsync()
    {
        if (!CanExecute)
            return;

        IsExecuting = true;
        try
        {
            StatusMessage = "Executing remediation plan...";
            ExecutionResult = await _executeAsync();
            IsCompleted = true;
        }
        finally
        {
            IsExecuting = false;
        }

        if (ExecutionResult is null)
        {
            StatusMessage = "Execution did not produce a result.";
            return;
        }

        StatusMessage = ExecutionResult.AllSucceeded && ExecutionResult.TotalCommandsExecuted > 0
            ? "✅ All permitted remediation commands completed successfully."
            : ExecutionResult.AllSucceeded
                ? "ℹ️ No remediation commands were executed (all skipped by policy or validation)."
                : "⚠️ Some remediation commands failed. Review the output above.";
    }
}
