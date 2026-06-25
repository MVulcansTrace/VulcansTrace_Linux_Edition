using FluentValidation;
using VulcansTrace.Linux.Agent.Memory;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="RuleMemoryEntry"/>.
/// </summary>
public sealed class RuleMemoryEntryValidator : AbstractValidator<RuleMemoryEntry>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RuleMemoryEntryValidator"/> class.
    /// </summary>
    public RuleMemoryEntryValidator()
    {
        RuleFor(x => x.RuleId).NotEmpty();
        RuleFor(x => x.FirstSeenUtc).MustBeUtc();
        RuleFor(x => x.LastSeenUtc).MustBeUtc();
        RuleFor(x => x.LastRemediationAttemptUtc).MustBeUtcWhenPresent();
        RuleFor(x => x.LastVerifiedFixedUtc).MustBeUtcWhenPresent();
        RuleFor(x => x.SeverityHistory).NotNull();
        RuleFor(x => x.RemediationCycles).NotNull();
    }
}
