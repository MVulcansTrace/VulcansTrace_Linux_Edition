using FluentValidation;
using VulcansTrace.Linux.Agent.Memory;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates an <see cref="AgentMemorySnapshot"/> before persistence or after loading.
/// </summary>
public sealed class AgentMemorySnapshotValidator : AbstractValidator<AgentMemorySnapshot>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AgentMemorySnapshotValidator"/> class.
    /// </summary>
    public AgentMemorySnapshotValidator()
    {
        RuleFor(x => x.UtcTimestamp).MustBeUtc();
        RuleFor(x => x.RecentTurns).NotNull();
        RuleFor(x => x.CheckedCategories).NotNull();
        RuleFor(x => x.RuleHistory).NotNull();

        RuleForEach(x => x.RecentTurns)
            .SetValidator(new DialogueTurnValidator());

        RuleForEach(x => x.CheckedCategories)
            .SetValidator(new CategoryAuditEntryValidator());

        RuleFor(x => x.RuleHistory)
            .Must(dict => dict.All(kvp => !string.IsNullOrWhiteSpace(kvp.Key)))
            .WithMessage("RuleHistory must not contain empty rule IDs.");

        RuleForEach(x => x.RuleHistory.Values)
            .SetValidator(new RuleMemoryEntryValidator());
    }
}
