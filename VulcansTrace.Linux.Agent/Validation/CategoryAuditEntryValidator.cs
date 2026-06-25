using FluentValidation;
using VulcansTrace.Linux.Agent.Memory;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="CategoryAuditEntry"/>.
/// </summary>
public sealed class CategoryAuditEntryValidator : AbstractValidator<CategoryAuditEntry>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CategoryAuditEntryValidator"/> class.
    /// </summary>
    public CategoryAuditEntryValidator()
    {
        RuleFor(x => x.Category).NotEmpty();
        RuleFor(x => x.UtcTimestamp).MustBeUtc();
    }
}
