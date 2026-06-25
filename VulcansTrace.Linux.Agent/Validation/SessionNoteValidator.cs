using FluentValidation;
using VulcansTrace.Linux.Agent.Sessions;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="SessionNote"/>.
/// </summary>
public sealed class SessionNoteValidator : AbstractValidator<SessionNote>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SessionNoteValidator"/> class.
    /// </summary>
    public SessionNoteValidator()
    {
        RuleFor(x => x.Text).NotEmpty();
        RuleFor(x => x.CreatedAtUtc).MustBeUtc();
        RuleFor(x => x.EvidenceLinks).NotNull();
    }
}
