using FluentValidation;
using VulcansTrace.Linux.Agent.Dialogue;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="DialogueTurn"/>.
/// </summary>
public sealed class DialogueTurnValidator : AbstractValidator<DialogueTurn>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DialogueTurnValidator"/> class.
    /// </summary>
    public DialogueTurnValidator()
    {
        RuleFor(x => x.RawQuery).NotEmpty();
        RuleFor(x => x.TimestampUtc).MustBeUtc();
    }
}
