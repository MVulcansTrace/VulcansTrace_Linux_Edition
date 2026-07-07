using FluentValidation;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates a <see cref="Messages.PinnedMessage"/> before it is persisted or after it is loaded.
/// </summary>
public sealed class PinnedMessageValidator : AbstractValidator<Messages.PinnedMessage>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PinnedMessageValidator"/> class.
    /// </summary>
    public PinnedMessageValidator()
    {
        RuleFor(x => x.MessageId).NotEmpty().MaximumLength(128);
        RuleFor(x => x.Text).NotEmpty().MaximumLength(100_000);
        RuleFor(x => x.Details).MaximumLength(100_000);
        RuleFor(x => x.Category).MaximumLength(200);
        RuleFor(x => x.Severity).MaximumLength(50);
        RuleFor(x => x.Notes).MaximumLength(4000);
        RuleFor(x => x.TimestampUtc).MustBeUtc();
        RuleFor(x => x.PinnedAtUtc).MustBeUtc();
    }
}
