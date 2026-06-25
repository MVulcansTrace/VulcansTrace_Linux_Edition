using System.Net;
using FluentValidation;
using VulcansTrace.Linux.Agent.ThreatIntel;
using VulcansTrace.Linux.Core.ThreatIntel;

namespace VulcansTrace.Linux.Agent.Validation;

/// <summary>
/// Validates an <see cref="IocEntry"/> before persistence or after loading.
/// </summary>
public sealed class IocEntryValidator : AbstractValidator<IocEntry>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IocEntryValidator"/> class.
    /// </summary>
    public IocEntryValidator()
    {
        RuleFor(x => x.Value).NotEmpty();
        RuleFor(x => x.ThreatScore).InclusiveBetween(0, 100);
        RuleFor(x => x.Source).NotEmpty();
        RuleFor(x => x.ImportedAt).MustBeUtc();

        RuleFor(x => x.Value)
            .Must((entry, value) => BeValidForType(entry, value!))
            .When(x => !string.IsNullOrWhiteSpace(x.Value))
            .WithMessage((entry, value) => $"Value '{value}' does not match the expected format for IOC type {entry.Type}.");
    }

    private static bool BeValidForType(IocEntry entry, string value)
    {
        return entry.Type switch
        {
            IocType.IPv4 => IPAddress.TryParse(value, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork,
            IocType.IPv6 => IPAddress.TryParse(value, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6,
            IocType.Port => IocValueValidator.IsValidPort(value),
            IocType.FileHash => IocValueValidator.IsValidHash(value),
            _ => true
        };
    }
}
