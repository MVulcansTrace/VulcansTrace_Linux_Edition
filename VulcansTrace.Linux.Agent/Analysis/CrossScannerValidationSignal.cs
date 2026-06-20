using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Analysis;

/// <summary>
/// How independent scanner data relates to an agent finding.
/// </summary>
internal enum CrossScannerValidationVerdict
{
    Supports,
    Contradicts
}

/// <summary>
/// Describes a single cross-scanner validation signal for a finding.
/// </summary>
internal sealed record CrossScannerValidationSignal
{
    /// <summary>The rule ID that was validated.</summary>
    public string RuleId { get; init; } = string.Empty;

    /// <summary>Whether the independent scanner data supports or contradicts the finding.</summary>
    public CrossScannerValidationVerdict Verdict { get; init; }

    /// <summary>Human-readable name of the validation match.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Source classifier for the evidence signal.</summary>
    public const string SourceName = "CrossScannerValidation";

    /// <summary>Human-readable explanation of which independent sources validated the finding.</summary>
    public string Explanation { get; init; } = string.Empty;

    /// <summary>Converts this validation result into an evidence signal attached to the finding.</summary>
    public EvidenceSignal ToEvidenceSignal() =>
        new()
        {
            Name = $"{Verdict}: {Name}",
            Source = SourceName,
            Explanation = Explanation
        };
}
