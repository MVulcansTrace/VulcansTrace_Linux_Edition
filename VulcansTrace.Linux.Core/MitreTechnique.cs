namespace VulcansTrace.Linux.Core;

/// <summary>
/// Maps a security finding or rule to a specific MITRE ATT&CK technique.
/// </summary>
public sealed record MitreTechnique
{
    private string _techniqueId = string.Empty;

    /// <summary>MITRE ATT&CK technique identifier, e.g. T1071.001.</summary>
    public required string TechniqueId
    {
        get => _techniqueId;
        init
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("TechniqueId cannot be empty or whitespace.", nameof(TechniqueId));
            _techniqueId = value;
        }
    }

    /// <summary>Human-readable technique name, e.g. "Application Layer Protocol: Web Protocols".</summary>
    public string TechniqueName { get; init; } = string.Empty;

    /// <summary>The MITRE ATT&CK tactic this technique belongs to, e.g. "Command and Control".</summary>
    public string Tactic { get; init; } = string.Empty;

    /// <summary>Short rationale explaining why this technique is relevant to the finding or rule.</summary>
    public string WhyItMatters { get; init; } = string.Empty;
}
