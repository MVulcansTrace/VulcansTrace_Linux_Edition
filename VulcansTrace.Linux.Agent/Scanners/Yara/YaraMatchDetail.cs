namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Internal detail returned by the YARA engine for a single rule match.
/// </summary>
internal sealed record YaraMatchDetail
{
    public string RuleIdentifier { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
}
