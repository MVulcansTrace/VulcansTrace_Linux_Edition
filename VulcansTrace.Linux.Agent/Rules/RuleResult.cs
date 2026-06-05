using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// Result of evaluating a single security rule against scan data.
/// </summary>
public sealed record RuleResult
{
    /// <summary>The rule identifier that produced this result.</summary>
    public required string RuleId { get; init; }

    /// <summary>The rule category.</summary>
    public required string Category { get; init; }

    /// <summary>Whether the rule passed (true) or failed (false).</summary>
    public required bool Passed { get; init; }

    /// <summary>Detailed status of the rule evaluation (defaults from <see cref="Passed"/>).</summary>
    public RuleStatus Status
    {
        get => _status ?? (Passed ? RuleStatus.Passed : RuleStatus.Failed);
        init => _status = value;
    }

    private RuleStatus? _status;

    /// <summary>Severity if the rule failed; ignored when <see cref="Passed"/> is true.</summary>
    public Severity Severity { get; init; } = Severity.Info;

    /// <summary>Key used to look up the explanation template.</summary>
    public required string ExplanationKey { get; init; }

    /// <summary>Variables to substitute into the explanation template.</summary>
    public IReadOnlyDictionary<string, string> Variables { get; init; } = new Dictionary<string, string>();

    /// <summary>Human-readable description of what was checked.</summary>
    public required string Description { get; init; }

    /// <summary>Target of the rule evaluation (port, service, interface, etc.).</summary>
    public string Target { get; init; } = string.Empty;

    /// <summary>CIS Benchmark controls this rule maps to (may be empty).</summary>
    public IReadOnlyList<CisBenchmarkMapping> CisMappings { get; init; } = Array.Empty<CisBenchmarkMapping>();

    /// <summary>MITRE ATT&CK techniques this rule maps to (may be empty).</summary>
    public IReadOnlyList<MitreTechnique> MitreTechniques { get; init; } = Array.Empty<MitreTechnique>();

    /// <summary>Creates a passing result.</summary>
    public static RuleResult Pass(string ruleId, string category, string explanationKey, string description, IReadOnlyList<CisBenchmarkMapping>? cisMappings = null, IReadOnlyList<MitreTechnique>? mitreTechniques = null, IReadOnlyDictionary<string, string>? variables = null) =>
        new()
        {
            RuleId = ruleId,
            Category = category,
            Passed = true,
            ExplanationKey = explanationKey,
            Description = description,
            Variables = variables ?? new Dictionary<string, string>(),
            CisMappings = cisMappings ?? Array.Empty<CisBenchmarkMapping>(),
            MitreTechniques = mitreTechniques ?? Array.Empty<MitreTechnique>()
        };

    /// <summary>Creates a failing result.</summary>
    public static RuleResult Fail(string ruleId, string category, string explanationKey, string description, Severity severity, string target, IReadOnlyDictionary<string, string>? variables = null, IReadOnlyList<CisBenchmarkMapping>? cisMappings = null, IReadOnlyList<MitreTechnique>? mitreTechniques = null) =>
        new()
        {
            RuleId = ruleId,
            Category = category,
            Passed = false,
            Severity = severity,
            ExplanationKey = explanationKey,
            Description = description,
            Target = target,
            Variables = variables ?? new Dictionary<string, string>(),
            CisMappings = cisMappings ?? Array.Empty<CisBenchmarkMapping>(),
            MitreTechniques = mitreTechniques ?? Array.Empty<MitreTechnique>()
        };

    /// <summary>Creates a crashed result.</summary>
    public static RuleResult Crash(string ruleId, string category, string description, IReadOnlyList<CisBenchmarkMapping>? cisMappings = null, IReadOnlyList<MitreTechnique>? mitreTechniques = null) =>
        new()
        {
            RuleId = ruleId,
            Category = category,
            Passed = false,
            Status = RuleStatus.Crashed,
            ExplanationKey = ruleId,
            Description = description,
            CisMappings = cisMappings ?? Array.Empty<CisBenchmarkMapping>(),
            MitreTechniques = mitreTechniques ?? Array.Empty<MitreTechnique>()
        };

    /// <summary>Creates a not-applicable result (data source missing or unreadable).</summary>
    public static RuleResult NotApplicable(string ruleId, string category, string explanationKey, string description, IReadOnlyList<CisBenchmarkMapping>? cisMappings = null, IReadOnlyList<MitreTechnique>? mitreTechniques = null) =>
        new()
        {
            RuleId = ruleId,
            Category = category,
            Passed = true,
            Status = RuleStatus.NotApplicable,
            ExplanationKey = explanationKey,
            Description = description,
            CisMappings = cisMappings ?? Array.Empty<CisBenchmarkMapping>(),
            MitreTechniques = mitreTechniques ?? Array.Empty<MitreTechnique>()
        };
}
