namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Identifies a pre-defined safe attack-replay scenario for demonstration and testing.
/// </summary>
public enum DemoScenario
{
    /// <summary>Existing probabilistic mix of port scans, beaconing, and floods.</summary>
    RandomMix,

    /// <summary>Periodic beaconing to a single destination — triggers BeaconingDetector.</summary>
    C2Beaconing,

    /// <summary>High-volume burst targeted at TCP/22 — triggers FloodDetector.</summary>
    SshBruteforce,

    /// <summary>Rapid access attempts across multiple admin ports — triggers PrivilegeEscalationDetector.</summary>
    PrivilegeEscalation
}

/// <summary>
/// Human-readable names used in the Avalonia UI dropdown and CLI help text.
/// </summary>
public static class DemoScenarioNames
{
    public const string RandomMix = "Demo: Random Mix";
    public const string C2Beaconing = "Demo: C2 Beaconing";
    public const string SshBruteforce = "Demo: SSH Brute Force";
    public const string PrivilegeEscalation = "Demo: Privilege Escalation";

    /// <summary>
    /// Maps a display name back to a <see cref="DemoScenario"/>.
    /// Throws <see cref="ArgumentException"/> for unknown names.
    /// </summary>
    public static DemoScenario FromDisplayName(string displayName)
    {
        return displayName switch
        {
            RandomMix => DemoScenario.RandomMix,
            C2Beaconing => DemoScenario.C2Beaconing,
            SshBruteforce => DemoScenario.SshBruteforce,
            PrivilegeEscalation => DemoScenario.PrivilegeEscalation,
            _ => throw new ArgumentException($"Unknown demo scenario: '{displayName}'", nameof(displayName))
        };
    }

    /// <summary>
    /// Maps a <see cref="DemoScenario"/> to its CLI keyword (kebab-case).
    /// </summary>
    public static string ToCliKeyword(DemoScenario scenario)
    {
        return scenario switch
        {
            DemoScenario.RandomMix => "random-mix",
            DemoScenario.C2Beaconing => "c2-beaconing",
            DemoScenario.SshBruteforce => "ssh-bruteforce",
            DemoScenario.PrivilegeEscalation => "privilege-escalation",
            _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, null)
        };
    }

    /// <summary>
    /// Parses a CLI keyword back to a <see cref="DemoScenario"/>.
    /// Throws <see cref="ArgumentException"/> for unknown keywords.
    /// </summary>
    public static DemoScenario FromCliKeyword(string keyword)
    {
        return keyword switch
        {
            "random-mix" => DemoScenario.RandomMix,
            "c2-beaconing" => DemoScenario.C2Beaconing,
            "ssh-bruteforce" => DemoScenario.SshBruteforce,
            "privilege-escalation" => DemoScenario.PrivilegeEscalation,
            _ => throw new ArgumentException($"Unknown demo scenario keyword: '{keyword}'", nameof(keyword))
        };
    }

    /// <summary>
    /// Gets a short description suitable for CLI help text.
    /// </summary>
    public static string GetDescription(DemoScenario scenario)
    {
        return scenario switch
        {
            DemoScenario.RandomMix => "Random mix of port scans, beaconing, and floods (legacy synthetic source).",
            DemoScenario.C2Beaconing => "Periodic beaconing to a single destination. Recommended: --duration 150 --intensity High.",
            DemoScenario.SshBruteforce => "High-volume SYN flood targeted at port 22. Recommended: --duration 60 --intensity High.",
            DemoScenario.PrivilegeEscalation => "Rapid sweep across admin ports (22, 3389, 5900, ...). Recommended: --duration 60 --intensity High.",
            _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, null)
        };
    }
}
