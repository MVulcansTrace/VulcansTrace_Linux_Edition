namespace VulcansTrace.Linux.Core.Security;

/// <summary>
/// Represents a SHA-256 hash of a file discovered during scanning.
/// </summary>
public sealed record FileHashEntry
{
    /// <summary>Absolute path to the file.</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Hex-encoded hash value.</summary>
    public string Hash { get; init; } = string.Empty;

    /// <summary>Hash algorithm used (e.g. "SHA-256").</summary>
    public string Algorithm { get; init; } = "SHA-256";
}
