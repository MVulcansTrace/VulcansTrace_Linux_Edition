namespace VulcansTrace.Linux.Evidence;

/// <summary>
/// Represents the result of verifying an evidence bundle's integrity.
/// </summary>
public sealed class VerificationResult
{
    /// <summary>Gets whether the evidence bundle passed all integrity checks.</summary>
    public bool IsValid { get; init; }

    /// <summary>Gets the human-readable description of verification outcome.</summary>
    public string Message { get; init; } = string.Empty;

    /// <summary>Gets the list of individual verification issues found (empty when valid).</summary>
    public IReadOnlyList<string> Issues { get; init; } = Array.Empty<string>();

    /// <summary>Creates a successful verification result.</summary>
    public static VerificationResult Valid(string message = "Evidence bundle integrity verified.") =>
        new() { IsValid = true, Message = message };

    /// <summary>Creates a failed verification result with one or more issues.</summary>
    public static VerificationResult Invalid(params string[] issues) =>
        new() { IsValid = false, Message = "Evidence bundle verification failed.", Issues = issues };
}
