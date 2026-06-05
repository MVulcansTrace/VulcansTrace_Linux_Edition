namespace VulcansTrace.Linux.Agent.Scanners;

/// <summary>
/// Abstracts the YARA rule compiler and scanner so the agent can be tested
/// without a live <c>libyara</c> native dependency.
/// </summary>
internal interface IYaraEngine : IDisposable
{
    /// <summary>
    /// True when the underlying YARA library can be loaded.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Compiles the provided YARA rule text.
    /// </summary>
    /// <param name="rulesText">YARA rules to compile.</param>
    /// <param name="namespace">Optional namespace for the rules.</param>
    /// <returns>A list of human-readable compile errors. Empty when compilation succeeds.</returns>
    IReadOnlyList<string> CompileRules(string rulesText, string? @namespace = null);

    /// <summary>
    /// Scans a file with the previously compiled rules.
    /// </summary>
    /// <param name="path">Absolute path to the file to scan.</param>
    /// <param name="timeoutSeconds">Maximum time the scan may run.</param>
    /// <param name="cancellationToken">Token that can abort the scan between rules.</param>
    /// <returns>Details for each matching rule.</returns>
    IReadOnlyList<YaraMatchDetail> ScanFile(string path, int timeoutSeconds = 30, CancellationToken cancellationToken = default);
}
