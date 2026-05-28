using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Evidence.Formatters;

/// <summary>
/// Interface for evidence formatters that convert analysis results to specific formats.
/// </summary>
public interface IEvidenceFormatter
{
    /// <summary>
    /// Gets the file extension for the output format (e.g., ".json", ".csv").
    /// </summary>
    string FileExtension { get; }

    /// <summary>
    /// Gets the MIME content type for the output format (e.g., "application/json", "text/csv").
    /// </summary>
    string ContentType { get; }

    /// <summary>
    /// Formats the analysis result into the specific output format.
    /// </summary>
    /// <param name="result">The analysis result to format.</param>
    /// <param name="originalLog">The original log content that was analyzed.</param>
    /// <returns>A string representation of the analysis result in the target format.</returns>
    string Format(AnalysisResult result, string originalLog);
}