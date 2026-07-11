using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Agent.Diagnostics;

/// <summary>
/// Produces the user-facing form of a Doctor result without exposing raw scanner failures.
/// </summary>
public static class DoctorResultSanitizer
{
    /// <summary>
    /// Sanitizes capability details and collapses raw scanner warnings into concise messages.
    /// The returned copy is suitable for terminal, UI, and JSON presentation.
    /// </summary>
    public static DoctorResult SanitizeForDisplay(DoctorResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var capabilities = result.Capabilities
            .Select(capability => capability with
            {
                Detail = ErrorSanitizer.SanitizeOptional(capability.Detail),
                Command = ErrorSanitizer.SanitizeOptional(capability.Command)
            })
            .ToArray();

        var warningLines = result.Warnings
            .SelectMany(warning => (warning ?? string.Empty)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            .ToArray();

        var warnings = warningLines.Length == 0
            ? Array.Empty<string>()
            : new WarningInterpreter()
                .Interpret(AgentIntent.FullAudit, warningLines, capabilities)
                .Select(warning => string.IsNullOrWhiteSpace(warning.Suggestion)
                    ? warning.Message
                    : $"{warning.Message} {warning.Suggestion}")
                .ToArray();

        return result with
        {
            Capabilities = capabilities,
            CapabilityReport = new AgentResultComposer().BuildCapabilityReport(capabilities),
            Warnings = warnings
        };
    }
}
