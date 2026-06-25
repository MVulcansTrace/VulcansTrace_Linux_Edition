using System.Text.Json;
using System.Text.Json.Serialization;

namespace VulcansTrace.Linux.Agent.Persistence;

/// <summary>
/// Provides reusable, immutable <see cref="JsonSerializerOptions"/> configurations for
/// JSON-backed stores. Using these defaults eliminates duplicate inline option declarations.
/// </summary>
internal static class JsonOptionsProvider
{
    /// <summary>
    /// Default agent options: indented JSON with standard PascalCase naming.
    /// </summary>
    public static JsonSerializerOptions Default { get; } = new()
    {
        WriteIndented = true
    };

    /// <summary>
    /// Indented JSON with camelCase property naming and string-based enum serialization.
    /// </summary>
    public static JsonSerializerOptions CamelCaseEnums { get; } = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };
}
