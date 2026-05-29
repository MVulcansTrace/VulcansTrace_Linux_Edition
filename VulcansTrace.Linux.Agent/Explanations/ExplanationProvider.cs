using System.Reflection;
using System.Text.RegularExpressions;

namespace VulcansTrace.Linux.Agent.Explanations;

/// <summary>
/// Loads embedded markdown templates and fills variable placeholders.
/// </summary>
public sealed class ExplanationProvider : IExplanationProvider
{
    private readonly Dictionary<string, string> _templates;
    private static readonly Regex VariablePattern = new(@"\{\{\s*(\w+)\s*\}\}", RegexOptions.Compiled);

    /// <summary>
    /// Initializes the provider by scanning embedded resources for .md templates.
    /// </summary>
    public ExplanationProvider()
    {
        _templates = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        LoadEmbeddedTemplates();
    }

    /// <inheritdoc />
    public string GetExplanation(string key, IReadOnlyDictionary<string, string> variables)
    {
        if (!_templates.TryGetValue(key, out var template))
        {
            return $"No explanation available for rule **{key}**.";
        }

        return VariablePattern.Replace(template, match =>
        {
            var varName = match.Groups[1].Value;
            return variables.TryGetValue(varName, out var value) ? value : $"[{varName}]";
        });
    }

    private void LoadEmbeddedTemplates()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceNames = assembly.GetManifestResourceNames();

        foreach (var resourceName in resourceNames)
        {
            if (!resourceName.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
                continue;

            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null) continue;

            using var reader = new StreamReader(stream);
            var content = reader.ReadToEnd();

            // Key from filename: "VulcansTrace.Linux.Agent.Explanations.Templates.firewall.md" -> "firewall"
            var fileName = resourceName.Split('.')[^2];
            _templates[fileName] = content;

            // Also parse individual rule keys if templates contain section headers like "## FW-001"
            ParseSectionKeys(content);
        }
    }

    private void ParseSectionKeys(string content)
    {
        var lines = content.Split('\n');
        string? currentKey = null;
        var currentLines = new List<string>();

        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd();
            if (line.StartsWith("## "))
            {
                if (currentKey != null)
                {
                    _templates[currentKey] = string.Join("\n", currentLines).Trim();
                }

                currentKey = line.Substring(3).Trim();
                currentLines.Clear();
            }
            else if (currentKey != null)
            {
                currentLines.Add(line);
            }
        }

        if (currentKey != null)
        {
            _templates[currentKey] = string.Join("\n", currentLines).Trim();
        }
    }
}
