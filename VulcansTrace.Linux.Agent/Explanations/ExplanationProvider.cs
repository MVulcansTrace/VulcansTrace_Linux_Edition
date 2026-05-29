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

        return FillVariables(template, variables);
    }

    /// <inheritdoc />
    public StructuredExplanation GetStructuredExplanation(string key, IReadOnlyDictionary<string, string> variables)
    {
        if (!_templates.TryGetValue(key, out var template))
        {
            return new StructuredExplanation
            {
                WhatWasFound = $"No explanation available for rule **{key}**."
            };
        }

        var filled = FillVariables(template, variables);
        var sections = ParseSections(filled);

        return BuildStructuredExplanation(sections);
    }

    private static string FillVariables(string template, IReadOnlyDictionary<string, string> variables)
    {
        return VariablePattern.Replace(template, match =>
        {
            var varName = match.Groups[1].Value;
            return variables.TryGetValue(varName, out var value) ? value : $"[{varName}]";
        });
    }

    private static Dictionary<string, string> ParseSections(string content)
    {
        var sections = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = content.Split('\n');
        string? currentKey = null;
        var currentLines = new List<string>();

        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd();
            // Match bold section headers like "**What we found:** rest of line"
            if (line.StartsWith("**") && line.Contains(":**"))
            {
                var headerEnd = line.IndexOf(":**");
                var key = line.Substring(2, headerEnd - 2).Trim();

                if (currentKey != null)
                {
                    sections[currentKey] = string.Join("\n", currentLines).Trim();
                }

                currentKey = key;
                currentLines.Clear();

                // Any content after ":**" on the same line belongs to this section
                var remainder = line.Substring(headerEnd + 3).TrimStart();
                if (!string.IsNullOrEmpty(remainder))
                {
                    currentLines.Add(remainder);
                }
            }
            else if (currentKey != null)
            {
                currentLines.Add(line);
            }
        }

        if (currentKey != null)
        {
            sections[currentKey] = string.Join("\n", currentLines).Trim();
        }

        return sections;
    }

    /// <inheritdoc />
    public StructuredExplanation ParseStructuredFromText(string text)
    {
        var sections = ParseSections(text);

        return BuildStructuredExplanation(sections);
    }

    private static StructuredExplanation BuildStructuredExplanation(Dictionary<string, string> sections)
    {
        var confidence = GetSection(sections, "Risk level", "Confidence");
        var caveats = GetSection(sections, "Caveats", "Notes");
        var combinedConfidenceCaveat = GetSection(sections, "Confidence / caveat");

        if (!string.IsNullOrWhiteSpace(combinedConfidenceCaveat))
        {
            if (string.IsNullOrWhiteSpace(confidence) && TrySplitConfidenceCaveat(combinedConfidenceCaveat, out var splitConfidence, out var splitCaveat))
            {
                confidence = splitConfidence;
                if (string.IsNullOrWhiteSpace(caveats))
                {
                    caveats = splitCaveat;
                }
            }
            else if (string.IsNullOrWhiteSpace(confidence) && string.IsNullOrWhiteSpace(caveats))
            {
                confidence = combinedConfidenceCaveat;
            }
            else if (string.IsNullOrWhiteSpace(caveats) && !combinedConfidenceCaveat.Equals(confidence, StringComparison.OrdinalIgnoreCase))
            {
                caveats = combinedConfidenceCaveat;
            }
        }

        return new StructuredExplanation
        {
            WhatWasFound = GetSection(sections, "What we found", "What was found"),
            WhyItMatters = GetSection(sections, "Why this matters"),
            HowToVerify = GetSection(sections, "How to verify", "How to check"),
            SuggestedNextAction = GetSection(sections, "Suggested next action", "How to fix it", "Next steps"),
            Confidence = confidence,
            Caveats = caveats
        };
    }

    private static bool TrySplitConfidenceCaveat(string value, out string confidence, out string caveat)
    {
        var separators = new[] { " — ", " – ", " - " };
        foreach (var separator in separators)
        {
            var index = value.IndexOf(separator, StringComparison.Ordinal);
            if (index <= 0)
                continue;

            confidence = value[..index].Trim();
            caveat = value[(index + separator.Length)..].Trim();
            return !string.IsNullOrWhiteSpace(confidence) && !string.IsNullOrWhiteSpace(caveat);
        }

        confidence = string.Empty;
        caveat = string.Empty;
        return false;
    }

    private static string GetSection(Dictionary<string, string> sections, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (sections.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
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
