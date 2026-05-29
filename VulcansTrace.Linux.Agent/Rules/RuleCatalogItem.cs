using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// A read-only description of a single security rule for display in the rule catalog.
/// </summary>
public sealed record RuleCatalogItem
{
    /// <summary>Unique rule identifier (e.g., "FW-001").</summary>
    public required string Id { get; init; }

    /// <summary>Human-readable rule category (e.g., "Firewall").</summary>
    public required string Category { get; init; }

    /// <summary>Brief description of what this rule checks.</summary>
    public required string Description { get; init; }

    /// <summary>Detailed description of what this rule checks.</summary>
    public required string WhatItChecks { get; init; }

    /// <summary>Maximum severity this rule can produce when it fails.</summary>
    public required Severity Severity { get; init; }

    /// <summary>Data sources / commands this rule relies on.</summary>
    public required IReadOnlyList<string> SupportedDataSources { get; init; }

    /// <summary>The explanation template key used by this rule.</summary>
    public required string ExplanationKey { get; init; }
}
