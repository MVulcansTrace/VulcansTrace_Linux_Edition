using VulcansTrace.Linux.Agent.Scanners;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Agent.Rules;

/// <summary>
/// A single security check rule that evaluates live system scan data.
/// </summary>
public interface IRule
{
    /// <summary>Unique rule identifier (e.g., "FW-001").</summary>
    string Id { get; }

    /// <summary>Human-readable rule category (e.g., "Firewall").</summary>
    string Category { get; }

    /// <summary>Brief description of what this rule checks.</summary>
    string Description { get; }

    /// <summary>Human-readable description of what this rule checks in detail.</summary>
    string WhatItChecks { get; }

    /// <summary>Data sources / commands this rule relies on.</summary>
    IReadOnlyList<string> SupportedDataSources { get; }

    /// <summary>
    /// ScanData field names this rule reads BEYOND its own category's primary data source
    /// (e.g. a Network rule that also reads <c>OpenPorts</c>). Declared here so the scanner
    /// that produces each field is guaranteed to run during a targeted audit, keeping scanner
    /// selection derived from rule data dependencies instead of a hand-maintained map — which
    /// prevents the rule from being silently data-starved. Defaults to none (the rule only
    /// needs its category's primary scanner).
    /// </summary>
    IReadOnlyCollection<string> RequiredDataFields => Array.Empty<string>();

    /// <summary>Maximum severity this rule can produce when it fails.</summary>
    Severity Severity { get; }

    /// <summary>CIS Benchmark controls this rule maps to (may be empty).</summary>
    IReadOnlyList<CisBenchmarkMapping> CisMappings => Array.Empty<CisBenchmarkMapping>();

    /// <summary>MITRE ATT&CK techniques this rule maps to (may be empty).</summary>
    IReadOnlyList<MitreTechnique> MitreTechniques => Array.Empty<MitreTechnique>();

    /// <summary>
    /// Evaluates the provided scan data.
    /// </summary>
    /// <param name="data">The aggregated system scan data.</param>
    /// <returns>The result of the evaluation, including pass/fail status and severity.</returns>
    RuleResult Evaluate(ScanData data);
}
