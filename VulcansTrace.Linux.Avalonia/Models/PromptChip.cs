namespace VulcansTrace.Linux.Avalonia.Models;

/// <summary>
/// A suggested-prompt chip shown under the hero input in the empty state
/// (UI v2 Phase 3). Clicking fills the input with <see cref="Label"/> — it
/// never auto-sends. The AutomationId keeps each chip individually addressable
/// for the Computer-Use contract.
/// </summary>
public sealed record PromptChip(string Label, string AutomationId);
