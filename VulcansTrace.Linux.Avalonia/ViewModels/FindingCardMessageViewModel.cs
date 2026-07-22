using System.Windows.Input;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A per-finding card posted inline in the agent thread after an analysis (UI v2
/// Phase 2): severity dot, short description, evidence signals, time range, and
/// Open-in-Findings / Suppress actions. Rendered by its own DataTemplate selected
/// on runtime type. Automation ids carry the rule id as a stable per-rule suffix.
/// </summary>
public sealed class FindingCardMessageViewModel : AgentMessageViewModel
{
    /// <summary>
    /// Initializes a new instance of the <see cref="FindingCardMessageViewModel"/> class.
    /// </summary>
    /// <param name="item">The finding display model to wrap.</param>
    public FindingCardMessageViewModel(FindingItemViewModel item)
    {
        Item = item;
        IdSuffix = string.IsNullOrWhiteSpace(item.RuleId) ? MessageId : item.RuleId;
    }

    /// <summary>Gets the finding display model (severity, rule, evidence, time range).</summary>
    public FindingItemViewModel Item { get; }

    /// <summary>Gets the card header line, e.g. "Critical · Firewall".</summary>
    public string Header => $"{Item.Severity} · {Item.Category}";

    /// <summary>Gets whether the card has evidence signals to show.</summary>
    public bool HasEvidence => !string.IsNullOrWhiteSpace(Item.EvidenceSignalsDisplay);

    /// <summary>Gets the unique accessible name of the card itself.</summary>
    public string CardAccessibleName => $"{Item.RuleId} {Item.Category} finding";

    /// <summary>Gets the stable per-rule suffix used in automation ids.</summary>
    public string IdSuffix { get; }

    /// <summary>Gets the automation id of the card itself.</summary>
    public string CardAutomationId => $"FindingCard{IdSuffix}";

    /// <summary>Gets the automation id of the Open-in-Findings action.</summary>
    public string OpenAutomationId => $"FindingCardOpen{IdSuffix}";

    /// <summary>Gets the automation id of the Suppress action.</summary>
    public string SuppressAutomationId => $"FindingCardSuppress{IdSuffix}";

    /// <summary>Gets the unique accessible name of the Open-in-Findings action.</summary>
    public string OpenAccessibleName => $"Open {Item.RuleId} in Findings";

    /// <summary>Gets the unique accessible name of the Suppress action.</summary>
    public string SuppressAccessibleName => $"Suppress {Item.RuleId}";

    /// <summary>Gets the deep-link command: open the finding in the Findings view, filtered.</summary>
    public ICommand? OpenCommand { get; init; }

    /// <summary>Gets the suppress command for this finding.</summary>
    public ICommand? SuppressCommand { get; init; }
}
