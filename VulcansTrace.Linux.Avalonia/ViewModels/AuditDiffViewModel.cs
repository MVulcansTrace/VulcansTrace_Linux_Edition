using System.Collections.ObjectModel;
using VulcansTrace.Linux.Agent.Reports;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for displaying an audit diff.
/// </summary>
public sealed class AuditDiffViewModel : ViewModelBase
{
    private string _summary = "";
    private string _narrative = "";
    private int _newCount;
    private int _resolvedCount;
    private int _worsenedCount;
    private int _improvedCount;
    private int _confidenceChangedCount;

    /// <summary>Gets the collection of new findings.</summary>
    public ObservableCollection<DiffFinding> NewFindings { get; } = new();

    /// <summary>Gets the collection of resolved findings.</summary>
    public ObservableCollection<DiffFinding> ResolvedFindings { get; } = new();

    /// <summary>Gets the collection of worsened findings.</summary>
    public ObservableCollection<SeverityChangeFinding> WorsenedFindings { get; } = new();

    /// <summary>Gets the collection of improved findings.</summary>
    public ObservableCollection<SeverityChangeFinding> ImprovedFindings { get; } = new();

    /// <summary>Gets the collection of findings with changed confidence.</summary>
    public ObservableCollection<ConfidenceChangeFinding> ConfidenceChangedFindings { get; } = new();

    /// <summary>Gets the diff summary text.</summary>
    public string Summary
    {
        get => _summary;
        private set => SetField(ref _summary, value);
    }

    /// <summary>Gets the deterministic diff narrative.</summary>
    public string Narrative
    {
        get => _narrative;
        private set => SetField(ref _narrative, value);
    }

    /// <summary>Gets the count of new findings.</summary>
    public int NewCount
    {
        get => _newCount;
        private set => SetField(ref _newCount, value);
    }

    /// <summary>Gets the count of resolved findings.</summary>
    public int ResolvedCount
    {
        get => _resolvedCount;
        private set => SetField(ref _resolvedCount, value);
    }

    /// <summary>Gets the count of worsened findings.</summary>
    public int WorsenedCount
    {
        get => _worsenedCount;
        private set => SetField(ref _worsenedCount, value);
    }

    /// <summary>Gets the count of improved findings.</summary>
    public int ImprovedCount
    {
        get => _improvedCount;
        private set => SetField(ref _improvedCount, value);
    }

    /// <summary>Gets the count of findings whose confidence changed.</summary>
    public int ConfidenceChangedCount
    {
        get => _confidenceChangedCount;
        private set => SetField(ref _confidenceChangedCount, value);
    }

    /// <summary>
    /// Loads an <see cref="AuditDiff"/> into the view model.
    /// </summary>
    /// <param name="diff">The diff to display.</param>
    public void LoadDiff(AuditDiff diff)
    {
        NewFindings.Clear();
        ResolvedFindings.Clear();
        WorsenedFindings.Clear();
        ImprovedFindings.Clear();
        ConfidenceChangedFindings.Clear();

        foreach (var f in diff.NewFindings) NewFindings.Add(f);
        foreach (var f in diff.ResolvedFindings) ResolvedFindings.Add(f);
        foreach (var f in diff.WorsenedFindings) WorsenedFindings.Add(f);
        foreach (var f in diff.ImprovedFindings) ImprovedFindings.Add(f);
        foreach (var f in diff.ConfidenceChangedFindings) ConfidenceChangedFindings.Add(f);

        Summary = diff.Summary;
        Narrative = diff.Narrative;
        NewCount = diff.NewFindings.Count;
        ResolvedCount = diff.ResolvedFindings.Count;
        WorsenedCount = diff.WorsenedFindings.Count;
        ImprovedCount = diff.ImprovedFindings.Count;
        ConfidenceChangedCount = diff.ConfidenceChangedFindings.Count;
    }
}
