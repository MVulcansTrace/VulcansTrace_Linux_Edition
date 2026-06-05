using System.Collections.ObjectModel;
using VulcansTrace.Linux.Engine.LogDiff;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for displaying a log diff result.
/// </summary>
public sealed class LogDiffViewModel : ViewModelBase
{
    private string _narrative = "";
    private string _summary = "";
    private int _addedCount;
    private int _removedCount;
    private int _changedCount;
    private int _unchangedCount;
    private int _addedFindingsCount;
    private int _removedFindingsCount;
    private int _changedFindingsCount;

    /// <summary>Gets the collection of diffed connection-pattern events.</summary>
    public ObservableCollection<DiffEvent> Events { get; } = new();

    /// <summary>Gets the collection of diffed findings.</summary>
    public ObservableCollection<DiffFinding> Findings { get; } = new();

    /// <summary>Gets the deterministic diff narrative.</summary>
    public string Narrative
    {
        get => _narrative;
        private set => SetField(ref _narrative, value);
    }

    /// <summary>Gets the compact diff summary.</summary>
    public string Summary
    {
        get => _summary;
        private set => SetField(ref _summary, value);
    }

    /// <summary>Gets the count of Added connection patterns.</summary>
    public int AddedCount
    {
        get => _addedCount;
        private set => SetField(ref _addedCount, value);
    }

    /// <summary>Gets the count of Removed connection patterns.</summary>
    public int RemovedCount
    {
        get => _removedCount;
        private set => SetField(ref _removedCount, value);
    }

    /// <summary>Gets the count of Changed connection patterns.</summary>
    public int ChangedCount
    {
        get => _changedCount;
        private set => SetField(ref _changedCount, value);
    }

    /// <summary>Gets the count of Unchanged connection patterns.</summary>
    public int UnchangedCount
    {
        get => _unchangedCount;
        private set => SetField(ref _unchangedCount, value);
    }

    /// <summary>Gets the count of Added findings.</summary>
    public int AddedFindingsCount
    {
        get => _addedFindingsCount;
        private set => SetField(ref _addedFindingsCount, value);
    }

    /// <summary>Gets the count of Removed findings.</summary>
    public int RemovedFindingsCount
    {
        get => _removedFindingsCount;
        private set => SetField(ref _removedFindingsCount, value);
    }

    /// <summary>Gets the count of Changed findings.</summary>
    public int ChangedFindingsCount
    {
        get => _changedFindingsCount;
        private set => SetField(ref _changedFindingsCount, value);
    }

    /// <summary>
    /// Loads a <see cref="LogDiffResult"/> into the view model.
    /// </summary>
    /// <param name="result">The diff to display.</param>
    public void LoadDiff(LogDiffResult result)
    {
        Events.Clear();
        Findings.Clear();

        foreach (var e in result.Events) Events.Add(e);
        foreach (var f in result.Findings) Findings.Add(f);

        Narrative = result.Narrative;
        Summary = result.Summary;
        AddedCount = result.AddedCount;
        RemovedCount = result.RemovedCount;
        ChangedCount = result.ChangedCount;
        UnchangedCount = result.UnchangedCount;
        AddedFindingsCount = result.AddedFindingsCount;
        RemovedFindingsCount = result.RemovedFindingsCount;
        ChangedFindingsCount = result.ChangedFindingsCount;
    }
}
