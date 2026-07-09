using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Evidence.Formatters;
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
    private string _statusMessage = "";
    private LogDiffResult? _result;

    private readonly IDialogService _dialogService;
    private readonly LogDiffMarkdownFormatter _markdownFormatter;
    private readonly LogDiffHtmlFormatter _htmlFormatter;

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

    /// <summary>Gets the status message from the last export attempt.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set
        {
            if (SetField(ref _statusMessage, value))
            {
                OnPropertyChanged(nameof(HasStatusMessage));
            }
        }
    }

    /// <summary>Gets whether there is a status message to display.</summary>
    public bool HasStatusMessage => !string.IsNullOrWhiteSpace(_statusMessage);

    /// <summary>Gets the command to export the diff as HTML.</summary>
    public AsyncRelayCommand ExportHtmlCommand { get; }

    /// <summary>Gets the command to export the diff as Markdown.</summary>
    public AsyncRelayCommand ExportMarkdownCommand { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="LogDiffViewModel"/> class for design-time use.
    /// </summary>
    public LogDiffViewModel()
        : this(new NoOpDialogService())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LogDiffViewModel"/> class.
    /// </summary>
    /// <param name="dialogService">Dialog service for save prompts and messages.</param>
    /// <param name="markdownFormatter">Optional markdown formatter.</param>
    /// <param name="htmlFormatter">Optional HTML formatter.</param>
    public LogDiffViewModel(
        IDialogService dialogService,
        LogDiffMarkdownFormatter? markdownFormatter = null,
        LogDiffHtmlFormatter? htmlFormatter = null)
    {
        _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
        _markdownFormatter = markdownFormatter ?? new LogDiffMarkdownFormatter();
        _htmlFormatter = htmlFormatter ?? new LogDiffHtmlFormatter();

        ExportHtmlCommand = new AsyncRelayCommand(
            async _ => await ExportHtmlAsync(),
            _ => _result != null,
            ex => SetStatus($"Export failed: {ex.Message}"));

        ExportMarkdownCommand = new AsyncRelayCommand(
            async _ => await ExportMarkdownAsync(),
            _ => _result != null,
            ex => SetStatus($"Export failed: {ex.Message}"));
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
        _result = result;
        StatusMessage = string.Empty;
        ExportHtmlCommand.RaiseCanExecuteChanged();
        ExportMarkdownCommand.RaiseCanExecuteChanged();
    }

    private async Task ExportHtmlAsync()
    {
        if (_result == null)
        {
            SetStatus("No diff result is loaded.");
            return;
        }

        var path = await _dialogService.ShowSaveFileDialogAsync(
            "Save Log Diff HTML Report",
            "HTML files (*.html)|*.html|All files (*.*)|*.*",
            $"log-diff-{DateTime.UtcNow:yyyyMMdd-HHmmss}.html");

        if (string.IsNullOrWhiteSpace(path))
        {
            SetStatus("Export cancelled.");
            return;
        }

        var html = _htmlFormatter.ToHtml(_result, _result.BaselineLabel, _result.IncidentLabel);
        await File.WriteAllTextAsync(path, html);
        SetStatus($"HTML report saved to {path}");
        _dialogService.ShowMessage("HTML report saved.", "Log Diff Export");
    }

    private async Task ExportMarkdownAsync()
    {
        if (_result == null)
        {
            SetStatus("No diff result is loaded.");
            return;
        }

        var path = await _dialogService.ShowSaveFileDialogAsync(
            "Save Log Diff Markdown Report",
            "Markdown files (*.md)|*.md|All files (*.*)|*.*",
            $"log-diff-{DateTime.UtcNow:yyyyMMdd-HHmmss}.md");

        if (string.IsNullOrWhiteSpace(path))
        {
            SetStatus("Export cancelled.");
            return;
        }

        var markdown = _markdownFormatter.ToMarkdown(_result, _result.BaselineLabel, _result.IncidentLabel);
        await File.WriteAllTextAsync(path, markdown);
        SetStatus($"Markdown report saved to {path}");
        _dialogService.ShowMessage("Markdown report saved.", "Log Diff Export");
    }

    private void SetStatus(string message)
    {
        StatusMessage = message;
    }

    private sealed class NoOpDialogService : IDialogService
    {
        public void ShowMessage(string message, string title) { }
        public void ShowError(string message, string title) { }
        public Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName) => Task.FromResult<string?>(null);
        public Task<string?> ShowOpenFileDialogAsync(string title, string filter) => Task.FromResult<string?>(null);
        public Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "") => Task.FromResult<string?>(null);
        public Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel) => Task.FromResult<bool?>(null);
        public Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0) => Task.FromResult<int?>(null);
    }
}
