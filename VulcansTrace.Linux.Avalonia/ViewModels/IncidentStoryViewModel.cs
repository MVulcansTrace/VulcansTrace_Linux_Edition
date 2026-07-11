using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;
using Avalonia.Platform.Storage;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Evidence.Formatters;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the Incident Story tab, presenting findings as a flowing attack narrative.
/// </summary>
public sealed class IncidentStoryViewModel : ViewModelBase
{
    private readonly IncidentStoryFormatter _formatter = new();

    private bool _hasStory;
    private string _likelyChain = string.Empty;
    private bool _hasCriticalChain;
    private string _markdown = string.Empty;
    private string _copyStatus = string.Empty;
    private bool _hasLoadedTraceMap;

    /// <summary>Gets the ordered beats that make up the attack timeline.</summary>
    public ObservableCollection<StoryBeat> Beats { get; } = new();

    /// <summary>Gets the context-aware recommended responses.</summary>
    public ObservableCollection<string> Recommendations { get; } = new();

    /// <summary>Gets whether a story is currently loaded.</summary>
    public bool HasStory
    {
        get => _hasStory;
        private set => SetField(ref _hasStory, value);
    }

    /// <summary>Gets whether a Trace Map result has been loaded into the story view.</summary>
    public bool HasLoadedTraceMap
    {
        get => _hasLoadedTraceMap;
        private set
        {
            if (SetField(ref _hasLoadedTraceMap, value))
            {
                RaiseEmptyStateText();
            }
        }
    }

    /// <summary>Gets the headline shown when no incident story is available.</summary>
    public string EmptyStateHeadline => HasLoadedTraceMap ? "No incident story in this result" : "No incident story yet";

    /// <summary>Gets the description shown when no incident story is available.</summary>
    public string EmptyStateDescription => HasLoadedTraceMap
        ? "The last run completed without findings to narrate. Review the findings, warnings, or parse errors for the run."
        : "Run an analysis or agent audit to generate a narrative attack chain and recommended response.";

    /// <summary>Gets the summary of the likely attack chain.</summary>
    public string LikelyChain
    {
        get => _likelyChain;
        private set => SetField(ref _likelyChain, value);
    }

    /// <summary>Gets whether a critical attack chain was detected.</summary>
    public bool HasCriticalChain
    {
        get => _hasCriticalChain;
        private set => SetField(ref _hasCriticalChain, value);
    }

    /// <summary>Gets the raw markdown representation suitable for export.</summary>
    public string Markdown
    {
        get => _markdown;
        private set => SetField(ref _markdown, value);
    }

    /// <summary>Gets the status text shown after a copy operation.</summary>
    public string CopyStatus
    {
        get => _copyStatus;
        private set => SetField(ref _copyStatus, value);
    }

    /// <summary>Gets the command that copies the incident story markdown to the clipboard.</summary>
    public AsyncRelayCommand CopyMarkdownCommand { get; }

    /// <summary>Gets or sets the command invoked by the empty-state action button.</summary>
    public ICommand? EmptyStateActionCommand { get; set; }

    /// <summary>Gets or sets the text of the empty-state action button.</summary>
    public string EmptyStateActionText { get; set; } = "Analyze";

    public IncidentStoryViewModel()
    {
        CopyMarkdownCommand = new AsyncRelayCommand(
            async _ => await CopyMarkdownAsync(),
            _ => HasStory,
            ex => CopyStatus = $"Copy failed: {ErrorSanitizer.SanitizeException(ex)}");
    }

    /// <summary>
    /// Loads a Trace Map result and generates the incident story narrative.
    /// </summary>
    public void LoadTraceMap(TraceMapResult? traceMap)
    {
        HasLoadedTraceMap = traceMap != null;
        Beats.Clear();
        Recommendations.Clear();
        CopyStatus = string.Empty;

        if (traceMap == null || traceMap.Findings.Count == 0)
        {
            HasStory = false;
            LikelyChain = string.Empty;
            HasCriticalChain = false;
            Markdown = string.Empty;
            CopyMarkdownCommand.RaiseCanExecuteChanged();
            return;
        }

        var story = _formatter.Format(traceMap);

        foreach (var beat in story.Beats)
        {
            Beats.Add(beat);
        }

        foreach (var rec in story.Recommendations)
        {
            Recommendations.Add(rec);
        }

        LikelyChain = story.LikelyChain;
        HasCriticalChain = story.HasCriticalChain;
        Markdown = story.Markdown;
        HasStory = true;
        CopyMarkdownCommand.RaiseCanExecuteChanged();
    }

    private async Task CopyMarkdownAsync()
    {
        if (string.IsNullOrEmpty(Markdown))
        {
            CopyStatus = "No story to copy.";
            return;
        }

        var topLevel = Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
        var mainWindow = topLevel?.MainWindow;

        if (mainWindow != null)
        {
            var clipboard = TopLevel.GetTopLevel(mainWindow)?.Clipboard;
            if (clipboard != null)
            {
                await clipboard.SetTextAsync(Markdown);
                CopyStatus = "Markdown copied to clipboard.";
                return;
            }
        }

        CopyStatus = "Clipboard not available.";
    }

    private void RaiseEmptyStateText()
    {
        OnPropertyChanged(nameof(EmptyStateHeadline));
        OnPropertyChanged(nameof(EmptyStateDescription));
    }
}
