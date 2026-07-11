using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Linux.Agent.Diagnostics;
using VulcansTrace.Linux.Agent.Reports;
using VulcansTrace.Linux.Agent.Scanners;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the Doctor diagnostic tab.
/// </summary>
public sealed class DoctorViewModel : ViewModelBase
{
    private readonly DoctorService _doctorService;
    private bool _isBusy;
    private bool _hasData;
    private bool _hasProbed;
    private string _summaryText = string.Empty;
    private string _summaryColor = "#64748b";
    private string _summaryBackground = "#1e293b";

    /// <summary>Gets the collection of capability rows.</summary>
    public ObservableCollection<DoctorCapabilityViewModel> Capabilities { get; } = new();

    /// <summary>Gets the collection of scanner warnings.</summary>
    public ObservableCollection<string> Warnings { get; } = new();

    /// <summary>Gets whether a diagnostic probe is running.</summary>
    public bool IsBusy
    {
        get => _isBusy;
        private set => SetField(ref _isBusy, value);
    }

    /// <summary>Gets whether any diagnostic data has been loaded.</summary>
    public bool HasData
    {
        get => _hasData;
        private set => SetField(ref _hasData, value);
    }

    /// <summary>Gets whether a probe has ever been run.</summary>
    public bool HasProbed
    {
        get => _hasProbed;
        private set => SetField(ref _hasProbed, value);
    }

    /// <summary>Gets the summary message.</summary>
    public string SummaryText
    {
        get => _summaryText;
        private set => SetField(ref _summaryText, value);
    }

    /// <summary>Gets the summary foreground color.</summary>
    public string SummaryColor
    {
        get => _summaryColor;
        private set => SetField(ref _summaryColor, value);
    }

    /// <summary>Gets the summary background color.</summary>
    public string SummaryBackground
    {
        get => _summaryBackground;
        private set => SetField(ref _summaryBackground, value);
    }

    /// <summary>Gets the command to run diagnostics.</summary>
    public AsyncRelayCommand RunDiagnosticsCommand { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DoctorViewModel"/> class.
    /// </summary>
    public DoctorViewModel(DoctorService doctorService)
    {
        _doctorService = doctorService;
        RunDiagnosticsCommand = new AsyncRelayCommand(
            async _ => await RunDiagnosticsAsync(),
            _ => !IsBusy,
            ex =>
            {
                SummaryText = $"Diagnostic failed: {ErrorSanitizer.Sanitize(ex.Message)}";
                SummaryColor = "#f87171";
                SummaryBackground = "#450a0a";
                HasProbed = true;
                IsBusy = false;
            });
    }

    private async Task RunDiagnosticsAsync()
    {
        IsBusy = true;
        SummaryText = "Probing data sources...";
        SummaryColor = "#94a3b8";
        SummaryBackground = "#1e293b";

        using var cts = new CancellationTokenSource();
        var result = await Task.Run(() => _doctorService.ProbeAsync(cts.Token));

        LoadResults(result);
        IsBusy = false;
    }

    /// <summary>
    /// Loads diagnostic results into the view model.
    /// </summary>
    public void LoadResults(DoctorResult result)
    {
        result = DoctorResultSanitizer.SanitizeForDisplay(result);

        Capabilities.Clear();
        Warnings.Clear();

        foreach (var warning in result.Warnings)
        {
            Warnings.Add(warning);
        }

        foreach (var cap in result.Capabilities)
        {
            var (color, label) = cap.Status switch
            {
                CapabilityStatus.Available => ("#22c55e", "Available"),
                CapabilityStatus.PermissionLimited => ("#fbbf24", "Permission Limited"),
                CapabilityStatus.Unavailable => ("#ef4444", "Unavailable"),
                _ => ("#94a3b8", "Not Checked")
            };

            Capabilities.Add(new DoctorCapabilityViewModel
            {
                SourceName = cap.SourceName,
                StatusLabel = label,
                StatusColor = color,
                Detail = cap.Detail ?? string.Empty,
                IsAvailable = cap.Status == CapabilityStatus.Available,
                IsPermissionLimited = cap.Status == CapabilityStatus.PermissionLimited,
                IsUnavailable = cap.Status == CapabilityStatus.Unavailable
            });
        }

        if (result.IsHealthy)
        {
            SummaryText = $"All {result.Capabilities.Count} data sources are available.";
            SummaryColor = "#34d399";
            SummaryBackground = "#064e3b";
        }
        else if (result.PermissionLimitedCount > 0 || result.UnavailableCount > 0 || result.UnknownCount > 0)
        {
            var parts = new System.Collections.Generic.List<string>();
            if (result.PermissionLimitedCount > 0)
                parts.Add($"{result.PermissionLimitedCount} permission-limited");
            if (result.UnavailableCount > 0)
                parts.Add($"{result.UnavailableCount} unavailable");
            if (result.UnknownCount > 0)
                parts.Add($"{result.UnknownCount} not checked");
            SummaryText = $"{string.Join(" and ", parts)} data source(s). Run with sudo where permission-limited, and review unavailable or not-checked sources before interpreting audit coverage.";
            SummaryColor = "#fcd34d";
            SummaryBackground = "#451a03";
        }
        else
        {
            SummaryText = "No capabilities reported.";
            SummaryColor = "#94a3b8";
            SummaryBackground = "#1e293b";
        }

        HasData = Capabilities.Count > 0;
        HasProbed = true;
    }
}
