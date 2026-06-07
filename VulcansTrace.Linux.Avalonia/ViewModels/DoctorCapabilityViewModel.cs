namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for a single data-source capability row in the Doctor tab.
/// </summary>
public sealed class DoctorCapabilityViewModel : ViewModelBase
{
    private string _sourceName = string.Empty;
    private string _statusLabel = string.Empty;
    private string _statusColor = "#94a3b8";
    private string _detail = string.Empty;
    private bool _isAvailable;
    private bool _isPermissionLimited;
    private bool _isUnavailable;

    /// <summary>Name of the data source.</summary>
    public string SourceName
    {
        get => _sourceName;
        set => SetField(ref _sourceName, value);
    }

    /// <summary>Human-readable status label.</summary>
    public string StatusLabel
    {
        get => _statusLabel;
        set => SetField(ref _statusLabel, value);
    }

    /// <summary>Hex color for the status badge.</summary>
    public string StatusColor
    {
        get => _statusColor;
        set => SetField(ref _statusColor, value);
    }

    /// <summary>Optional detail message.</summary>
    public string Detail
    {
        get => _detail;
        set => SetField(ref _detail, value);
    }

    /// <summary>Whether the source is fully available.</summary>
    public bool IsAvailable
    {
        get => _isAvailable;
        set => SetField(ref _isAvailable, value);
    }

    /// <summary>Whether the source is permission-limited.</summary>
    public bool IsPermissionLimited
    {
        get => _isPermissionLimited;
        set => SetField(ref _isPermissionLimited, value);
    }

    /// <summary>Whether the source is unavailable.</summary>
    public bool IsUnavailable
    {
        get => _isUnavailable;
        set => SetField(ref _isUnavailable, value);
    }
}
