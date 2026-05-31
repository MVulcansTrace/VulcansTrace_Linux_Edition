namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// A single row in the rule coverage panel representing one category.
/// </summary>
public sealed class RuleCoverageCategoryViewModel : ViewModelBase
{
    private string _category = "";
    private int _passed;
    private int _failed;
    private int _suppressed;
    private int _crashed;
    private int _notApplicable;

    /// <summary>The category name (e.g., "Firewall", "Network").</summary>
    public string Category
    {
        get => _category;
        set => SetField(ref _category, value);
    }

    /// <summary>Number of rules that passed in this category.</summary>
    public int Passed
    {
        get => _passed;
        set => SetField(ref _passed, value);
    }

    /// <summary>Number of rules that failed in this category.</summary>
    public int Failed
    {
        get => _failed;
        set => SetField(ref _failed, value);
    }

    /// <summary>Number of rules suppressed in this category.</summary>
    public int Suppressed
    {
        get => _suppressed;
        set => SetField(ref _suppressed, value);
    }

    /// <summary>Number of rules that crashed in this category.</summary>
    public int Crashed
    {
        get => _crashed;
        set => SetField(ref _crashed, value);
    }

    /// <summary>Number of rules not applicable in this category.</summary>
    public int NotApplicable
    {
        get => _notApplicable;
        set => SetField(ref _notApplicable, value);
    }

    /// <summary>Total number of rules evaluated in this category.</summary>
    public int Total => Passed + Failed + Suppressed + Crashed + NotApplicable;
}
