using System.Security.Cryptography;
using System.Text;

namespace VulcansTrace.Linux.Core;

/// <summary>
/// Represents a security finding identified during log analysis.
/// </summary>
/// <remarks>
/// Immutable record created by detectors. Use <c>with</c> expression to create modified copies.
/// </remarks>
public sealed record Finding
{
    private string _category = string.Empty;
    private string _sourceHost = string.Empty;
    private string _target = string.Empty;
    private DateTime _timeRangeStart;
    private DateTime _timeRangeEnd;
    private string _shortDescription = string.Empty;
    private string _details = string.Empty;
    private Guid? _id;

    /// <summary>
    /// Unique identifier for this finding, deterministically derived from content fields.
    /// If not explicitly set, computed on first access as a SHA-256 hash of all content fields.
    /// </summary>
    public Guid Id
    {
        get => _id ?? ComputeIdFromFields();
        init => _id = value;
    }

    /// <summary>Category of the finding (e.g., PortScan, Beaconing).</summary>
    public string Category
    {
        get => _category;
        init => _category = NormalizeNonEmpty(value, nameof(Category));
    }

    /// <summary>Severity level of the finding.</summary>
    public Severity Severity { get; init; }

    /// <summary>Source host IP address.</summary>
    public string SourceHost
    {
        get => _sourceHost;
        init => _sourceHost = NormalizeNonEmpty(value, nameof(SourceHost));
    }

    /// <summary>Target of the activity (IP, port, or description).</summary>
    public string Target
    {
        get => _target;
        init => _target = NormalizeNonEmpty(value, nameof(Target));
    }

    /// <summary>
    /// Start of the activity time range.
    /// When using <c>with</c> expressions to modify time range properties, set
    /// <see cref="TimeRangeStart"/> before <see cref="TimeRangeEnd"/> to ensure
    /// cross-field validation runs correctly.
    /// </summary>
    public DateTime TimeRangeStart
    {
        get => _timeRangeStart;
        init
        {
            ValidateTimeRange(value, _timeRangeEnd, nameof(TimeRangeStart));
            _timeRangeStart = value;
        }
    }

    /// <summary>End of the activity time range.</summary>
    public DateTime TimeRangeEnd
    {
        get => _timeRangeEnd;
        init
        {
            ValidateTimeRange(_timeRangeStart, value, nameof(TimeRangeEnd));
            _timeRangeEnd = value;
        }
    }

    /// <summary>Brief description of the finding.</summary>
    public string ShortDescription
    {
        get => _shortDescription;
        init => _shortDescription = NormalizeNonEmpty(value, nameof(ShortDescription));
    }

    /// <summary>Detailed information about the finding.</summary>
    public string Details
    {
        get => _details;
        init => _details = NormalizeNonEmpty(value, nameof(Details));
    }

    private static string NormalizeNonEmpty(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{name} must be set.", name);
        }

        return value.Trim();
    }

    private static void ValidateTimeRange(DateTime start, DateTime end, string name)
    {
        if (start != default && end != default && start > end)
        {
            throw new ArgumentException("TimeRangeStart must be <= TimeRangeEnd.", name);
        }
    }

    private Guid ComputeIdFromFields()
    {
        var canonical = $"{_category}|{(int)Severity}|{_sourceHost}|{_target}|{_timeRangeStart:O}|{_timeRangeEnd:O}|{_shortDescription}|{_details}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return new Guid(hash[..16]);
    }
}
