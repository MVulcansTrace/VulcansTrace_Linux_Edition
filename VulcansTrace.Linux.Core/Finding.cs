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
    private string? _ruleId;
    private Guid? _id;
    private string? _fingerprint;
    private IReadOnlyList<CisBenchmarkMapping> _cisMappings = Array.Empty<CisBenchmarkMapping>();
    private IReadOnlyList<MitreTechnique> _mitreTechniques = Array.Empty<MitreTechnique>();

    /// <summary>
    /// Optional agent rule identifier (e.g., "FW-001", "PORT-003").
    /// Set by the Security Agent; engine findings will have this as null.
    /// </summary>
    public string? RuleId
    {
        get => _ruleId;
        init => _ruleId = value;
    }

    /// <summary>
    /// Unique identifier for this finding, deterministically derived from content fields.
    /// If not explicitly set, computed on first access as a SHA-256 hash of all content fields.
    /// </summary>
    public Guid Id
    {
        get => _id ?? ComputeIdFromFields();
        init => _id = value;
    }

    /// <summary>
    /// Stable fingerprint for this finding, derived from semantic fields that identify the
    /// underlying issue (RuleId, Category, SourceHost, Target). Excludes volatile fields
    /// like timestamps and descriptions, plus mutable state like severity, so the fingerprint
    /// remains stable across runs even when wording, time ranges, or severity change slightly.
    /// </summary>
    public string Fingerprint
    {
        get => _fingerprint ?? ComputeFingerprintFromFields();
        init => _fingerprint = string.IsNullOrWhiteSpace(value) ? null! : value;
    }

    /// <summary>Category of the finding (e.g., PortScan, Beaconing).</summary>
    public string Category
    {
        get => _category;
        init => _category = NormalizeNonEmpty(value, nameof(Category));
    }

    /// <summary>Severity level of the finding.</summary>
    public Severity Severity { get; init; }

    /// <summary>Confidence level of the finding.</summary>
    public DetectionConfidence Confidence { get; init; } = DetectionConfidence.Unknown;

    private IReadOnlyList<EvidenceSignal> _evidenceSignals = Array.Empty<EvidenceSignal>();

    /// <summary>Evidence signals that contributed to the finding's confidence score.</summary>
    public IReadOnlyList<EvidenceSignal> EvidenceSignals
    {
        get => _evidenceSignals;
        init => _evidenceSignals = value ?? throw new ArgumentNullException(nameof(EvidenceSignals));
    }

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

    /// <summary>
    /// CIS Benchmark controls this finding maps to, explaining compliance context.
    /// </summary>
    public IReadOnlyList<CisBenchmarkMapping> CisMappings
    {
        get => _cisMappings;
        init => _cisMappings = value ?? throw new ArgumentNullException(nameof(CisMappings));
    }

    /// <summary>
    /// MITRE ATT&CK techniques this finding maps to, explaining threat-framework context.
    /// </summary>
    public IReadOnlyList<MitreTechnique> MitreTechniques
    {
        get => _mitreTechniques;
        init => _mitreTechniques = value ?? throw new ArgumentNullException(nameof(MitreTechniques));
    }

    private int _groupedCount = 1;
    private IReadOnlyList<string> _representativeTargets = Array.Empty<string>();
    private IReadOnlyList<string> _riskDrivers = Array.Empty<string>();

    /// <summary>Number of raw findings grouped into this representative. 1 if not grouped.</summary>
    public int GroupedCount
    {
        get => _groupedCount;
        init => _groupedCount = value > 0 ? value : 1;
    }

    /// <summary>Example targets from the grouped findings (top N representatives).</summary>
    public IReadOnlyList<string> RepresentativeTargets
    {
        get => _representativeTargets;
        init => _representativeTargets = value ?? throw new ArgumentNullException(nameof(RepresentativeTargets));
    }

    /// <summary>Derived risk drivers (e.g., common path prefixes, frequent source hosts).</summary>
    public IReadOnlyList<string> RiskDrivers
    {
        get => _riskDrivers;
        init => _riskDrivers = value ?? throw new ArgumentNullException(nameof(RiskDrivers));
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

    private string ComputeFingerprintFromFields()
    {
        var canonical = $"{_ruleId ?? ""}|{_category}|{_sourceHost}|{_target}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(hash[..16]);
    }
}
