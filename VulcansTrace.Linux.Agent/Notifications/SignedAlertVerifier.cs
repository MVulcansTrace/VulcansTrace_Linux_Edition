using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VulcansTrace.Linux.Core.Security;

namespace VulcansTrace.Linux.Agent.Notifications;

/// <summary>
/// Signs and verifies <see cref="SignedAlertMessage"/> payloads using HMAC-SHA256 over a
/// stable canonical JSON form. The canonical form binds the schedule identity, a per-alert
/// nonce, and every transmitted field so that recipients can detect tampering and replays.
/// </summary>
/// <remarks>
/// The verifier guarantees integrity and origin-binding: a recipient with the same key can confirm
/// the payload has not been altered and that it was produced for the claimed schedule. It does not,
/// by itself, guarantee freshness (replay resistance). Recipients that need replay resistance must
/// maintain a cache of observed <see cref="SignedAlertMessage.Nonce"/> values and reject duplicates.
/// </remarks>
public sealed class SignedAlertVerifier
{
    private readonly IntegrityHasher _hasher;

    /// <summary>
    /// Initializes a new instance of the <see cref="SignedAlertVerifier"/> class with the default
    /// <see cref="IntegrityHasher"/>.
    /// </summary>
    public SignedAlertVerifier() : this(new IntegrityHasher())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SignedAlertVerifier"/> class with a supplied
    /// <see cref="IntegrityHasher"/>.
    /// </summary>
    /// <param name="hasher">The hasher used for HMAC computation.</param>
    public SignedAlertVerifier(IntegrityHasher hasher)
    {
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
    }

    /// <summary>
    /// Sentinel signature value used when no signing key is configured. Such an alert cannot
    /// be authenticated by a recipient and must not be mistaken for a verified signature.
    /// </summary>
    public const string UnsignedSentinel = "UNSIGNED";

    /// <summary>
    /// Computes the HMAC-SHA256 signature (uppercase hex) for the alert under the given key.
    /// </summary>
    /// <param name="alert">The alert payload to sign. Must have a non-empty nonce.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns>The hex-encoded signature.</returns>
    public string ComputeSignature(SignedAlertMessage alert, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(alert);
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length == 0)
            throw new ArgumentException("Signing key must not be empty.", nameof(key));

        var canonical = BuildCanonicalString(alert);
        var signatureBytes = _hasher.ComputeHmacSha256(Encoding.UTF8.GetBytes(canonical), key);
        return Convert.ToHexString(signatureBytes);
    }

    /// <summary>
    /// Verifies that the alert's signature matches its content under the given key, using a
    /// constant-time comparison.
    /// </summary>
    /// <param name="alert">The alert to verify.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns>True if the signature is valid and the alert is not the unsigned sentinel.</returns>
    public bool Verify(SignedAlertMessage alert, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(alert);
        ArgumentNullException.ThrowIfNull(key);

        if (string.IsNullOrEmpty(alert.Signature) ||
            string.Equals(alert.Signature, UnsignedSentinel, StringComparison.Ordinal))
        {
            return false;
        }

        byte[] expected;
        try
        {
            expected = Convert.FromHexString(alert.Signature);
        }
        catch (FormatException)
        {
            return false;
        }

        var canonical = BuildCanonicalString(alert);
        var actual = _hasher.ComputeHmacSha256(Encoding.UTF8.GetBytes(canonical), key);

        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    /// <summary>
    /// Builds the deterministic canonical JSON string that is signed. Field order is fixed and
    /// list fields remain arrays so the signature binds the transmitted structure, not a lossy
    /// delimiter-joined representation.
    /// </summary>
    /// <param name="alert">The alert payload.</param>
    /// <returns>The canonical JSON string.</returns>
    internal static string BuildCanonicalString(SignedAlertMessage alert)
    {
        var canonical = new
        {
            scheduleId = alert.ScheduleId,
            nonce = alert.Nonce,
            title = alert.Title,
            body = alert.Body,
            scheduleName = alert.ScheduleName,
            maxSeverity = alert.MaxSeverity.ToString(),
            driftFindingCount = alert.DriftFindingCount,
            ruleIds = alert.RuleIds.ToArray(),
            attackChainNarratives = alert.AttackChainNarratives.ToArray(),
            proactiveAlertSummaries = alert.ProactiveAlertSummaries.ToArray(),
            remediationSummary = alert.RemediationSummary ?? string.Empty,
            timestamp = alert.TimestampUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
        };

        return JsonSerializer.Serialize(canonical, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }
}
