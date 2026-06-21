using VulcansTrace.Linux.Agent.Notifications;
using VulcansTrace.Linux.Core;

namespace VulcansTrace.Linux.Tests.Notifications;

public class SignedAlertVerifierTests
{
    private static readonly SignedAlertVerifier Verifier = new();
    private static readonly byte[] Key = Convert.FromHexString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    private static readonly byte[] OtherKey = Convert.FromHexString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

    private static SignedAlertMessage BuildAlert() => new()
    {
        Title = "Drift alert",
        Body = "The firewall posture has degraded.",
        ScheduleId = "sched-1",
        ScheduleName = "Daily Firewall Check",
        Nonce = "deadbeefcafebabe",
        MaxSeverity = Severity.Critical,
        DriftFindingCount = 2,
        RuleIds = new[] { "FW-001", "FW-002" },
        AttackChainNarratives = new[] { "FW-001 -> FW-002" },
        ProactiveAlertSummaries = new[] { "FW-001 returned after verified fix." },
        RemediationSummary = "1 permitted command",
        TimestampUtc = new DateTime(2026, 6, 20, 12, 0, 0, DateTimeKind.Utc)
    };

    private static SignedAlertMessage Signed() => BuildAlert() with
    {
        Signature = Verifier.ComputeSignature(BuildAlert(), Key)
    };

    [Fact]
    public void ComputeSignature_ThenVerify_RoundTrips()
    {
        Assert.True(Verifier.Verify(Signed(), Key));
    }

    [Fact]
    public void Verify_TamperedBody_ReturnsFalse()
    {
        var alert = Signed() with { Body = "tampered body" };
        Assert.False(Verifier.Verify(alert, Key));
    }

    [Fact]
    public void Verify_ChangedNonce_ReturnsFalse()
    {
        var alert = Signed() with { Nonce = "different-nonce" };
        Assert.False(Verifier.Verify(alert, Key));
    }

    [Fact]
    public void Verify_ChangedScheduleId_ReturnsFalse()
    {
        var alert = Signed() with { ScheduleId = "sched-2" };
        Assert.False(Verifier.Verify(alert, Key));
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        Assert.False(Verifier.Verify(Signed(), OtherKey));
    }

    [Fact]
    public void Verify_UnsignedSentinel_ReturnsFalse()
    {
        var alert = Signed() with { Signature = SignedAlertVerifier.UnsignedSentinel };
        Assert.False(Verifier.Verify(alert, Key));
    }

    [Fact]
    public void Verify_MalformedSignatureHex_ReturnsFalse()
    {
        var alert = Signed() with { Signature = "not-hex" };
        Assert.False(Verifier.Verify(alert, Key));
    }

    [Fact]
    public void ComputeSignature_IsDeterministicForIdenticalPayloads()
    {
        var a = Verifier.ComputeSignature(BuildAlert(), Key);
        var b = Verifier.ComputeSignature(BuildAlert(), Key);
        Assert.Equal(a, b);
    }

    [Fact]
    public void ComputeSignature_BindsListStructureWithoutDelimiterCollisions()
    {
        var singleItem = BuildAlert() with { RuleIds = new[] { "FW-001,FW-002" } };
        var twoItems = BuildAlert() with { RuleIds = new[] { "FW-001", "FW-002" } };

        var singleItemSignature = Verifier.ComputeSignature(singleItem, Key);
        var twoItemsSignature = Verifier.ComputeSignature(twoItems, Key);

        Assert.NotEqual(singleItemSignature, twoItemsSignature);
        Assert.False(Verifier.Verify(twoItems with { Signature = singleItemSignature }, Key));
    }
}
