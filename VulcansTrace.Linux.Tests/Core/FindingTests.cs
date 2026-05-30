using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Core;

public class FindingTests
{
    [Fact]
    public void Id_SameContent_SameGuid()
    {
        var finding1 = CreatePortScanFinding();
        var finding2 = CreatePortScanFinding();

        Assert.Equal(finding1.Id, finding2.Id);
    }

    [Fact]
    public void Id_DifferentContent_DifferentGuid()
    {
        var finding1 = CreatePortScanFinding();

        var finding2 = new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan detected",
            Details = "Detected 20 distinct destinations." // different
        };

        Assert.NotEqual(finding1.Id, finding2.Id);
    }

    [Fact]
    public void Id_NotEmpty()
    {
        var finding = CreatePortScanFinding();

        Assert.NotEqual(Guid.Empty, finding.Id);
    }

    [Fact]
    public void Id_StableAcrossMultipleAccesses()
    {
        var finding = CreatePortScanFinding();

        var firstAccess = finding.Id;
        var secondAccess = finding.Id;

        Assert.Equal(firstAccess, secondAccess);
    }

    [Fact]
    public void Id_ExplicitlySet_PreservesValue()
    {
        var explicitId = Guid.NewGuid();
        var finding = new Finding
        {
            Id = explicitId,
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan detected",
            Details = "Detected 12 distinct destinations."
        };

        Assert.Equal(explicitId, finding.Id);
    }

    [Fact]
    public void Id_WithExpression_AfterPriorAccess_RecomputesBasedOnNewContent()
    {
        // Regression test: record 'with' does a shallow copy, so the _id
        // backing field must not be cached across mutations.
        var finding = new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.1",
            Target = "multiple ports",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "Draft details"
        };

        // Force ID computation BEFORE mutation (simulates upstream access)
        _ = finding.Id;

        // Mutate via with — same pattern as PrivilegeEscalationDetector
        var mutated = finding with
        {
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(5),
            Details = "Final details after mutation"
        };

        // Create identical content directly
        var direct = new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.1",
            Target = "multiple ports",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(5),
            ShortDescription = "Port scan",
            Details = "Final details after mutation"
        };

        // Deterministic ID guarantee: identical content → identical ID
        Assert.Equal(direct.Id, mutated.Id);
    }

    [Fact]
    public void Fingerprint_SameStableFields_SameFingerprint()
    {
        var finding1 = CreatePortScanFinding();
        var finding2 = CreatePortScanFinding();

        Assert.Equal(finding1.Fingerprint, finding2.Fingerprint);
    }

    [Fact]
    public void Fingerprint_DifferentDescription_SameFingerprint()
    {
        var finding1 = CreatePortScanFinding();
        var finding2 = new Finding
        {
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.UnixEpoch.AddHours(1),
            TimeRangeEnd = DateTime.UnixEpoch.AddHours(2),
            ShortDescription = "Different description",
            Details = "Different details"
        };

        Assert.Equal(finding1.Fingerprint, finding2.Fingerprint);
    }

    [Fact]
    public void Fingerprint_DifferentSeverity_SameFingerprint()
    {
        var finding1 = CreatePortScanFinding();
        var finding2 = finding1 with { Severity = Severity.Critical };

        Assert.Equal(finding1.Fingerprint, finding2.Fingerprint);
    }

    [Fact]
    public void Fingerprint_DifferentStableFields_DifferentFingerprint()
    {
        var finding1 = CreatePortScanFinding();
        var finding2 = new Finding
        {
            Category = "Beaconing",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan detected",
            Details = "Detected 12 distinct destinations."
        };

        Assert.NotEqual(finding1.Fingerprint, finding2.Fingerprint);
    }

    [Fact]
    public void Fingerprint_NotEmpty()
    {
        var finding = CreatePortScanFinding();

        Assert.False(string.IsNullOrEmpty(finding.Fingerprint));
    }

    [Fact]
    public void Fingerprint_StableAcrossMultipleAccesses()
    {
        var finding = CreatePortScanFinding();

        var firstAccess = finding.Fingerprint;
        var secondAccess = finding.Fingerprint;

        Assert.Equal(firstAccess, secondAccess);
    }

    [Fact]
    public void Fingerprint_ExplicitlySet_PreservesValue()
    {
        var explicitFingerprint = "A1B2C3D4";
        var finding = new Finding
        {
            Fingerprint = explicitFingerprint,
            Category = "PortScan",
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan detected",
            Details = "Detected 12 distinct destinations."
        };

        Assert.Equal(explicitFingerprint, finding.Fingerprint);
    }

    [Fact]
    public void Fingerprint_WithExpression_AfterPriorAccess_RecomputesBasedOnNewContent()
    {
        var finding = new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.1",
            Target = "multiple ports",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "Draft details"
        };

        _ = finding.Fingerprint;

        var mutated = finding with
        {
            Target = "different target"
        };

        var direct = new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.1",
            Target = "different target",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "Draft details"
        };

        Assert.Equal(direct.Fingerprint, mutated.Fingerprint);
    }

    [Fact]
    public void Fingerprint_IncludesRuleId()
    {
        var finding1 = new Finding
        {
            RuleId = "FW-001",
            Category = "Firewall",
            Severity = Severity.High,
            SourceHost = "localhost",
            Target = "INPUT",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Desc",
            Details = "Details"
        };

        var finding2 = new Finding
        {
            RuleId = "FW-002",
            Category = "Firewall",
            Severity = Severity.High,
            SourceHost = "localhost",
            Target = "INPUT",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Desc",
            Details = "Details"
        };

        Assert.NotEqual(finding1.Fingerprint, finding2.Fingerprint);
    }

    private static Finding CreatePortScanFinding() => new()
    {
        Category = "PortScan",
        Severity = Severity.High,
        SourceHost = "192.168.1.10",
        Target = "multiple hosts/ports",
        TimeRangeStart = DateTime.UnixEpoch,
        TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
        ShortDescription = "Port scan detected",
        Details = "Detected 12 distinct destinations."
    };
}
