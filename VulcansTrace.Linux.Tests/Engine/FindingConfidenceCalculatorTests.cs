using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Confidence;

namespace VulcansTrace.Linux.Tests.Engine;

public class FindingConfidenceCalculatorTests
{
    [Fact]
    public void Calculate_NoSignals_ReturnsUnknown()
    {
        var result = FindingConfidenceCalculator.Calculate(Array.Empty<EvidenceSignal>());

        Assert.Equal(DetectionConfidence.Unknown, result);
    }

    [Fact]
    public void Calculate_NullSignals_ReturnsUnknown()
    {
        var result = FindingConfidenceCalculator.Calculate(null!);

        Assert.Equal(DetectionConfidence.Unknown, result);
    }

    [Fact]
    public void Calculate_SingleSignal_ReturnsLow()
    {
        var signals = new[]
        {
            new EvidenceSignal { Name = "Periodic outbound traffic", Source = "Behavior", Explanation = "Repeating intervals" }
        };

        var result = FindingConfidenceCalculator.Calculate(signals);

        Assert.Equal(DetectionConfidence.Low, result);
    }

    [Fact]
    public void Calculate_TwoSignals_ReturnsMedium()
    {
        var signals = new[]
        {
            new EvidenceSignal { Name = "Periodic outbound traffic", Source = "Behavior" },
            new EvidenceSignal { Name = "Same destination repeated", Source = "Behavior" }
        };

        var result = FindingConfidenceCalculator.Calculate(signals);

        Assert.Equal(DetectionConfidence.Medium, result);
    }

    [Fact]
    public void Calculate_ThreeSignals_ReturnsHigh()
    {
        var signals = new[]
        {
            new EvidenceSignal { Name = "Periodic outbound traffic", Source = "Behavior" },
            new EvidenceSignal { Name = "Same destination repeated", Source = "Behavior" },
            new EvidenceSignal { Name = "Matches known C2 behavior", Source = "Behavior" }
        };

        var result = FindingConfidenceCalculator.Calculate(signals);

        Assert.Equal(DetectionConfidence.High, result);
    }

    [Fact]
    public void Calculate_ThreatIntelAndBehavior_ReturnsConfirmed()
    {
        var signals = new[]
        {
            new EvidenceSignal { Name = "Known malicious IP", Source = EvidenceSignal.ThreatIntelSource },
            new EvidenceSignal { Name = "Beaconing pattern", Source = EvidenceSignal.BehaviorSource }
        };

        var result = FindingConfidenceCalculator.Calculate(signals);

        Assert.Equal(DetectionConfidence.Confirmed, result);
    }

    [Fact]
    public void Calculate_ThreatIntelAndBehavior_CaseInsensitive()
    {
        var signals = new[]
        {
            new EvidenceSignal { Name = "Known malicious IP", Source = "threatintel" },
            new EvidenceSignal { Name = "Beaconing pattern", Source = "BEHAVIOR" }
        };

        var result = FindingConfidenceCalculator.Calculate(signals);

        Assert.Equal(DetectionConfidence.Confirmed, result);
    }

    [Fact]
    public void Calculate_ThreatIntelOnly_WithManySignals_ReturnsHigh()
    {
        var signals = new[]
        {
            new EvidenceSignal { Name = "Known malicious IP", Source = EvidenceSignal.ThreatIntelSource },
            new EvidenceSignal { Name = "Unusual port", Source = EvidenceSignal.ThreatIntelSource },
            new EvidenceSignal { Name = "Rare user agent", Source = EvidenceSignal.ThreatIntelSource }
        };

        var result = FindingConfidenceCalculator.Calculate(signals);

        Assert.Equal(DetectionConfidence.High, result);
    }
}
