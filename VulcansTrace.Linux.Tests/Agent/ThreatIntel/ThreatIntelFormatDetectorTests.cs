using VulcansTrace.Linux.Agent.ThreatIntel;

namespace VulcansTrace.Linux.Tests.Agent.ThreatIntel;

public class ThreatIntelFormatDetectorTests
{
    [Fact]
    public void TryDetect_MinifiedStixBundle_DetectsStix()
    {
        var json = @"{""type"":""bundle"",""spec_version"":""2.1"",""objects"":[]}";

        var detected = ThreatIntelFormatDetector.TryDetect(json, out var format);

        Assert.True(detected);
        Assert.Equal(ThreatIntelBundleFormat.Stix, format);
    }

    [Fact]
    public void TryDetect_MispEvent_DetectsMisp()
    {
        var json = @"{""Event"":{""Attribute"":[{""type"":""ip-dst"",""value"":""1.2.3.4""}]}}";

        var detected = ThreatIntelFormatDetector.TryDetect(json, out var format);

        Assert.True(detected);
        Assert.Equal(ThreatIntelBundleFormat.Misp, format);
    }

    [Fact]
    public void TryDetect_UnknownJson_ReturnsFalse()
    {
        var detected = ThreatIntelFormatDetector.TryDetect(@"{""hello"":""world""}", out _);

        Assert.False(detected);
    }
}
