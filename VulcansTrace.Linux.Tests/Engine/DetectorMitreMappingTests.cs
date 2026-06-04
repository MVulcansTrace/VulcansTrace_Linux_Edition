using System.Reflection;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine.Detectors;
using Xunit;

namespace VulcansTrace.Linux.Tests.Engine;

public class DetectorMitreMappingTests
{
    [Theory]
    [InlineData(typeof(C2ChannelDetector), "T1071.001")]
    [InlineData(typeof(C2ChannelDetector), "T1071")]
    [InlineData(typeof(BeaconingDetector), "T1071.001")]
    [InlineData(typeof(PortScanDetector), "T1046")]
    [InlineData(typeof(FloodDetector), "T1498")]
    [InlineData(typeof(FloodDetector), "T1499")]
    [InlineData(typeof(LateralMovementDetector), "T1021")]
    [InlineData(typeof(LateralMovementDetector), "T1210")]
    [InlineData(typeof(PrivilegeEscalationDetector), "T1068")]
    [InlineData(typeof(PrivilegeEscalationDetector), "T1548")]
    [InlineData(typeof(PolicyViolationDetector), "T1090")]
    [InlineData(typeof(PolicyViolationDetector), "T1571")]
    [InlineData(typeof(FlagAnomalyDetector), "T1046")]
    [InlineData(typeof(MacSpoofingDetector), "T1557")]
    [InlineData(typeof(MacSpoofingDetector), "T1557.001")]
    [InlineData(typeof(InterfaceHoppingDetector), "T1595")]
    [InlineData(typeof(KernelModuleDetector), "T1547.006")]
    [InlineData(typeof(NoveltyDetector), "T1071")]
    [InlineData(typeof(UnusualPacketSizeDetector), "T1001")]
    public void Detector_Category_HasExpectedMitreTechnique(Type detectorType, string expectedTechniqueId)
    {
        // Verify the type implements IDetector
        Assert.True(typeof(IDetector).IsAssignableFrom(detectorType), $"{detectorType.Name} must implement IDetector");

        // Reflect on the static s_mitreTechniques field and assert the expected ID is present
        var field = detectorType.GetField("s_mitreTechniques", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);

        var value = field.GetValue(null) as IReadOnlyList<MitreTechnique>;
        Assert.NotNull(value);
        Assert.NotEmpty(value);

        var actualIds = value.Select(t => t.TechniqueId).ToList();
        Assert.Contains(expectedTechniqueId, actualIds);
    }

    [Fact]
    public void AllDetectors_AreCoveredByTheory()
    {
        var detectorTypes = typeof(IDetector).Assembly.GetTypes()
            .Where(t => typeof(IDetector).IsAssignableFrom(t) && t is { IsInterface: false, IsAbstract: false })
            .ToList();

        var coveredTypes = new[]
        {
            typeof(C2ChannelDetector),
            typeof(BeaconingDetector),
            typeof(PortScanDetector),
            typeof(FloodDetector),
            typeof(LateralMovementDetector),
            typeof(PrivilegeEscalationDetector),
            typeof(PolicyViolationDetector),
            typeof(FlagAnomalyDetector),
            typeof(MacSpoofingDetector),
            typeof(InterfaceHoppingDetector),
            typeof(KernelModuleDetector),
            typeof(NoveltyDetector),
            typeof(UnusualPacketSizeDetector)
        };

        foreach (var dt in detectorTypes)
        {
            Assert.Contains(dt, coveredTypes);
        }
    }
}
