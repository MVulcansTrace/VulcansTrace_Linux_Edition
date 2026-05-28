using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Detectors;

namespace VulcansTrace.Linux.Tests.Helpers;

internal static class SentryAnalyzerFactory
{
    public static SentryAnalyzer CreateFull()
    {
        return new SentryAnalyzer(
            new LogNormalizer(),
            new AnalysisProfileProvider(),
            new IDetector[]
            {
                new PortScanDetector(),
                new FloodDetector(),
                new LateralMovementDetector(),
                new BeaconingDetector(),
                new PolicyViolationDetector(),
                new NoveltyDetector()
            },
            new IDetector[]
            {
                new FlagAnomalyDetector(),
                new MacSpoofingDetector(),
                new KernelModuleDetector(),
                new InterfaceHoppingDetector(),
                new UnusualPacketSizeDetector()
            },
            new IDetector[]
            {
                new C2ChannelDetector(),
                new PrivilegeEscalationDetector()
            },
            new RiskEscalator());
    }
}
