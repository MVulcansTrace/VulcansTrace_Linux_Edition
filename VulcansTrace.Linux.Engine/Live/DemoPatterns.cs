namespace VulcansTrace.Linux.Engine.Live;

/// <summary>
/// Factory for <see cref="SyntheticPatterns"/> tuned to specific demo scenarios.
/// </summary>
public static class DemoPatterns
{
    /// <summary>
    /// Returns a <see cref="SyntheticPatterns"/> configuration tuned for the given scenario.
    /// </summary>
    public static SyntheticPatterns For(DemoScenario scenario)
    {
        return scenario switch
        {
            DemoScenario.C2Beaconing => C2Beaconing(),
            DemoScenario.SshBruteforce => SshBruteforce(),
            DemoScenario.PrivilegeEscalation => PrivilegeEscalation(),
            DemoScenario.RandomMix => RandomMix(),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, null)
        };
    }

    /// <summary>
    /// Periodic beaconing tuned to trigger <see cref="Detectors.BeaconingDetector"/>
    /// and <see cref="Detectors.C2ChannelDetector"/> at High intensity.
    /// Uses a 30-second interval so that enough events accumulate in a 120-second
    /// analysis window.
    /// </summary>
    private static SyntheticPatterns C2Beaconing()
    {
        return new SyntheticPatterns
        {
            EventDelayMs = 200,
            PortScanEnabled = false,
            FloodEnabled = false,
            BeaconingEnabled = true,
            BeaconIntervalSeconds = 30.0,
            BeaconInitialDelaySeconds = 0,
            BeaconJitterSeconds = 0,
            BeaconDestinationIp = "8.8.8.8",
            AdminPortSweepEnabled = false,
            TargetedFloodEnabled = false,
            BackgroundTrafficEnabled = false,
            FixedAttackSourceIp = "10.99.99.100"
        };
    }

    /// <summary>
    /// High-volume burst targeted at TCP/22 tuned to trigger
    /// <see cref="Detectors.FloodDetector"/> at High intensity within ~30 seconds.
    /// </summary>
    private static SyntheticPatterns SshBruteforce()
    {
        return new SyntheticPatterns
        {
            EventDelayMs = 50,
            PortScanEnabled = false,
            FloodEnabled = false,
            BeaconingEnabled = false,
            AdminPortSweepEnabled = false,
            TargetedFloodEnabled = true,
            TargetedFloodPort = 22,
            TargetedFloodStart = TimeSpan.Zero,
            TargetedFloodEnd = TimeSpan.FromSeconds(60),
            TargetedFloodProbability = 1.0,
            BackgroundTrafficEnabled = false,
            FixedAttackSourceIp = "10.99.99.100",
            FixedTargetIp = "192.168.1.10"
        };
    }

    /// <summary>
    /// Rapid admin-port sweep tuned to trigger
    /// <see cref="Detectors.PrivilegeEscalationDetector"/> at High intensity
    /// within ~30 seconds.
    /// </summary>
    private static SyntheticPatterns PrivilegeEscalation()
    {
        return new SyntheticPatterns
        {
            EventDelayMs = 3000,
            PortScanEnabled = false,
            FloodEnabled = false,
            BeaconingEnabled = false,
            AdminPortSweepEnabled = true,
            AdminPortSweepStart = TimeSpan.Zero,
            AdminPortSweepEnd = TimeSpan.FromSeconds(60),
            AdminPortSweepProbability = 1.0,
            AdminPortSweepMinEventsPerBurst = 4,
            AdminPortSweepMaxEventsPerBurst = 4,
            TargetedFloodEnabled = false,
            BackgroundTrafficEnabled = false,
            FixedAttackSourceIp = "10.99.99.100",
            FixedTargetIp = "192.168.1.10"
        };
    }

    /// <summary>
    /// The legacy random-mix configuration that generates port scans, beaconing,
    /// and floods with default probabilities.
    /// </summary>
    private static SyntheticPatterns RandomMix()
    {
        return new SyntheticPatterns();
    }
}
