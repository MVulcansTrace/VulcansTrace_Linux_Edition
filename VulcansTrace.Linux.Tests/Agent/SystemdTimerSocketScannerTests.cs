using VulcansTrace.Linux.Agent.Scanners;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class SystemdTimerSocketScannerTests
{
    [Fact]
    public void ParseUnitOutput_TimerAndSocket_PopulatesLists()
    {
        var output = """
            logrotate.timer loaded active waiting Daily rotation of log files
            ssh.socket loaded active listening OpenBSD secure shell server socket
            """;

        var timers = new List<SystemdTimer>();
        var sockets = new List<SystemdSocket>();

        SystemdTimerSocketScanner.ParseUnitOutput(output, timers, sockets);

        Assert.Single(timers);
        Assert.Equal("logrotate.timer", timers[0].Name);
        Assert.True(timers[0].Active);
        Assert.Equal("logrotate.service", timers[0].TriggerUnit);

        Assert.Single(sockets);
        Assert.Equal("ssh.socket", sockets[0].Name);
        Assert.True(sockets[0].Listening);
        Assert.Equal("ssh.service", sockets[0].TriggerUnit);
    }

    [Fact]
    public void ParseTimerOutput_SetsTriggerUnit_NotInterval()
    {
        // Real list-timers shape: the LEFT column ends in "left", only PASSED ends in "ago".
        var output = "Mon 2024-01-01 00:00:00 UTC 1h left Sun 2023-12-31 22:00:00 UTC 3h ago logrotate.timer logrotate.service";

        var timers = new List<SystemdTimer>
        {
            new() { Name = "logrotate.timer" }
        };

        SystemdTimerSocketScanner.ParseTimerOutput(output, timers);

        Assert.Equal("logrotate.service", timers[0].TriggerUnit);
        // The interval is intentionally NOT derived from list-timers columns; it is resolved
        // from `systemctl show` (see ParseTimerIntervalsFromShow).
        Assert.Equal("", timers[0].Interval);
    }

    [Fact]
    public void ParseTimerIntervalsFromShow_MapsUnitsToConfiguredFrequency()
    {
        var output = """
            Id=logrotate.timer
            OnUnitActiveSec=1min
            OnUnitSec=
            OnCalendar=
            Id=fstrim.timer
            OnUnitActiveSec=
            OnUnitSec=
            OnCalendar=weekly
            Id=oneshot.timer
            OnUnitActiveSec=infinity
            OnUnitSec=
            OnCalendar=
            """;

        var intervals = SystemdTimerSocketScanner.ParseTimerIntervalsFromShow(output);

        Assert.Equal("1min", intervals["logrotate.timer"]);
        Assert.Equal("weekly", intervals["fstrim.timer"]);
        Assert.Equal("", intervals["oneshot.timer"]);
    }

    [Fact]
    public void ParseTimerIntervalsFromShow_ParsesCurrentSystemdTimerProperties()
    {
        var output = """
            Id=rapid.timer
            TimersMonotonic={ OnBootSec=5min ; next_elapse=n/a } { OnUnitActiveSec=30s ; next_elapse=n/a }
            TimersCalendar=
            Id=logrotate.timer
            TimersMonotonic=
            TimersCalendar={ OnCalendar=*-*-* 00:00:00 ; next_elapse=Wed 2026-07-08 00:00:00 EDT }
            """;

        var intervals = SystemdTimerSocketScanner.ParseTimerIntervalsFromShow(output);

        Assert.Equal("30s", intervals["rapid.timer"]);
        Assert.Equal("*-*-* 00:00:00", intervals["logrotate.timer"]);
    }

    [Fact]
    public void ResolveTimerInterval_PrefersActiveSecThenCalendar()
    {
        Assert.Equal("30s", SystemdTimerSocketScanner.ResolveTimerInterval("30s", null, "daily"));
        Assert.Equal("daily", SystemdTimerSocketScanner.ResolveTimerInterval(null, null, "daily"));
        Assert.Equal("", SystemdTimerSocketScanner.ResolveTimerInterval("infinity", null, null));
        Assert.Equal("", SystemdTimerSocketScanner.ResolveTimerInterval(null, null, ""));
    }

    [Fact]
    public void SumDurationMicroseconds_SumsTokensOrNull()
    {
        Assert.Equal(90_000_000L, SystemdTimerSocketScanner.SumDurationMicroseconds("1min 30s"));
        Assert.Equal(500_000L, SystemdTimerSocketScanner.SumDurationMicroseconds("500ms"));
        Assert.Null(SystemdTimerSocketScanner.SumDurationMicroseconds("daily"));
    }

    [Fact]
    public void ParseSocketOutput_SetsListenAddressAndTriggerUnit()
    {
        var output = "/run/systemd/journal/dev-log systemd-journald-dev-log.socket systemd-journald.service";

        var sockets = new List<SystemdSocket>
        {
            new() { Name = "systemd-journald-dev-log.socket" }
        };

        SystemdTimerSocketScanner.ParseSocketOutput(output, sockets);

        Assert.True(sockets[0].Listening);
        Assert.Equal("/run/systemd/journal/dev-log", sockets[0].ListenAddress);
        Assert.Equal("systemd-journald.service", sockets[0].TriggerUnit);
    }

    [Fact]
    public void ParseSocketOutput_MultipleAddresses_PreservesPublicAddress()
    {
        var output = """
            0.0.0.0:8080 demo.socket demo.service
            127.0.0.1:8080 demo.socket demo.service
            """;
        var sockets = new List<SystemdSocket>
        {
            new() { Name = "demo.socket" }
        };

        SystemdTimerSocketScanner.ParseSocketOutput(output, sockets);

        Assert.Single(sockets);
        Assert.Contains("0.0.0.0:8080", sockets[0].ListenAddress);
        Assert.Contains("127.0.0.1:8080", sockets[0].ListenAddress);
        Assert.True(SystemdTimerSocketScanner.IsPublicListenAddress(sockets[0].ListenAddress));
    }

    [Theory]
    [InlineData("30s", true)]
    [InlineData("59s", true)]
    [InlineData("60s", false)]      // exactly once per minute is the threshold, not "more frequent"
    [InlineData("1min", false)]
    [InlineData("1min 30s", false)]
    [InlineData("5min", false)]
    [InlineData("1h", false)]
    [InlineData("1h 30min", false)]
    [InlineData("500ms", true)]
    [InlineData("5us", true)]
    [InlineData("daily", false)]
    [InlineData("minutely", false)]
    [InlineData("n/a", false)]
    [InlineData("", false)]
    [InlineData("30000000", true)]   // 30s expressed as bare microseconds (systemctl show form)
    [InlineData("60000000", false)]  // 60s as microseconds
    public void IsShortInterval_Various_ReturnsExpected(string interval, bool expected)
    {
        Assert.Equal(expected, SystemdTimerSocketScanner.IsShortInterval(interval));
    }

    [Theory]
    [InlineData("0.0.0.0:22", true)]
    [InlineData("[::]:22", true)]
    [InlineData(":::22", true)]
    [InlineData("*:22", true)]
    [InlineData("127.0.0.1:22", false)]
    [InlineData("/run/systemd/journal/dev-log", false)]
    [InlineData("", false)]
    public void IsPublicListenAddress_Various_ReturnsExpected(string address, bool expected)
    {
        Assert.Equal(expected, SystemdTimerSocketScanner.IsPublicListenAddress(address));
    }
}
