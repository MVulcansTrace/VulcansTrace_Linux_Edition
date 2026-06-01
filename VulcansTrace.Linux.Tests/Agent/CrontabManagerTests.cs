using VulcansTrace.Linux.Agent.Scheduling;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent;

public class CrontabManagerTests
{
    [Fact]
    public void BuildRunCommand_QuotesExecutableAndScheduleId()
    {
        var command = CrontabManager.BuildRunCommand("/opt/VulcansTrace/vulcanstrace", "sched-001");

        Assert.Equal("'/opt/VulcansTrace/vulcanstrace' schedule run --id 'sched-001'", command);
    }

    [Fact]
    public void BuildRunCommand_EscapesSingleQuotes()
    {
        var command = CrontabManager.BuildRunCommand("/opt/Vulcan's Trace/vulcanstrace", "schedule'001");

        Assert.Equal("'/opt/Vulcan'\\''s Trace/vulcanstrace' schedule run --id 'schedule'\\''001'", command);
    }

    [Fact]
    public void BuildRunCommand_RejectsEmptyExecutable()
    {
        Assert.Throws<ArgumentException>(() => CrontabManager.BuildRunCommand("", "sched-001"));
    }

    [Fact]
    public void BuildRunCommand_RejectsEmptyScheduleId()
    {
        Assert.Throws<ArgumentException>(() => CrontabManager.BuildRunCommand("vulcanstrace", ""));
    }
}
