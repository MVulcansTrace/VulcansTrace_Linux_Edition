using VulcansTrace.Linux.Agent.Remediation;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Remediation;

public class FailureResponseTableTests
{
    private readonly FailureResponseTable _table = new();

    [Fact]
    public void BuildResponse_ForMissingDependency_IncludesInstallGuidance()
    {
        var response = _table.BuildResponse("FW-001", "iptables isn't installed", "sudo iptables -P INPUT DROP");

        Assert.Contains("FW-001", response);
        Assert.Contains("MissingDependency", response);
        Assert.Contains("iptables", response);
    }

    [Fact]
    public void BuildResponse_ForPermissionIssue_IncludesSudoGuidance()
    {
        var response = _table.BuildResponse("FW-001", "permission denied", "sudo iptables -P INPUT DROP");

        Assert.Contains("PermissionIssue", response);
        Assert.Contains("sudo", response);
    }

    [Fact]
    public void BuildResponse_ForServiceMissing_IncludesSystemctlGuidance()
    {
        var response = _table.BuildResponse("SRV-001", "service not found", "systemctl stop telnet");

        Assert.Contains("ServiceMissing", response);
        Assert.Contains("systemctl enable --now", response);
    }

    [Fact]
    public void BuildResponse_ForUnknownFailure_FallsBackToCategoryGuidance()
    {
        var response = _table.BuildResponse("FW-001", "something weird happened", null);

        Assert.Contains("FW-001", response);
        Assert.Contains("UnknownFailure", response);
    }

    [Fact]
    public void BuildResponse_ForSshMissingDependency_IncludesOpenSshServer()
    {
        var response = _table.BuildResponse("SSH-001", "command not found", "systemctl restart sshd");

        Assert.Contains("MissingDependency", response);
        Assert.Contains("openssh-server", response);
    }

    [Fact]
    public void BuildResponse_CleanedReasonUnknown_FallsBackToOriginalText()
    {
        // "to start service" loses the "failed to start" trigger, but the original query has it.
        var response = _table.BuildResponse(
            "SRV-001",
            failureReason: "to start service",
            attemptedCommand: "systemctl start auditd",
            originalErrorText: "step 1 failed to start service");

        Assert.Contains("ServiceMissing", response);
        Assert.Contains("systemctl enable --now", response);
    }
}
