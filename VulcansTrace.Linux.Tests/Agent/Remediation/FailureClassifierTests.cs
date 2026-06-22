using VulcansTrace.Linux.Agent.Remediation;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Remediation;

public class FailureClassifierTests
{
    private readonly FailureClassifier _classifier = new();

    [Theory]
    [InlineData("command not found: iptables", FailureCategory.MissingDependency)]
    [InlineData("iptables isn't installed", FailureCategory.MissingDependency)]
    [InlineData("no such file or directory", FailureCategory.MissingDependency)]
    [InlineData("permission denied", FailureCategory.PermissionIssue)]
    [InlineData("operation not permitted", FailureCategory.PermissionIssue)]
    [InlineData("access denied", FailureCategory.PermissionIssue)]
    [InlineData("already exists", FailureCategory.AlreadyConfigured)]
    [InlineData("duplicate rule", FailureCategory.AlreadyConfigured)]
    [InlineData("service not found", FailureCategory.ServiceMissing)]
    [InlineData("unit not found", FailureCategory.ServiceMissing)]
    [InlineData("failed to start ssh.service", FailureCategory.ServiceMissing)]
    [InlineData("syntax error", FailureCategory.MalformedCommand)]
    [InlineData("invalid argument", FailureCategory.MalformedCommand)]
    [InlineData("unrecognized option", FailureCategory.MalformedCommand)]
    [InlineData("something weird happened", FailureCategory.UnknownFailure)]
    [InlineData("", FailureCategory.UnknownFailure)]
    [InlineData(null, FailureCategory.UnknownFailure)]
    public void Classify_MapsErrorTextToCategory(string? errorText, FailureCategory expected)
    {
        Assert.Equal(expected, _classifier.Classify(errorText));
    }
}
