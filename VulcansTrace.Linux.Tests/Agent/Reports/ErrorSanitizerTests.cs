using System;
using VulcansTrace.Linux.Agent.Reports;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Reports;

public class ErrorSanitizerTests
{
    [Fact]
    public void Sanitize_ProcessStartFailure_DropsAbsoluteWorkingDirectory()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var raw = $"An error occurred trying to start process 'iptables' with working directory '{home}/Projects/VulcansTrace-Computer-Use'. No such file or directory";

        var result = ErrorSanitizer.Sanitize(raw);

        Assert.Contains("iptables", result, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("could not be started", result, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("working directory", result, StringComparison.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(home))
            Assert.DoesNotContain(home, result, StringComparison.Ordinal);
    }

    [Fact]
    public void Sanitize_WrappedProcessStartFailure_IsCollapsed()
    {
        var raw = "Failed to start process: An error occurred trying to start process 'nft' with working directory '/root/x'. No such file or directory";

        var result = ErrorSanitizer.Sanitize(raw);

        // The process-start signature is rewritten to the exact canned message, dropping both the
        // wrapping "Failed to start process:" lead-in and the "/root/x" working-directory path.
        Assert.Equal("The tool 'nft' could not be started (it may not be installed or is not on PATH).", result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Sanitize_NullOrWhitespace_ReturnsEmpty(string? input)
    {
        Assert.Equal(string.Empty, ErrorSanitizer.Sanitize(input));
    }

    [Fact]
    public void Sanitize_ScrubsHomeDirectoryPrefix()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home))
            return; // Environment without a home profile; nothing to scrub.

        var result = ErrorSanitizer.Sanitize($"Failed reading {home}/.config/app/settings.json");

        Assert.DoesNotContain(home, result, StringComparison.Ordinal);
        Assert.Contains("~/.config/app/settings.json", result, StringComparison.Ordinal);
    }

    [Fact]
    public void SanitizeException_ProcessStartWin32Exception_IsSanitized()
    {
        var ex = new System.ComponentModel.Win32Exception(
            2,
            "An error occurred trying to start process 'iptables' with working directory '/home/u'. No such file or directory");

        var result = ErrorSanitizer.SanitizeException(ex);

        Assert.Contains("iptables", result, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("working directory", result, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SanitizeOptional_NullOrWhitespace_ReturnsNull(string? input)
    {
        Assert.Null(ErrorSanitizer.SanitizeOptional(input));
    }

    [Fact]
    public void SanitizeOptional_ProcessStartFailure_ReturnsSanitized()
    {
        var raw = "An error occurred trying to start process 'iptables' with working directory '/home/u/x'. No such file or directory";

        var result = ErrorSanitizer.SanitizeOptional(raw);

        Assert.NotNull(result);
        Assert.Equal("The tool 'iptables' could not be started (it may not be installed or is not on PATH).", result);
    }

    [Fact]
    public void SanitizeOptional_HomePath_ReturnsScrubbed()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(home))
            return;

        var result = ErrorSanitizer.SanitizeOptional($"Could not save to {home}/.config/app/state.json: disk full");

        Assert.NotNull(result);
        Assert.DoesNotContain(home, result, StringComparison.Ordinal);
        Assert.Contains("~/.config/app/state.json", result, StringComparison.Ordinal);
    }
}
