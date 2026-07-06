using System;
using VulcansTrace.Linux.Agent.Query;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class DefaultChatFilterTests
{
    [Fact]
    public void Apply_UserAndInfoMessages_AreAlwaysVisible_WhenNoSearch()
    {
        var messages = new[]
        {
            new AgentMessageViewModel { Text = "hello", IsUser = true, IsVisible = true },
            new AgentMessageViewModel { Text = "info", IsInfo = true, IsVisible = true },
            new AgentMessageViewModel { Text = "[Firewall] [High] exposed", Category = "Firewall", Severity = Severity.High, IsVisible = true }
        };

        new DefaultChatFilter().Apply(messages, new SeverityFilterOption("Critical", Severity.Critical), ChatFilterConstants.AllCategoriesFilter, null);

        Assert.True(messages[0].IsVisible);
        Assert.True(messages[1].IsVisible);
        Assert.False(messages[2].IsVisible);
    }

    [Fact]
    public void Apply_UserMessages_AreFilteredBySearch()
    {
        var messages = new[]
        {
            new AgentMessageViewModel { Text = "hello", IsUser = true, IsVisible = true },
            new AgentMessageViewModel { Text = "firewall info", IsInfo = true, IsVisible = true }
        };

        new DefaultChatFilter().Apply(messages, null, null, "firewall");

        Assert.False(messages[0].IsVisible);
        Assert.True(messages[1].IsVisible);
    }

    [Fact]
    public void Apply_SeverityFilter_HidesLowerSeverityFindingGroups()
    {
        var messages = new[]
        {
            new AgentMessageViewModel { Text = "Audit complete", IsInfo = true, IsVisible = true },
            new AgentMessageViewModel { Text = "Findings:", IsInfo = true, IsVisible = true },
            new AgentMessageViewModel { Text = "[Firewall] [High] exposed", Category = "Firewall", Severity = Severity.High, IsVisible = true },
            new AgentMessageViewModel { Text = "[SSH] [Medium] root", Category = "SSH", Severity = Severity.Medium, IsVisible = true },
            new AgentMessageViewModel { Text = "[Network] [Critical] promisc", Category = "Network", Severity = Severity.Critical, IsVisible = true }
        };

        new DefaultChatFilter().Apply(messages, new SeverityFilterOption("High & Critical only", Severity.High), ChatFilterConstants.AllCategoriesFilter, null);

        Assert.True(messages[0].IsVisible);
        Assert.True(messages[1].IsVisible);
        Assert.True(messages[2].IsVisible);
        Assert.False(messages[3].IsVisible);
        Assert.True(messages[4].IsVisible);
    }

    [Fact]
    public void Apply_CategoryFilter_HidesOtherCategories()
    {
        var messages = new[]
        {
            new AgentMessageViewModel { Text = "Audit complete", IsInfo = true, IsVisible = true },
            new AgentMessageViewModel { Text = "[Firewall] [High] exposed", Category = "Firewall", Severity = Severity.High, IsVisible = true },
            new AgentMessageViewModel { Text = "[SSH] [Medium] root", Category = "SSH", Severity = Severity.Medium, IsVisible = true },
            new AgentMessageViewModel { Text = "[Network] [Critical] promisc", Category = "Network", Severity = Severity.Critical, IsVisible = true }
        };

        new DefaultChatFilter().Apply(messages, null, "Firewall", null);

        Assert.True(messages[0].IsVisible);
        Assert.True(messages[1].IsVisible);
        Assert.False(messages[2].IsVisible);
        Assert.False(messages[3].IsVisible);
    }

    [Fact]
    public void Apply_SearchQuery_MatchesTextAndDetails()
    {
        var messages = new[]
        {
            new AgentMessageViewModel { Text = "firewall rule found", IsVisible = true },
            new AgentMessageViewModel { Text = "network exposed", Details = "firewall disabled", IsVisible = true },
            new AgentMessageViewModel { Text = "ssh root", IsVisible = true }
        };

        new DefaultChatFilter().Apply(messages, null, null, "firewall");

        Assert.True(messages[0].IsVisible);
        Assert.True(messages[1].IsVisible);
        Assert.False(messages[2].IsVisible);
    }

    [Fact]
    public void Apply_SearchAndSeverityCompose()
    {
        var messages = new[]
        {
            new AgentMessageViewModel { Text = "[Firewall] [High] exposed", Category = "Firewall", Severity = Severity.High, IsVisible = true },
            new AgentMessageViewModel { Text = "[Firewall] [Medium] log", Category = "Firewall", Severity = Severity.Medium, IsVisible = true },
            new AgentMessageViewModel { Text = "[SSH] [High] firewall key", Category = "SSH", Severity = Severity.High, IsVisible = true }
        };

        new DefaultChatFilter().Apply(messages, new SeverityFilterOption("High", Severity.High), "Firewall", "firewall");

        Assert.True(messages[0].IsVisible);
        Assert.False(messages[1].IsVisible);
        Assert.False(messages[2].IsVisible);
    }

    [Fact]
    public void Apply_NullOrEmptySearchQuery_ShowsAllPassingFilterMessages()
    {
        var messages = new[]
        {
            new AgentMessageViewModel { Text = "abc", IsVisible = true },
            new AgentMessageViewModel { Text = "def", IsVisible = true }
        };

        new DefaultChatFilter().Apply(messages, null, null, "");

        Assert.True(messages[0].IsVisible);
        Assert.True(messages[1].IsVisible);
    }

    [Fact]
    public void Apply_NullLists_AreTolerated()
    {
        var messages = Array.Empty<AgentMessageViewModel>();

        new DefaultChatFilter().Apply(messages, null, null, null);

        Assert.Empty(messages);
    }
}
