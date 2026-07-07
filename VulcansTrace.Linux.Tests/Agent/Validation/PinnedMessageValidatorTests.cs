using VulcansTrace.Linux.Agent.Messages;
using VulcansTrace.Linux.Agent.Validation;
using Xunit;

namespace VulcansTrace.Linux.Tests.Agent.Validation;

public class PinnedMessageValidatorTests
{
    private readonly PinnedMessageValidator _validator = new();

    [Fact]
    public void ValidMessage_Passes()
    {
        var message = CreateValidMessage();

        var result = _validator.Validate(message);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData(nameof(PinnedMessage.MessageId))]
    [InlineData(nameof(PinnedMessage.Text))]
    public void RequiredField_Empty_Fails(string propertyName)
    {
        var message = propertyName switch
        {
            nameof(PinnedMessage.MessageId) => CreateValidMessage() with { MessageId = "" },
            nameof(PinnedMessage.Text) => CreateValidMessage() with { Text = "" },
            _ => CreateValidMessage()
        };

        var result = _validator.Validate(message);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == propertyName);
    }

    [Fact]
    public void Notes_MayBeEmpty()
    {
        var message = CreateValidMessage() with { Notes = "" };

        var result = _validator.Validate(message);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void TimestampUtc_NonUtc_Fails()
    {
        var message = CreateValidMessage() with { TimestampUtc = DateTime.Now };

        var result = _validator.Validate(message);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == nameof(PinnedMessage.TimestampUtc));
    }

    [Fact]
    public void PinnedAtUtc_NonUtc_Fails()
    {
        var message = CreateValidMessage() with { PinnedAtUtc = DateTime.Now };

        var result = _validator.Validate(message);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == nameof(PinnedMessage.PinnedAtUtc));
    }

    [Fact]
    public void MessageId_TooLong_Fails()
    {
        var message = CreateValidMessage() with { MessageId = new string('a', 129) };

        var result = _validator.Validate(message);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Notes_TooLong_Fails()
    {
        var message = CreateValidMessage() with { Notes = new string('a', 4001) };

        var result = _validator.Validate(message);

        Assert.False(result.IsValid);
    }

    private static PinnedMessage CreateValidMessage()
    {
        return new PinnedMessage
        {
            MessageId = Guid.NewGuid().ToString("N"),
            IsUser = false,
            Text = "Hello",
            Details = "details",
            Category = "Firewall",
            Severity = "High",
            IsInfo = true,
            IsError = false,
            IsProse = true,
            TimestampUtc = DateTime.UtcNow,
            PinnedAtUtc = DateTime.UtcNow,
            Notes = "note"
        };
    }
}
