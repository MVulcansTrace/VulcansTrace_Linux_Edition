using System;
using System.Threading;
using Avalonia.Threading;
using VulcansTrace.Linux.Avalonia.ViewModels;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class AgentMessageStreamerTests
{
    /// <summary>
    /// Test scheduler that queues a tick action and exposes a synchronous <see cref="Tick"/> method.
    /// </summary>
    private sealed class ManualTypewriterScheduler : ITypewriterScheduler
    {
        private Action? _tick;

        public IDisposable Start(TimeSpan interval, Action tick)
        {
            _tick = tick;
            return new ActionDisposable(() => _tick = null);
        }

        public void Tick() => _tick?.Invoke();
    }

    [AvaloniaFact]
    public void Streamer_RevealsTextChunkByChunk()
    {
        var scheduler = new ManualTypewriterScheduler();
        var message = new AgentMessageViewModel();
        var fullText = "Hello, world!";
        using var streamer = new AgentMessageStreamer(
            message,
            fullText,
            charsPerTick: 3,
            tickInterval: TimeSpan.FromMilliseconds(1),
            scheduler);

        Assert.True(message.IsStreaming);
        Assert.Equal(fullText, message.StreamingFinalText);
        Assert.Equal(string.Empty, message.StreamingText);

        streamer.Start();
        scheduler.Tick();
        Assert.Equal("Hel", message.StreamingText);

        scheduler.Tick();
        Assert.Equal("Hello,", message.StreamingText);

        scheduler.Tick();
        Assert.Equal("Hello, wo", message.StreamingText);

        scheduler.Tick();
        Assert.Equal("Hello, world", message.StreamingText);

        scheduler.Tick();
        Assert.Equal("Hello, world!", message.Text);
        Assert.False(message.IsStreaming);
        Assert.Equal(string.Empty, message.StreamingText);

        // Extra ticks are no-ops after completion.
        scheduler.Tick();
        Assert.Equal("Hello, world!", message.Text);
        Assert.Equal(string.Empty, message.StreamingText);
    }

    [AvaloniaFact]
    public void Streamer_OnCancellation_FlushesFinalText()
    {
        var scheduler = new ManualTypewriterScheduler();
        var message = new AgentMessageViewModel();
        var fullText = "This is the final text.";
        using var cts = new CancellationTokenSource();
        var streamer = new AgentMessageStreamer(
            message,
            fullText,
            charsPerTick: 3,
            tickInterval: TimeSpan.FromMilliseconds(1),
            scheduler,
            cancellationToken: cts.Token);

        streamer.Start();
        scheduler.Tick();
        Assert.Equal("Thi", message.StreamingText);

        cts.Cancel();

        Assert.Equal(fullText, message.Text);
        Assert.False(message.IsStreaming);
        Assert.Equal(string.Empty, message.StreamingText);
    }

    [AvaloniaFact]
    public void Streamer_Dispose_FlushesFinalText()
    {
        var scheduler = new ManualTypewriterScheduler();
        var message = new AgentMessageViewModel();
        var fullText = "Dispose me.";
        var streamer = new AgentMessageStreamer(
            message,
            fullText,
            charsPerTick: 3,
            tickInterval: TimeSpan.FromMilliseconds(1),
            scheduler);

        streamer.Start();
        scheduler.Tick();
        Assert.Equal("Dis", message.StreamingText);

        streamer.Dispose();

        Assert.Equal(fullText, message.Text);
        Assert.False(message.IsStreaming);
        Assert.Equal(string.Empty, message.StreamingText);
    }

    [AvaloniaFact]
    public void Streamer_RaisesUpdatedOnEachTick()
    {
        var scheduler = new ManualTypewriterScheduler();
        var message = new AgentMessageViewModel();
        var updateCount = 0;
        using var streamer = new AgentMessageStreamer(
            message,
            "abc",
            charsPerTick: 1,
            tickInterval: TimeSpan.FromMilliseconds(1),
            scheduler,
            onUpdated: () => updateCount++);

        streamer.Start();
        scheduler.Tick(); // "a"
        Assert.Equal(1, updateCount);

        scheduler.Tick(); // "ab"
        Assert.Equal(2, updateCount);

        scheduler.Tick(); // "abc" + completion
        Assert.Equal(3, updateCount);
    }

    [AvaloniaFact]
    public void Streamer_Completed_RaisesOnCompleted()
    {
        var scheduler = new ManualTypewriterScheduler();
        var message = new AgentMessageViewModel();
        var completed = false;
        using var streamer = new AgentMessageStreamer(
            message,
            "x",
            charsPerTick: 1,
            tickInterval: TimeSpan.FromMilliseconds(1),
            scheduler,
            onCompleted: () => completed = true);

        streamer.Start();
        Assert.False(completed);

        scheduler.Tick();
        Assert.True(completed);
    }
}
