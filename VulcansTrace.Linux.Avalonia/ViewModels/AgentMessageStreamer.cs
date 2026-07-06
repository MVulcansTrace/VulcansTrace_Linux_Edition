using System;
using System.Threading;
using Avalonia.Threading;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// Schedules recurring ticks for a typewriter/streaming effect.
/// Abstracted so unit tests can drive ticks manually instead of waiting on real time.
/// </summary>
internal interface ITypewriterScheduler
{
    /// <summary>
    /// Starts invoking <paramref name="tick"/> every <paramref name="interval"/>.
    /// The returned disposable stops further ticks.
    /// </summary>
    IDisposable Start(TimeSpan interval, Action tick);
}

/// <summary>
/// Production scheduler backed by a <see cref="DispatcherTimer"/> so ticks run on the UI thread.
/// </summary>
internal sealed class DispatcherTypewriterScheduler : ITypewriterScheduler
{
    public IDisposable Start(TimeSpan interval, Action tick)
    {
        var timer = new DispatcherTimer { Interval = interval };
        EventHandler handler = (_, _) => tick();
        timer.Tick += handler;
        timer.Start();

        return new ActionDisposable(() =>
        {
            timer.Stop();
            timer.Tick -= handler;
        });
    }
}

/// <summary>
/// Drives a <see cref="AgentMessageViewModel"/> so its text appears progressively,
/// like a typewriter or streaming reply.
/// </summary>
internal sealed class AgentMessageStreamer : IDisposable
{
    private readonly AgentMessageViewModel _message;
    private readonly string _fullText;
    private readonly int _charsPerTick;
    private readonly TimeSpan _tickInterval;
    private readonly ITypewriterScheduler _scheduler;
    private readonly Action? _onUpdated;
    private readonly Action? _onCompleted;
    private readonly CancellationToken _cancellationToken;
    private readonly CancellationTokenRegistration _cancellationRegistration;

    private IDisposable? _schedule;
    private int _position;
    private bool _disposed;

    public AgentMessageStreamer(
        AgentMessageViewModel message,
        string fullText,
        int charsPerTick,
        TimeSpan tickInterval,
        ITypewriterScheduler scheduler,
        Action? onUpdated = null,
        Action? onCompleted = null,
        CancellationToken cancellationToken = default)
    {
        _message = message ?? throw new ArgumentNullException(nameof(message));
        _fullText = fullText ?? throw new ArgumentNullException(nameof(fullText));
        _charsPerTick = charsPerTick > 0 ? charsPerTick : throw new ArgumentOutOfRangeException(nameof(charsPerTick));
        _tickInterval = tickInterval > TimeSpan.Zero ? tickInterval : throw new ArgumentOutOfRangeException(nameof(tickInterval));
        _scheduler = scheduler ?? throw new ArgumentNullException(nameof(scheduler));
        _onUpdated = onUpdated;
        _onCompleted = onCompleted;
        _cancellationToken = cancellationToken;

        // Order matters for the view's finalize detection: IsStreaming must read true
        // before IsStreamingPending reads false, otherwise the transition out of "queued"
        // is momentarily indistinguishable from "done".
        _message.IsStreaming = true;
        _message.StreamingFinalText = fullText;
        _message.StreamingText = string.Empty;
        _message.IsStreamingPending = false;

        _cancellationRegistration = cancellationToken.Register(Dispose);
    }

    /// <summary>
    /// Begins revealing the message text chunk by chunk.
    /// </summary>
    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _schedule = _scheduler.Start(_tickInterval, OnTick);
    }

    private void OnTick()
    {
        if (_disposed || _cancellationToken.IsCancellationRequested)
            return;

        _position += _charsPerTick;
        if (_position >= _fullText.Length)
        {
            _message.StreamingText = _fullText;
            _onUpdated?.Invoke();
            Complete();
            return;
        }

        _message.StreamingText = _fullText[.._position];
        _onUpdated?.Invoke();
    }

    /// <summary>
    /// Invoked when the final chunk is reached: commits the full text and notifies the
    /// owner so it can advance to the next message. Only natural completion advances.
    /// </summary>
    private void Complete()
    {
        if (_disposed)
            return;

        StopCore();
        _onCompleted?.Invoke();
    }

    /// <summary>
    /// Stops streaming and commits the full final text without advancing the queue.
    /// Used for cancellation, a new query pre-empting the stream, and disposal.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        StopCore();
    }

    private void StopCore()
    {
        // Guard against concurrent cancellation callback / Dispose / Complete races.
        if (_disposed)
            return;

        _disposed = true;
        _schedule?.Dispose();
        _cancellationRegistration.Dispose();
        _message.FlushStreaming(_fullText);
    }
}

/// <summary>
/// Minimal disposable that invokes an action on disposal.
/// </summary>
internal sealed class ActionDisposable : IDisposable
{
    private Action? _action;

    public ActionDisposable(Action action)
    {
        _action = action ?? throw new ArgumentNullException(nameof(action));
    }

    public void Dispose()
    {
        var action = Interlocked.Exchange(ref _action, null);
        action?.Invoke();
    }
}
