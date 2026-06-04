using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Core.Live;
using VulcansTrace.Linux.Engine;
using VulcansTrace.Linux.Engine.Configuration;
using VulcansTrace.Linux.Engine.Live;

namespace VulcansTrace.Linux.Avalonia.ViewModels;

/// <summary>
/// ViewModel for the Live Stream panel. Manages real-time kernel packet capture,
/// windowed analysis, and live findings display.
/// </summary>
public sealed class LiveStreamViewModel : ViewModelBase, IDisposable
{
    private readonly LiveStreamAnalyzer _analyzer;
    private readonly Func<IntensityLevel> _intensityProvider;
    private CancellationTokenSource? _resultCts;
    private Task? _resultTask;
    private IEventSource? _resolvedSource;
    private bool _disposed;
    private const int MaxLiveFindings = 1000;

    private bool _isRunning;
    private string _statusText = "Stopped";
    private string _selectedSourceName = SourceNames.Synthetic;
    private double _eventsPerSecond;
    private int _windowEventCount;
    private int _analysisRunCount;
    private int _totalDeltaFindings;

    public LiveStreamViewModel(LiveStreamAnalyzer analyzer, Func<IntensityLevel>? intensityProvider = null)
    {
        _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
        _intensityProvider = intensityProvider ?? (() => IntensityLevel.Medium);
        _analyzer.StreamFaulted += OnStreamFaulted;

        AvailableSources = new ObservableCollection<string>
        {
            SourceNames.Synthetic,
            SourceNames.PacketCapture,
            SourceNames.Nflog
        };

        LiveFindings = new ObservableCollection<Finding>();
        StartCommand = new RelayCommand(_ => Start(), _ => CanStart());
        StopCommand = new AsyncRelayCommand(
            async _ => await StopAsync(),
            _ => CanStop());
    }

    /// <summary>
    /// Raised when a new live analysis result is available.
    /// MainViewModel can subscribe to merge findings into the main grid.
    /// </summary>
    public event EventHandler<LiveAnalysisResult>? LiveResultReceived;

    public ObservableCollection<string> AvailableSources { get; }

    public ObservableCollection<Finding> LiveFindings { get; }

    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }

    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (SetField(ref _isRunning, value))
            {
                (StartCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (StopCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public string StatusText
    {
        get => _statusText;
        private set => SetField(ref _statusText, value);
    }

    public string SelectedSourceName
    {
        get => _selectedSourceName;
        set
        {
            if (SetField(ref _selectedSourceName, value))
            {
                (StartCommand as RelayCommand)?.RaiseCanExecuteChanged();
                ReleaseResolvedSource();
                UpdateStatusForSelection();
            }
        }
    }

    public double EventsPerSecond
    {
        get => _eventsPerSecond;
        private set => SetField(ref _eventsPerSecond, value);
    }

    public int WindowEventCount
    {
        get => _windowEventCount;
        private set => SetField(ref _windowEventCount, value);
    }

    public int AnalysisRunCount
    {
        get => _analysisRunCount;
        private set => SetField(ref _analysisRunCount, value);
    }

    public int TotalDeltaFindings
    {
        get => _totalDeltaFindings;
        private set => SetField(ref _totalDeltaFindings, value);
    }

    private void UpdateStatusForSelection()
    {
        if (IsRunning)
            return;

        var source = ResolveSource();
        StatusText = source.IsAvailable
            ? $"Ready: {source.DisplayName}"
            : $"Unavailable: {source.UnavailabilityReason}";
    }

    private bool CanStart() => !IsRunning && ResolveSource().IsAvailable;
    private bool CanStop() => IsRunning;

    private void Start()
    {
        if (IsRunning) return;

        var source = ResolveSource();
        if (!source.IsAvailable)
        {
            StatusText = $"Unavailable: {source.UnavailabilityReason}";
            ReleaseResolvedSource();
            return;
        }

        // Ownership transfers to the analyzer; clear our cache so we
        // don't accidentally dispose it or reuse a disposed instance.
        _resolvedSource = null;

        LiveFindings.Clear();
        TotalDeltaFindings = 0;
        AnalysisRunCount = 0;
        EventsPerSecond = 0;
        WindowEventCount = 0;

        IsRunning = true;
        StatusText = $"Capturing: {source.DisplayName}";

        try
        {
            _analyzer.Start(source, _intensityProvider());
        }
        catch (Exception ex)
        {
            (source as IDisposable)?.Dispose();
            IsRunning = false;
            StatusText = $"Stream error: {ex.Message}";
            return;
        }

        _resultCts = new CancellationTokenSource();
        _resultTask = Task.Run(() => ConsumeResultsAsync(_resultCts.Token));
    }

    /// <summary>
    /// Fast synchronous stop for disposal paths. Does not wait for tasks.
    /// </summary>
    private void Stop()
    {
        if (!IsRunning) return;

        _resultCts?.Cancel();
        _analyzer.Stop();
        _resultCts?.Dispose();
        _resultCts = null;
        _resultTask = null;

        IsRunning = false;
        StatusText = "Stopped";
    }

    /// <summary>
    /// Asynchronous stop that gracefully awaits pipeline and result-task
    /// shutdown without blocking the UI thread.
    /// </summary>
    private async Task StopAsync()
    {
        if (!IsRunning) return;

        _resultCts?.Cancel();

        await _analyzer.StopAsync().ConfigureAwait(false);

        if (_resultTask != null)
        {
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await _resultTask.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected on timeout or cancellation
            }
            catch (Exception ex)
            {
                StatusText = $"Shutdown error: {ex.Message}";
            }
        }

        _resultCts?.Dispose();
        _resultCts = null;
        _resultTask = null;

        IsRunning = false;
        StatusText = "Stopped";
    }

    private async Task ConsumeResultsAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var result in _analyzer.ResultsAsync(cancellationToken).ConfigureAwait(false))
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                Dispatcher.UIThread.Post(() =>
                {
                    EventsPerSecond = result.WindowMetrics.EventsPerSecond;
                    WindowEventCount = result.WindowMetrics.EventCount;
                    AnalysisRunCount = result.AnalysisRunCount;

                    foreach (var finding in result.DeltaFindings)
                    {
                        LiveFindings.Add(finding);
                        TotalDeltaFindings++;
                    }

                    // Evict oldest findings to prevent unbounded UI growth
                    while (LiveFindings.Count > MaxLiveFindings)
                    {
                        LiveFindings.RemoveAt(0);
                    }

                    LiveResultReceived?.Invoke(this, result);
                });
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on stop
        }
        catch (Exception ex)
        {
            Dispatcher.UIThread.Post(() =>
            {
                StatusText = $"Stream error: {ex.Message}";
                IsRunning = false;
            });
        }
    }

    private void OnStreamFaulted(object? sender, Exception ex)
    {
        Dispatcher.UIThread.Post(() =>
        {
            _resultCts?.Cancel();
            _resultCts?.Dispose();
            _resultCts = null;
            _resultTask = null;

            IsRunning = false;
            StatusText = $"Stream error: {ex.Message}";
        });
    }

    private IEventSource ResolveSource()
    {
        if (_resolvedSource != null)
            return _resolvedSource;

        _resolvedSource = SelectedSourceName switch
        {
            SourceNames.PacketCapture => new PacketCaptureEventSource(),
            SourceNames.Nflog => new NflogEventSource(),
            SourceNames.Synthetic => new SyntheticEventSource(),
            _ => throw new InvalidOperationException($"Unknown source name: '{SelectedSourceName}'")
        };
        return _resolvedSource;
    }

    private static class SourceNames
    {
        public const string Synthetic = "Synthetic Demo Stream";
        public const string PacketCapture = "Kernel Packet Capture (AF_PACKET + BPF)";
        public const string Nflog = "NFLOG Netlink (AF_NETLINK)";
    }

    private void ReleaseResolvedSource()
    {
        (_resolvedSource as IDisposable)?.Dispose();
        _resolvedSource = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _analyzer.StreamFaulted -= OnStreamFaulted;
        Stop();
        ReleaseResolvedSource();
    }
}
