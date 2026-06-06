using System;
using System.Collections.Generic;
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
    private readonly EventHandler<LiveAnalysisResult> _resultProducedHandler;
    private readonly object _demoFindingsLock = new();
    private readonly List<Finding> _currentDemoFindings = new();
    private IReadOnlyList<Finding> _latestDemoAnalysisFindings = Array.Empty<Finding>();
    private IEventSource? _resolvedSource;
    private bool _disposed;
    private const int MaxLiveFindings = 1000;

    private bool _isRunning;
    private string _statusText = "Stopped";
    private string _selectedSourceName = SourceNames.DemoRandom;
    private double _eventsPerSecond;
    private int _windowEventCount;
    private int _analysisRunCount;
    private int _totalDeltaFindings;
    private int _scenarioDurationSeconds = 60;
    private CancellationTokenSource? _autoStopCts;
    private Task? _autoStopTask;
    private bool _isAutoStopping;
    private int _isStopping;
    private DateTime _demoStartTime;

    public LiveStreamViewModel(LiveStreamAnalyzer analyzer, Func<IntensityLevel>? intensityProvider = null)
    {
        _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
        _intensityProvider = intensityProvider ?? (() => IntensityLevel.Medium);
        _analyzer.StreamFaulted += OnStreamFaulted;
        _resultProducedHandler = (_, result) => OnResultProduced(result);
        _analyzer.ResultProduced += _resultProducedHandler;

        AvailableSources = new ObservableCollection<string>
        {
            SourceNames.DemoRandom,
            SourceNames.DemoC2Beaconing,
            SourceNames.DemoSshBruteforce,
            SourceNames.DemoPrivilegeEscalation,
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

    /// <summary>
    /// Raised when a scenario demo completes (auto-stop or manual stop).
    /// </summary>
    public event EventHandler<DemoCompletedEventArgs>? DemoCompleted;

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
                ScenarioDurationSeconds = GetRecommendedDuration(value);
                OnPropertyChanged(nameof(IsScenarioSource));
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

    /// <summary>
    /// Duration in seconds for scenario demo runs.
    /// </summary>
    public int ScenarioDurationSeconds
    {
        get => _scenarioDurationSeconds;
        set => SetField(ref _scenarioDurationSeconds, value);
    }

    /// <summary>
    /// Whether the currently selected source is a demo scenario.
    /// </summary>
    public bool IsScenarioSource => SelectedSourceName == SourceNames.DemoRandom
                                 || SelectedSourceName == SourceNames.DemoC2Beaconing
                                 || SelectedSourceName == SourceNames.DemoSshBruteforce
                                 || SelectedSourceName == SourceNames.DemoPrivilegeEscalation;

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
        lock (_demoFindingsLock)
        {
            _currentDemoFindings.Clear();
            _latestDemoAnalysisFindings = Array.Empty<Finding>();
        }

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

        if (IsScenarioSource && ScenarioDurationSeconds > 0)
        {
            _demoStartTime = DateTime.UtcNow;
            _autoStopCts = new CancellationTokenSource();
            _isAutoStopping = false;
            _autoStopTask = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(ScenarioDurationSeconds), _autoStopCts.Token).ConfigureAwait(false);
                    _isAutoStopping = true;
                    await StopAsync().ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected when user clicks Stop manually
                }
            });
        }
    }

    /// <summary>
    /// Fast synchronous stop for disposal paths. Does not wait for tasks.
    /// </summary>
    private void Stop()
    {
        if (!IsRunning) return;

        _analyzer.Stop();

        IsRunning = false;
        StatusText = "Stopped";
    }

    /// <summary>
    /// Asynchronous stop that gracefully awaits pipeline and result-task
    /// shutdown without blocking the UI thread.
    /// </summary>
    private async Task StopAsync()
    {
        if (Interlocked.CompareExchange(ref _isStopping, 1, 0) != 0)
            return;

        try
        {
            if (!IsRunning) return;

            var wasAutoStop = _isAutoStopping;
            _isAutoStopping = false;
            _autoStopCts?.Cancel();

            await _analyzer.StopAsync().ConfigureAwait(false);

            _autoStopCts?.Dispose();
            _autoStopCts = null;
            _autoStopTask = null;

            IsRunning = false;

            if (IsScenarioSource)
            {
                var duration = DateTime.UtcNow - _demoStartTime;
                StatusText = $"Demo complete: {TotalDeltaFindings} finding(s)";
                IReadOnlyList<Finding> demoFindings;
                lock (_demoFindingsLock)
                {
                    demoFindings = _latestDemoAnalysisFindings.Count > 0
                        ? _latestDemoAnalysisFindings.ToList()
                        : _currentDemoFindings.ToList();
                }

                var args = new DemoCompletedEventArgs(
                    SelectedSourceName,
                    demoFindings,
                    wasAutoStop,
                    duration,
                    _demoStartTime,
                    DateTime.UtcNow);
                Dispatcher.UIThread.Post(() => DemoCompleted?.Invoke(this, args));
            }
            else
            {
                StatusText = "Stopped";
            }
        }
        finally
        {
            Interlocked.Exchange(ref _isStopping, 0);
        }
    }

    private void OnResultProduced(LiveAnalysisResult result)
    {
        if (IsScenarioSource && result.DeltaFindings.Count > 0)
        {
            lock (_demoFindingsLock)
            {
                _currentDemoFindings.AddRange(result.DeltaFindings);
                _latestDemoAnalysisFindings = result.Analysis.Findings.ToList();
            }
        }
        else if (IsScenarioSource)
        {
            lock (_demoFindingsLock)
            {
                _latestDemoAnalysisFindings = result.Analysis.Findings.ToList();
            }
        }

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

    private void OnStreamFaulted(object? sender, Exception ex)
    {
        Dispatcher.UIThread.Post(() =>
        {
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
            SourceNames.DemoRandom => new SyntheticEventSource(),
            SourceNames.DemoC2Beaconing => new SyntheticEventSource(DemoPatterns.For(DemoScenario.C2Beaconing)),
            SourceNames.DemoSshBruteforce => new SyntheticEventSource(DemoPatterns.For(DemoScenario.SshBruteforce)),
            SourceNames.DemoPrivilegeEscalation => new SyntheticEventSource(DemoPatterns.For(DemoScenario.PrivilegeEscalation)),
            _ => throw new InvalidOperationException($"Unknown source name: '{SelectedSourceName}'")
        };
        return _resolvedSource;
    }

    private static int GetRecommendedDuration(string sourceName)
    {
        return sourceName switch
        {
            SourceNames.DemoC2Beaconing => 150,
            _ => 60
        };
    }

    private static class SourceNames
    {
        public const string DemoRandom = "Demo: Random Mix";
        public const string DemoC2Beaconing = "Demo: C2 Beaconing";
        public const string DemoSshBruteforce = "Demo: SSH Brute Force";
        public const string DemoPrivilegeEscalation = "Demo: Privilege Escalation";
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
        _analyzer.ResultProduced -= _resultProducedHandler;
        Stop();
        ReleaseResolvedSource();
    }
}
