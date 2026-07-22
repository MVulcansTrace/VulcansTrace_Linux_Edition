using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using VulcansTrace.Linux.Avalonia.Controls;
using VulcansTrace.Linux.Avalonia.Services;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Views;

public partial class AgentView : UserControl
{
    private const double CompactInspectorThreshold = 1040;

    private AgentViewModel? _viewModel;
    private ListBox? _chatListBox;
    private ScrollViewer? _scrollViewer;
    private TextBox? _slashHelpSearchBox;
    private TextBox? _chatSearchBox;
    private AgentComposer? _agentComposer;
    private Grid? _agentLayout;
    private Border? _inspectorPanel;
    private Border? _inspectorScrim;
    private Border? _inspectorDrawerHeader;
    private Button? _inspectorToggleButton;
    private Ellipse? _traceCompletionPulse;
    private Border? _tracePulseLine;
    private bool _isCompactInspector;
    private bool _isInspectorDrawerOpen;
    private bool _responsiveLayoutInitialized;
    private CancellationTokenSource? _stateTransitionCts;
    private readonly HashSet<AgentMessageViewModel> _streamingMessageSubscriptions = new();

    public AgentView()
    {
        InitializeComponent();
        _chatListBox = this.FindControl<ListBox>("ChatListBox");
        _slashHelpSearchBox = this.FindControl<TextBox>("SlashHelpSearchBox");
        _chatSearchBox = this.FindControl<TextBox>("ChatSearchBox");
        _agentComposer = this.FindControl<AgentComposer>("AgentComposer");
        _agentLayout = this.FindControl<Grid>("AgentLayout");
        _inspectorPanel = this.FindControl<Border>("InspectorPanel");
        _inspectorScrim = this.FindControl<Border>("InspectorScrim");
        _inspectorDrawerHeader = this.FindControl<Border>("InspectorDrawerHeader");
        _inspectorToggleButton = this.FindControl<Button>("InspectorToggleButton");
        _traceCompletionPulse = this.FindControl<Ellipse>("TraceCompletionPulse");
        _tracePulseLine = this.FindControl<Border>("TracePulseLine");
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (_viewModel is not null)
        {
            _viewModel.Messages.CollectionChanged -= OnMessagesCollectionChanged;
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            _viewModel.ComposerFocusRequested -= OnComposerFocusRequested;
            DetachStreamingMessageSubscriptions();
        }

        _viewModel = DataContext as AgentViewModel;
        if (_viewModel is not null)
        {
            _viewModel.Messages.CollectionChanged += OnMessagesCollectionChanged;
            _viewModel.PropertyChanged += OnViewModelPropertyChanged;
            _viewModel.ComposerFocusRequested += OnComposerFocusRequested;
            AttachStreamingMessageSubscriptions(_viewModel.Messages.Where(message =>
                message.IsProse && !message.IsUser && (message.IsStreaming || message.IsStreamingPending)));
        }
    }

    protected override void OnLoaded(RoutedEventArgs e)
    {
        base.OnLoaded(e);
        EnsureScrollViewer();
        UpdateResponsiveLayout(Bounds.Width);
    }

    protected override void OnUnloaded(RoutedEventArgs e)
    {
        base.OnUnloaded(e);

        if (_viewModel is not null)
        {
            _viewModel.Messages.CollectionChanged -= OnMessagesCollectionChanged;
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            _viewModel.ComposerFocusRequested -= OnComposerFocusRequested;
            _viewModel = null;
        }

        DetachStreamingMessageSubscriptions();
        _stateTransitionCts?.Cancel();
        _stateTransitionCts = null;
        _scrollViewer = null;
    }

    /// <inheritdoc />
    protected override void OnSizeChanged(SizeChangedEventArgs e)
    {
        base.OnSizeChanged(e);
        UpdateResponsiveLayout(e.NewSize.Width);
    }

    /// <inheritdoc />
    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape && _isCompactInspector && _isInspectorDrawerOpen)
        {
            SetInspectorDrawerOpen(false);
            e.Handled = true;
            return;
        }

        base.OnKeyDown(e);
    }

    private void OnInspectorToggleClick(object? sender, RoutedEventArgs e) =>
        SetInspectorDrawerOpen(!_isInspectorDrawerOpen);

    private void OnInspectorCloseClick(object? sender, RoutedEventArgs e) =>
        SetInspectorDrawerOpen(false);

    private void OnInspectorScrimPressed(object? sender, PointerPressedEventArgs e)
    {
        SetInspectorDrawerOpen(false);
        e.Handled = true;
    }

    private void UpdateResponsiveLayout(double width)
    {
        if (_agentLayout is null || _inspectorPanel is null ||
            _inspectorScrim is null || _inspectorDrawerHeader is null ||
            _inspectorToggleButton is null || width <= 0)
            return;

        var useCompactInspector = width < CompactInspectorThreshold;
        if (_responsiveLayoutInitialized && useCompactInspector == _isCompactInspector)
        {
            if (useCompactInspector)
                _inspectorPanel.Width = Math.Min(360, Math.Max(300, width - 24));
            return;
        }

        _responsiveLayoutInitialized = true;
        _isCompactInspector = useCompactInspector;
        _agentLayout.ColumnDefinitions = new ColumnDefinitions(
            useCompactInspector ? "*" : "*,320");
        Grid.SetColumn(_inspectorPanel, useCompactInspector ? 0 : 1);

        _inspectorToggleButton.IsVisible = useCompactInspector;
        _inspectorDrawerHeader.IsVisible = useCompactInspector;
        _inspectorPanel.HorizontalAlignment = useCompactInspector
            ? HorizontalAlignment.Right
            : HorizontalAlignment.Stretch;
        _inspectorPanel.Width = useCompactInspector
            ? Math.Min(360, Math.Max(300, width - 24))
            : double.NaN;
        _inspectorPanel.BorderBrush = useCompactInspector
            ? this.FindResource("VtBorderDefaultBrush") as IBrush
            : null;
        _inspectorPanel.BorderThickness = useCompactInspector
            ? new Thickness(1, 0, 0, 0)
            : new Thickness(0);

        // The dock is always present at wide widths. Entering compact mode
        // closes it so the conversation remains the primary surface.
        SetInspectorDrawerOpen(!useCompactInspector);
    }

    private void SetInspectorDrawerOpen(bool isOpen)
    {
        _isInspectorDrawerOpen = isOpen;
        if (_inspectorPanel is null || _inspectorScrim is null)
            return;

        _inspectorPanel.IsVisible = !_isCompactInspector || isOpen;
        _inspectorScrim.IsVisible = _isCompactInspector && isOpen;
    }

    internal bool TryCloseInspectorDrawer()
    {
        if (!_isCompactInspector || !_isInspectorDrawerOpen)
            return false;

        SetInspectorDrawerOpen(false);
        return true;
    }

    private void OnComposerFocusRequested(object? sender, EventArgs e) => _agentComposer?.FocusInput();

    private void EnsureScrollViewer()
    {
        if (_scrollViewer is not null || _chatListBox is null)
            return;

        _scrollViewer = _chatListBox.GetVisualDescendants().OfType<ScrollViewer>().FirstOrDefault();
    }

    private void OnSlashHelpKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not AgentViewModel vm)
            return;

        // Ctrl+K toggles the help popup closed even when focus is in the search box.
        if (e.Key == Key.K && e.KeyModifiers.HasFlag(KeyModifiers.Control))
        {
            vm.CloseSlashHelpCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Escape)
        {
            vm.CloseSlashHelpCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Down)
        {
            vm.SelectNextSlashHelpCommand();
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Up)
        {
            vm.SelectPreviousSlashHelpCommand();
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Enter && vm.SelectedSlashHelpCommand is not null)
        {
            vm.ExecuteSlashCommandCommand.Execute(vm.SelectedSlashHelpCommand);
            e.Handled = true;
        }
    }

    private void OnChatSearchKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            if (DataContext is AgentViewModel vm)
            {
                vm.ClearChatSearchCommand.Execute(null);
            }

            e.Handled = true;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AgentViewModel.IsBusy) && _viewModel?.IsBusy == true)
        {
            // When the agent starts responding, re-pin to the bottom so the user sees the
            // incoming messages. A short delay lets the busy indicator layout first.
            Dispatcher.UIThread.Post(() => ScrollChatToEnd(force: true), DispatcherPriority.Background);
        }
        else if (e.PropertyName == nameof(AgentViewModel.IsSlashHelpOpen))
        {
            if (_viewModel?.IsSlashHelpOpen == true)
            {
                // Focus the search box when the help popup opens so the user can type immediately.
                Dispatcher.UIThread.Post(() => _slashHelpSearchBox?.Focus(), DispatcherPriority.Background);
            }
        }
        else if (e.PropertyName == nameof(AgentViewModel.CurrentPageState) && _viewModel is not null)
        {
            var state = _viewModel.CurrentPageState;
            Dispatcher.UIThread.Post(
                () => StartStateTransition(state),
                DispatcherPriority.Background);
        }
    }

    private void StartStateTransition(AgentPageState state)
    {
        var next = new CancellationTokenSource();
        var previous = Interlocked.Exchange(ref _stateTransitionCts, next);
        previous?.Cancel();
        _ = AnimateStateTransitionAsync(state, next);
    }

    private async Task AnimateStateTransitionAsync(
        AgentPageState state,
        CancellationTokenSource animationCts)
    {
        if (!MotionSettings.IsEnabled)
        {
            CompleteStateTransition(animationCts);
            return;
        }

        var artifact = state switch
        {
            AgentPageState.Running => this.FindControl<Border>("RunningArtifact"),
            AgentPageState.Results => this.FindControl<Grid>("ResultsArtifact") as Control,
            AgentPageState.Error => this.FindControl<Border>("ErrorArtifact"),
            _ => this.FindControl<Border>("IdleArtifact")
        };

        if (artifact is null)
        {
            CompleteStateTransition(animationCts);
            return;
        }

        var token = animationCts.Token;
        var artifactAnimation = new Animation
        {
            Duration = TimeSpan.FromMilliseconds(190),
            Easing = new CubicEaseOut(),
            Children =
            {
                new KeyFrame
                {
                    Setters =
                    {
                        new Setter(Visual.OpacityProperty, 0.0),
                        new Setter(Visual.RenderTransformProperty, new TranslateTransform(0, -6))
                    },
                    KeyTime = TimeSpan.Zero
                },
                new KeyFrame
                {
                    Setters =
                    {
                        new Setter(Visual.OpacityProperty, 1.0),
                        new Setter(Visual.RenderTransformProperty, new TranslateTransform(0, 0))
                    },
                    KeyTime = TimeSpan.FromMilliseconds(190)
                }
            }
        };

        var lineAnimation = new Animation
        {
            Duration = TimeSpan.FromMilliseconds(220),
            Easing = new CubicEaseOut(),
            Children =
            {
                new KeyFrame
                {
                    Setters = { new Setter(Visual.OpacityProperty, 0.2) },
                    KeyTime = TimeSpan.Zero
                },
                new KeyFrame
                {
                    Setters = { new Setter(Visual.OpacityProperty, 0.72) },
                    KeyTime = TimeSpan.FromMilliseconds(220)
                }
            }
        };

        try
        {
            var animations = new List<Task> { artifactAnimation.RunAsync(artifact, token) };
            if (_tracePulseLine is not null)
                animations.Add(lineAnimation.RunAsync(_tracePulseLine, token));
            if (state == AgentPageState.Results && _traceCompletionPulse is not null)
                animations.Add(CreateCompletionPulseAnimation().RunAsync(_traceCompletionPulse, token));
            await Task.WhenAll(animations);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // A newer state owns the visual transition.
        }
        catch (Exception) when (token.IsCancellationRequested)
        {
            // Avalonia animation teardown can surface cancellation as a generic exception.
        }
        catch (Exception)
        {
            // Motion is optional; a renderer-specific animation failure must not
            // interrupt the Agent workflow.
        }
        finally
        {
            CompleteStateTransition(animationCts);
        }
    }

    private static Animation CreateCompletionPulseAnimation() => new()
    {
        Duration = TimeSpan.FromMilliseconds(420),
        Easing = new CubicEaseOut(),
        Children =
        {
            new KeyFrame
            {
                Setters =
                {
                    new Setter(Visual.OpacityProperty, 0.75),
                    new Setter(Visual.RenderTransformProperty, new ScaleTransform(0.92, 0.92))
                },
                KeyTime = TimeSpan.Zero
            },
            new KeyFrame
            {
                Setters =
                {
                    new Setter(Visual.OpacityProperty, 0.0),
                    new Setter(Visual.RenderTransformProperty, new ScaleTransform(1.35, 1.35))
                },
                KeyTime = TimeSpan.FromMilliseconds(420)
            }
        }
    };

    private void CompleteStateTransition(CancellationTokenSource animationCts)
    {
        Interlocked.CompareExchange(ref _stateTransitionCts, null, animationCts);
        animationCts.Dispose();
    }

    private void OnMessagesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Reset)
        {
            DetachStreamingMessageSubscriptions();
            return;
        }

        if (e.Action == NotifyCollectionChangedAction.Remove && e.OldItems is not null)
        {
            DetachStreamingMessageSubscriptions(e.OldItems.OfType<AgentMessageViewModel>());
            return;
        }

        if (e.Action != NotifyCollectionChangedAction.Add || e.NewItems is null)
            return;

        var isUserMessage = e.NewItems.OfType<AgentMessageViewModel>().Any(m => m.IsUser);
        // Card messages (summary/finding/more-link) arrive outside the conversation flow:
        // no user message precedes them, so the near-bottom gate would strand the view
        // at the top. Force the scroll for them.
        var isCardMessage = e.NewItems.OfType<AgentMessageViewModel>().Any(m =>
            m is AnalysisSummaryCardMessageViewModel or FindingCardMessageViewModel or MoreFindingsLinkMessageViewModel);

        // Subscribe to prose messages (set at add time) so queued bubbles that begin
        // streaming later still drive the per-tick auto-scroll.
        AttachStreamingMessageSubscriptions(e.NewItems.OfType<AgentMessageViewModel>().Where(message =>
            message.IsProse && !message.IsUser));

        // Defer scrolling until layout has updated with the new item.
        Dispatcher.UIThread.Post(() => ScrollChatToEnd(force: isUserMessage || isCardMessage), DispatcherPriority.Background);
    }

    private void OnStreamingMessagePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not AgentMessageViewModel message)
            return;

        if (e.PropertyName == nameof(AgentMessageViewModel.StreamingText))
        {
            Dispatcher.UIThread.Post(() => ScrollChatToEnd(force: false), DispatcherPriority.Background);
            return;
        }

        // A streaming message is finalized once it is neither actively streaming nor queued.
        // Drop the subscription then. Either transition (stream finishing, or a queued message
        // being revealed) can change what is on screen, so post a scroll in both cases.
        var becameInactive = e.PropertyName == nameof(AgentMessageViewModel.IsStreaming) && !message.IsStreaming;
        var becameRevealed = e.PropertyName == nameof(AgentMessageViewModel.IsStreamingPending) && !message.IsStreamingPending;
        if (becameInactive || becameRevealed)
        {
            if (!message.IsStreaming && !message.IsStreamingPending)
            {
                _ = _streamingMessageSubscriptions.Remove(message);
                message.PropertyChanged -= OnStreamingMessagePropertyChanged;
            }

            Dispatcher.UIThread.Post(() => ScrollChatToEnd(force: false), DispatcherPriority.Background);
        }
    }

    private void AttachStreamingMessageSubscriptions(IEnumerable<AgentMessageViewModel> messages)
    {
        foreach (var message in messages)
        {
            if (_streamingMessageSubscriptions.Add(message))
            {
                message.PropertyChanged += OnStreamingMessagePropertyChanged;
            }
        }
    }

    private void DetachStreamingMessageSubscriptions(IEnumerable<AgentMessageViewModel>? messages = null)
    {
        var targets = messages?.ToList() ?? _streamingMessageSubscriptions.ToList();
        foreach (var message in targets)
        {
            if (_streamingMessageSubscriptions.Remove(message))
            {
                message.PropertyChanged -= OnStreamingMessagePropertyChanged;
            }
        }
    }

    private void ScrollChatToEnd(bool force = false)
    {
        var listBox = _chatListBox;
        if (listBox is null || listBox.Items.Count == 0)
            return;

        EnsureScrollViewer();

        if (!force && !IsScrolledToBottom())
            return;

        listBox.ScrollIntoView(listBox.Items.Count - 1);
    }

    private bool IsScrolledToBottom()
    {
        // If the ScrollViewer is not available yet, assume the user is at the bottom.
        if (_scrollViewer is null)
            return true;

        var extent = _scrollViewer.Extent.Height;
        var viewport = _scrollViewer.Viewport.Height;
        var offset = _scrollViewer.Offset.Y;

        if (extent <= viewport)
            return true;

        // Consider "near the bottom" within 40 logical pixels of the end.
        return offset + viewport >= extent - 40;
    }
}
