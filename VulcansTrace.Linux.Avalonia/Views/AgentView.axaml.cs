using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Avalonia.VisualTree;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Views;

public partial class AgentView : UserControl
{
    private AgentViewModel? _viewModel;
    private ListBox? _chatListBox;
    private ScrollViewer? _scrollViewer;
    private TextBox? _queryInput;
    private TextBox? _slashHelpSearchBox;
    private TextBox? _chatSearchBox;
    private readonly HashSet<AgentMessageViewModel> _streamingMessageSubscriptions = new();

    public AgentView()
    {
        InitializeComponent();
        _chatListBox = this.FindControl<ListBox>("ChatListBox");
        _queryInput = this.FindControl<TextBox>("AgentQueryInput");
        _slashHelpSearchBox = this.FindControl<TextBox>("SlashHelpSearchBox");
        _chatSearchBox = this.FindControl<TextBox>("ChatSearchBox");
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (_viewModel is not null)
        {
            _viewModel.Messages.CollectionChanged -= OnMessagesCollectionChanged;
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            DetachStreamingMessageSubscriptions();
        }

        _viewModel = DataContext as AgentViewModel;
        if (_viewModel is not null)
        {
            _viewModel.Messages.CollectionChanged += OnMessagesCollectionChanged;
            _viewModel.PropertyChanged += OnViewModelPropertyChanged;
            AttachStreamingMessageSubscriptions(_viewModel.Messages.Where(message =>
                message.IsProse && !message.IsUser && (message.IsStreaming || message.IsStreamingPending)));
        }
    }

    protected override void OnLoaded(RoutedEventArgs e)
    {
        base.OnLoaded(e);
        EnsureScrollViewer();
    }

    protected override void OnUnloaded(RoutedEventArgs e)
    {
        base.OnUnloaded(e);

        if (_viewModel is not null)
        {
            _viewModel.Messages.CollectionChanged -= OnMessagesCollectionChanged;
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            _viewModel = null;
        }

        DetachStreamingMessageSubscriptions();
        _scrollViewer = null;
    }

    private void EnsureScrollViewer()
    {
        if (_scrollViewer is not null || _chatListBox is null)
            return;

        _scrollViewer = _chatListBox.GetVisualDescendants().OfType<ScrollViewer>().FirstOrDefault();
    }

    private void OnQueryKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not AgentViewModel vm)
            return;

        // Ctrl+K toggles the searchable slash-command help popup.
        if (e.Key == Key.K && e.KeyModifiers.HasFlag(KeyModifiers.Control))
        {
            if (vm.IsSlashHelpOpen)
                vm.CloseSlashHelpCommand.Execute(null);
            else
                vm.OpenSlashHelpCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Escape)
        {
            // Esc closes the help popup first, then the slash palette, preserving the typed query.
            if (vm.IsSlashHelpOpen)
            {
                vm.CloseSlashHelpCommand.Execute(null);
                e.Handled = true;
            }
            else if (vm.IsSlashPaletteOpen)
            {
                vm.CloseSlashPalette();
                e.Handled = true;
            }
            return;
        }

        if (vm.IsSlashPaletteOpen)
        {
            if (e.Key == Key.Down)
            {
                vm.SelectNextSlashCommand();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Up)
            {
                vm.SelectPreviousSlashCommand();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Enter && vm.SelectedSlashCommand is not null)
            {
                vm.ExecuteSlashCommandCommand.Execute(vm.SelectedSlashCommand);
                e.Handled = true;
                return;
            }
        }

        if (e.Key == Key.Enter)
        {
            vm.SendQueryCommand.Execute(null);
            e.Handled = true;
            return;
        }

        // Query history recall when no command surface is open.
        if (!vm.IsSlashPaletteOpen && !vm.IsSlashHelpOpen)
        {
            if (e.Key == Key.Up)
            {
                vm.RecallPreviousQuery();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Down)
            {
                vm.RecallNextQuery();
                e.Handled = true;
                return;
            }
        }
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

            // Return focus to the query input so the user can keep typing.
            Dispatcher.UIThread.Post(() => _queryInput?.Focus(), DispatcherPriority.Background);
            e.Handled = true;
        }
    }

    private void OnQueryLostFocus(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not AgentViewModel vm || !vm.IsSlashPaletteOpen)
            return;

        // Clicking a palette item also blurs this box. Defer the close so that item's command can
        // run first — ExecuteSlashCommandCommand closes the palette itself synchronously, making this
        // deferred close a harmless no-op in that case. Closing synchronously would remove the button
        // before its Click fires.
        Dispatcher.UIThread.Post(() =>
        {
            if (DataContext is AgentViewModel vm2 && vm2.IsSlashPaletteOpen)
            {
                vm2.CloseSlashPalette();
            }
        }, DispatcherPriority.Background);
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
            else
            {
                // Return focus to the query box when the help popup closes so the user can resume typing.
                Dispatcher.UIThread.Post(() => _queryInput?.Focus(), DispatcherPriority.Background);
            }
        }
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

        // Subscribe to prose messages (set at add time) so queued bubbles that begin
        // streaming later still drive the per-tick auto-scroll.
        AttachStreamingMessageSubscriptions(e.NewItems.OfType<AgentMessageViewModel>().Where(message =>
            message.IsProse && !message.IsUser));

        // Defer scrolling until layout has updated with the new item.
        Dispatcher.UIThread.Post(() => ScrollChatToEnd(force: isUserMessage), DispatcherPriority.Background);
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
