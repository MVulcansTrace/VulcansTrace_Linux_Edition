using System;
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

    public AgentView()
    {
        InitializeComponent();
        _chatListBox = this.FindControl<ListBox>("ChatListBox");
        _queryInput = this.FindControl<TextBox>("AgentQueryInput");
        _slashHelpSearchBox = this.FindControl<TextBox>("SlashHelpSearchBox");
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (_viewModel is not null)
        {
            _viewModel.Messages.CollectionChanged -= OnMessagesCollectionChanged;
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        _viewModel = DataContext as AgentViewModel;
        if (_viewModel is not null)
        {
            _viewModel.Messages.CollectionChanged += OnMessagesCollectionChanged;
            _viewModel.PropertyChanged += OnViewModelPropertyChanged;
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
        if (e.Action != NotifyCollectionChangedAction.Add || e.NewItems is null)
            return;

        var isUserMessage = e.NewItems.OfType<AgentMessageViewModel>().Any(m => m.IsUser);

        // Defer scrolling until layout has updated with the new item.
        Dispatcher.UIThread.Post(() => ScrollChatToEnd(force: isUserMessage), DispatcherPriority.Background);
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
