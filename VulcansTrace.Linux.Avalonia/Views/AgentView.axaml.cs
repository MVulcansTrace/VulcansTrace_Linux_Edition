using System;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Views;

public partial class AgentView : UserControl
{
    public AgentView()
    {
        InitializeComponent();
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (DataContext is AgentViewModel vm)
        {
            // Ensure we only subscribe once by detaching from the old collection if any.
            vm.Messages.CollectionChanged -= OnMessagesCollectionChanged;
            vm.Messages.CollectionChanged += OnMessagesCollectionChanged;
        }
    }

    private void OnQueryKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not AgentViewModel vm)
            return;

        if (e.Key == Key.Escape)
        {
            // Esc dismisses the slash palette (if open) without clearing the typed query.
            if (vm.IsSlashPaletteOpen)
            {
                vm.CloseSlashPalette();
                e.Handled = true;
            }
            return;
        }

        if (e.Key == Key.Enter)
        {
            vm.SendQueryCommand.Execute(null);
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

    private void OnMessagesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.Action == NotifyCollectionChangedAction.Add)
        {
            // Defer scrolling until layout has updated with the new item.
            Dispatcher.UIThread.Post(ScrollChatToEnd, DispatcherPriority.Background);
        }
    }

    private void ScrollChatToEnd()
    {
        if (this.FindControl<ListBox>("ChatListBox") is { } listBox && listBox.Items.Count > 0)
        {
            listBox.ScrollIntoView(listBox.Items.Count - 1);
        }
    }
}
