using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// Agent-home hero panel: the unified chat/log input (UI v2 Phase 3), prompt
/// chips, and scan options. Hosted above the main content when the Agent view
/// is selected. The DataContext is the window's MainViewModel; agent-thread
/// operations go through <see cref="MainViewModel.Agent"/>.
/// </summary>
public partial class HeroPanel : UserControl
{
    public HeroPanel()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Key handling for the unified hero input (ported from the retired bottom
    /// chat input). Enter dispatches the flipping primary action — except while
    /// the slash palette is open (Enter selects the command) or when the input
    /// is a pasted log (Enter inserts a newline; the button runs the analysis).
    /// </summary>
    private void OnHeroInputKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not MainViewModel vm)
            return;

        var agent = vm.Agent;

        // Ctrl+K toggles the searchable slash-command help popup.
        if (e.Key == Key.K && e.KeyModifiers.HasFlag(KeyModifiers.Control))
        {
            if (agent.IsSlashHelpOpen)
                agent.CloseSlashHelpCommand.Execute(null);
            else
                agent.OpenSlashHelpCommand.Execute(null);
            e.Handled = true;
            return;
        }

        if (e.Key == Key.Escape)
        {
            // Esc closes the help popup first, then the slash palette, preserving the typed query.
            if (agent.IsSlashHelpOpen)
            {
                agent.CloseSlashHelpCommand.Execute(null);
                e.Handled = true;
            }
            else if (agent.IsSlashPaletteOpen)
            {
                agent.CloseSlashPalette();
                e.Handled = true;
            }
            return;
        }

        if (agent.IsSlashPaletteOpen)
        {
            if (e.Key == Key.Down)
            {
                agent.SelectNextSlashCommand();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Up)
            {
                agent.SelectPreviousSlashCommand();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Enter && agent.SelectedSlashCommand is not null)
            {
                agent.ExecuteSlashCommandCommand.Execute(agent.SelectedSlashCommand);
                e.Handled = true;
                return;
            }
        }

        if (e.Key == Key.Enter && !e.KeyModifiers.HasFlag(KeyModifiers.Shift))
        {
            // Log intent keeps Enter as a plain newline (multiline paste box);
            // chat intent sends. Shift+Enter always inserts a newline.
            if (vm.IsLogIntent)
                return;

            if (vm.HeroPrimaryCommand.CanExecute(null))
            {
                vm.HeroPrimaryCommand.Execute(null);
                e.Handled = true;
            }
            return;
        }

        // Query history recall when no command surface is open.
        if (!agent.IsSlashPaletteOpen && !agent.IsSlashHelpOpen)
        {
            if (e.Key == Key.Up)
            {
                agent.RecallPreviousQuery();
                e.Handled = true;
                return;
            }

            if (e.Key == Key.Down)
            {
                agent.RecallNextQuery();
                e.Handled = true;
                return;
            }
        }
    }

    private void OnHeroInputLostFocus(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel vm || !vm.Agent.IsSlashPaletteOpen)
            return;

        // Clicking a palette item also blurs this box. Defer the close so that item's command can
        // run first — ExecuteSlashCommandCommand closes the palette itself synchronously, making this
        // deferred close a harmless no-op in that case. Closing synchronously would remove the button
        // before its Click fires.
        Dispatcher.UIThread.Post(() =>
        {
            if (DataContext is MainViewModel vm2 && vm2.Agent.IsSlashPaletteOpen)
            {
                vm2.Agent.CloseSlashPalette();
            }
        }, DispatcherPriority.Background);
    }
}
