using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Controls;

/// <summary>
/// Sticky bottom composer for the Agent workspace. Replaces the HeroPanel input row.
/// Binds to MainViewModel via the window DataContext.
/// </summary>
public partial class AgentComposer : UserControl
{
    public AgentComposer()
    {
        InitializeComponent();
    }

    /// <summary>Moves keyboard focus to the composer input.</summary>
    public void FocusInput() =>
        Dispatcher.UIThread.Post(() => ComposerInputBox.Focus(), DispatcherPriority.Background);

    private void OnComposerKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not MainViewModel vm)
            return;

        var agent = vm.Agent;

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
            if (vm.IsLogIntent)
                return;

            if (vm.HeroPrimaryCommand.CanExecute(null))
            {
                vm.HeroPrimaryCommand.Execute(null);
                e.Handled = true;
            }
            return;
        }

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

    private void OnComposerLostFocus(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel vm || !vm.Agent.IsSlashPaletteOpen)
            return;

        Dispatcher.UIThread.Post(() =>
        {
            if (DataContext is MainViewModel vm2 && vm2.Agent.IsSlashPaletteOpen)
            {
                vm2.Agent.CloseSlashPalette();
            }
        }, DispatcherPriority.Background);
    }
}
