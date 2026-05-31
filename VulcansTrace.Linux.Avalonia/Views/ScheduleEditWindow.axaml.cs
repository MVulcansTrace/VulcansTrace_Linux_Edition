using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using VulcansTrace.Linux.Agent.Scheduling;
using VulcansTrace.Linux.Avalonia.ViewModels;

namespace VulcansTrace.Linux.Avalonia.Views;

/// <summary>
/// Dialog window for adding or editing a scheduled audit.
/// </summary>
public partial class ScheduleEditWindow : Window
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ScheduleEditWindow"/> class.
    /// </summary>
    public ScheduleEditWindow()
    {
        InitializeComponent();
        DataContext = new ScheduleEditViewModel();
    }

    /// <summary>
    /// Gets the view model.
    /// </summary>
    public ScheduleEditViewModel ViewModel => (ScheduleEditViewModel)DataContext!;

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }

    private void OkButton_Click(object? sender, RoutedEventArgs e)
    {
        var vm = ViewModel;
        string? error = null;

        if (string.IsNullOrWhiteSpace(vm.Name))
            error = "Schedule name is required.";
        else if (string.IsNullOrWhiteSpace(vm.CronExpression))
            error = "Cron expression is required.";
        else if (!CronExpressionValidator.IsValid(vm.CronExpression))
            error = "Invalid cron expression. Expected 5 fields: minute hour day month weekday";
        else if (!string.IsNullOrWhiteSpace(vm.OutputDirectory) && !System.IO.Directory.Exists(vm.OutputDirectory))
            error = "Output directory does not exist.";

        if (error != null)
        {
            var validationBlock = this.FindControl<TextBlock>("ValidationError");
            if (validationBlock != null)
                validationBlock.Text = error;
            return;
        }

        Close(true);
    }

    private void CancelButton_Click(object? sender, RoutedEventArgs e)
    {
        Close(false);
    }
}
