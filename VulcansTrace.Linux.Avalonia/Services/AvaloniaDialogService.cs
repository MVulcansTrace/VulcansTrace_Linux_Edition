using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using VulcansTrace.Linux.Avalonia.Threading;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Avalonia.Views;

namespace VulcansTrace.Linux.Avalonia.Services;

/// <summary>
/// Avalonia-specific implementation of IDialogService for displaying dialogs and message boxes.
/// </summary>
/// <remarks>
/// Uses native Avalonia controls and ensures all UI operations run on the UI thread.
/// </remarks>
public sealed class AvaloniaDialogService : IDialogService
{
    private readonly Window _owner;

    /// <summary>
    /// Initializes a new instance of the AvaloniaDialogService.
    /// </summary>
    /// <param name="owner">The parent window for dialog operations.</param>
    public AvaloniaDialogService(Window owner)
    {
        _owner = owner;
    }

    /// <summary>
    /// Shows a non-modal information message dialog.
    /// </summary>
    /// <param name="message">The message to display.</param>
    /// <param name="title">The dialog title.</param>
    public void ShowMessage(string message, string title)
    {
        _ = ShowDialogAsync(message, title, isError: false)
            .ContinueWith(_ => { }, TaskContinuationOptions.OnlyOnFaulted);
    }

    /// <summary>
    /// Shows a non-modal error message dialog with error styling.
    /// </summary>
    /// <param name="message">The error message to display.</param>
    /// <param name="title">The dialog title.</param>
    public void ShowError(string message, string title)
    {
        _ = ShowDialogAsync(message, title, isError: true)
            .ContinueWith(_ => { }, TaskContinuationOptions.OnlyOnFaulted);
    }

    /// <summary>
    /// Shows a modal file save dialog.
    /// </summary>
    /// <param name="title">The dialog title.</param>
    /// <param name="filter">File type filter (e.g., "ZIP files (*.zip)|*.zip|All files (*.*)|*.*").</param>
    /// <param name="defaultFileName">The default file name.</param>
    /// <returns>The selected file path, or null if the dialog was cancelled.</returns>
    public async Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName)
    {
        var topLevel = TopLevel.GetTopLevel(_owner);
        if (topLevel == null || topLevel.StorageProvider == null)
        {
            ShowError("File dialog system not available. Please restart the application.", "Dialog Error");
            return null;
        }

        // Parse filter string (e.g., "ZIP files (*.zip)|*.zip|All files (*.*)|*.*")
        // to create appropriate FilePickerFileType entries
        var fileTypes = ParseFilter(filter);

        var options = new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = defaultFileName,
            FileTypeChoices = fileTypes
        };

        var result = await UiThread.InvokeAsync(() => topLevel.StorageProvider.SaveFilePickerAsync(options));
        return result?.TryGetLocalPath();
    }

    /// <summary>
    /// Shows a modal file open dialog.
    /// </summary>
    /// <param name="title">The dialog title.</param>
    /// <param name="filter">File type filter (e.g., "JSON files (*.json)|*.json|All files (*.*)|*.*").</param>
    /// <returns>The selected file path, or null if the dialog was cancelled.</returns>
    public async Task<string?> ShowOpenFileDialogAsync(string title, string filter)
    {
        var topLevel = TopLevel.GetTopLevel(_owner);
        if (topLevel == null || topLevel.StorageProvider == null)
        {
            ShowError("File dialog system not available. Please restart the application.", "Dialog Error");
            return null;
        }

        var fileTypes = ParseFilter(filter);

        var options = new FilePickerOpenOptions
        {
            Title = title,
            FileTypeFilter = fileTypes,
            AllowMultiple = false
        };

        var results = await UiThread.InvokeAsync(() => topLevel.StorageProvider.OpenFilePickerAsync(options));
        return results?.Count > 0 ? results[0].TryGetLocalPath() : null;
    }

    private Task ShowDialogAsync(string message, string title, bool isError)
    {
        return UiThread.InvokeAsync(async () =>
        {
            var dialog = new Window
            {
                Title = title,
                SizeToContent = SizeToContent.WidthAndHeight,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                CanResize = false
            };

            var messageBlock = new TextBlock
            {
                Text = message,
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 480
            };

            if (isError)
            {
                messageBlock.Foreground = Brushes.Firebrick;
            }

            var okButton = new Button
            {
                Content = "OK",
                HorizontalAlignment = HorizontalAlignment.Right,
                MinWidth = 80
            };
            okButton.Click += (_, _) => dialog.Close(true);

            var panel = new StackPanel
            {
                Spacing = 12,
                Margin = new Thickness(16)
            };
            panel.Children.Add(messageBlock);
            panel.Children.Add(okButton);

            dialog.Content = panel;

            await dialog.ShowDialog(_owner);
            return true;
        });
    }

    /// <summary>
    /// Shows a modal selection dialog with a dropdown of predefined options.
    /// </summary>
    public async Task<int?> ShowSelectionDialogAsync(string title, string message, string[] options, int defaultIndex = 0)
    {
        return await UiThread.InvokeAsync(async () =>
        {
            var dialog = new Window
            {
                Title = title,
                Width = 420,
                Height = 220,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                CanResize = false
            };

            var messageBlock = new TextBlock
            {
                Text = message,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            };

            var comboBox = new ComboBox
            {
                ItemsSource = options,
                SelectedIndex = defaultIndex >= 0 && defaultIndex < options.Length ? defaultIndex : 0
            };

            int? result = null;

            var okButton = new Button
            {
                Content = "OK",
                HorizontalAlignment = HorizontalAlignment.Right,
                MinWidth = 80,
                Margin = new Thickness(0, 0, 8, 0)
            };
            okButton.Click += (_, _) =>
            {
                result = comboBox.SelectedIndex;
                dialog.Close(true);
            };

            var cancelButton = new Button
            {
                Content = "Cancel",
                HorizontalAlignment = HorizontalAlignment.Right,
                MinWidth = 80
            };
            cancelButton.Click += (_, _) => dialog.Close(false);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 12, 0, 0),
                Spacing = 8
            };
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);

            var panel = new StackPanel
            {
                Spacing = 4,
                Margin = new Thickness(16)
            };
            panel.Children.Add(messageBlock);
            panel.Children.Add(comboBox);
            panel.Children.Add(buttonPanel);

            dialog.Content = panel;

            await dialog.ShowDialog<bool?>(_owner);
            return result;
        });
    }

    /// <summary>
    /// Shows a modal input dialog with a text box.
    /// </summary>
    public async Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "")
    {
        return await UiThread.InvokeAsync(async () =>
        {
            var dialog = new Window
            {
                Title = title,
                Width = 420,
                Height = 200,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                CanResize = false
            };

            var messageBlock = new TextBlock
            {
                Text = message,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            };

            var textBox = new TextBox
            {
                Text = defaultText,
                PlaceholderText = "Optional reason..."
            };

            string? result = null;

            var okButton = new Button
            {
                Content = "OK",
                HorizontalAlignment = HorizontalAlignment.Right,
                MinWidth = 80,
                Margin = new Thickness(0, 0, 8, 0)
            };
            okButton.Click += (_, _) =>
            {
                result = textBox.Text;
                dialog.Close(true);
            };

            var cancelButton = new Button
            {
                Content = "Cancel",
                HorizontalAlignment = HorizontalAlignment.Right,
                MinWidth = 80
            };
            cancelButton.Click += (_, _) => dialog.Close(false);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 12, 0, 0),
                Spacing = 8
            };
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);

            var panel = new StackPanel
            {
                Spacing = 4,
                Margin = new Thickness(16)
            };
            panel.Children.Add(messageBlock);
            panel.Children.Add(textBox);
            panel.Children.Add(buttonPanel);

            dialog.Content = panel;

            await dialog.ShowDialog<bool?>(_owner);
            return result;
        });
    }

    /// <summary>
    /// Shows a modal dialog for editing a rule's per-role policy.
    /// </summary>
    public async Task<bool?> ShowRulePolicyEditDialogAsync(RulePolicyEditViewModel viewModel)
    {
        return await UiThread.InvokeAsync(async () =>
        {
            var dialog = new RulePolicyEditWindow
            {
                DataContext = viewModel
            };
            return await dialog.ShowDialog<bool?>(_owner);
        });
    }

    private static FilePickerFileType[] ParseFilter(string filter)
    {
        if (string.IsNullOrEmpty(filter))
        {
            return new[] { new FilePickerFileType("All Files") { Patterns = new[] { "*" } } };
        }

        var fileTypes = new List<FilePickerFileType>();
        var parts = filter.Split('|');

        for (int i = 0; i < parts.Length; i += 2)
        {
            if (i + 1 < parts.Length)
            {
                var displayName = parts[i];
                var pattern = parts[i + 1];

                // Parse patterns like "*.zip" or "*.*"
                var patterns = pattern.Split(';')
                    .Select(p => p.Trim())
                    .Where(p => !string.IsNullOrEmpty(p))
                    .ToArray();

                if (patterns.Length > 0)
                {
                    fileTypes.Add(new FilePickerFileType(displayName)
                    {
                        Patterns = patterns
                    });
                }
            }
        }

        // If no valid file types parsed, default to all files
        return fileTypes.Count > 0
            ? fileTypes.ToArray()
            : new[] { new FilePickerFileType("All Files") { Patterns = new[] { "*" } } };
    }
}
