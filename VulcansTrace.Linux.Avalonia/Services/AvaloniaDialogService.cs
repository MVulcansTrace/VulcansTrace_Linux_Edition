using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

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

        var result = await RunOnUiThreadAsync(() => topLevel.StorageProvider.SaveFilePickerAsync(options));
        return result?.TryGetLocalPath();
    }

    private Task ShowDialogAsync(string message, string title, bool isError)
    {
        return RunOnUiThreadAsync(async () =>
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

    private static Task<T> RunOnUiThreadAsync<T>(Func<Task<T>> action)
    {
        if (Dispatcher.UIThread.CheckAccess())
        {
            return action();
        }

        return Dispatcher.UIThread.InvokeAsync(action);
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
