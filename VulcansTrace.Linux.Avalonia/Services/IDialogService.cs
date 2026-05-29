using System.Threading.Tasks;

namespace VulcansTrace.Linux.Avalonia.Services;

/// <summary>
/// Defines the contract for dialog and message box services in the Avalonia UI.
/// </summary>
/// <remarks>
/// Provides platform-agnostic dialog operations for displaying messages, errors, and file save dialogs.
/// </remarks>
public interface IDialogService
{
    /// <summary>
    /// Shows a non-modal information message dialog.
    /// </summary>
    /// <param name="message">The message to display.</param>
    /// <param name="title">The dialog title.</param>
    void ShowMessage(string message, string title);

    /// <summary>
    /// Shows a non-modal error message dialog with error styling.
    /// </summary>
    /// <param name="message">The error message to display.</param>
    /// <param name="title">The dialog title.</param>
    void ShowError(string message, string title);

    /// <summary>
    /// Shows a modal file save dialog.
    /// </summary>
    /// <param name="title">The dialog title.</param>
    /// <param name="filter">File type filter (e.g., "ZIP files (*.zip)|*.zip|All files (*.*)|*.*").</param>
    /// <param name="defaultFileName">The default file name.</param>
    /// <returns>The selected file path, or null if the dialog was cancelled.</returns>
    Task<string?> ShowSaveFileDialogAsync(string title, string filter, string defaultFileName);

    /// <summary>
    /// Shows a modal input dialog with a text box.
    /// </summary>
    /// <param name="title">The dialog title.</param>
    /// <param name="message">The message to display above the input.</param>
    /// <param name="defaultText">The default text in the input box.</param>
    /// <returns>The entered text, or null if cancelled.</returns>
    Task<string?> ShowInputDialogAsync(string title, string message, string defaultText = "");
}
