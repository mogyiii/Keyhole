using System;
using System.IO;
using Microsoft.Win32;

namespace Keyhole.App;

/// <summary>
/// Registers the UI to start when the user signs in.
///
/// Uses the per-user Run key rather than a scheduled task or the machine-wide key: this
/// is the UI, which runs unelevated as the signed-in user, so it needs no privileges to
/// register itself and affects nobody else on the machine. The service starts on its own
/// through the service control manager.
/// </summary>
internal static class StartupRegistration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "Keyhole";

    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: false);
            return key?.GetValue(ValueName) is string value && value.Length > 0;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return false;
        }
    }

    /// <summary>Returns false when the registry could not be written.</summary>
    public static bool SetEnabled(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true)
                            ?? Registry.CurrentUser.CreateSubKey(RunKey);

            if (key is null)
            {
                return false;
            }

            if (!enabled)
            {
                key.DeleteValue(ValueName, throwOnMissingValue: false);
                return true;
            }

            var executable = Environment.ProcessPath;
            if (string.IsNullOrEmpty(executable))
            {
                return false;
            }

            // Quoted: the install path contains spaces under Program Files, and an
            // unquoted entry would be parsed as a different executable plus arguments.
            key.SetValue(ValueName, $"\"{executable}\" --tray");
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
                                      or System.Security.SecurityException or IOException)
        {
            return false;
        }
    }
}
