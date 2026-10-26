using System;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
using Keyhole.App.ViewModels;
using Keyhole.App.Views;
using Keyhole.Core;
using Keyhole.Core.Ipc;

namespace Keyhole.App;

public partial class App : Application
{
    private MainWindow? _window;
    private KeyholeSettings _settings = new();

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            _settings = SettingsStore.Load();
            ApplyTheme(_settings.Theme);

            // Hand-wired: with a handful of collaborators a container would add
            // indirection without removing any.
            var client = new KeyholeServiceClient();
            var viewModel = new MainWindowViewModel(client) { Settings = _settings };

            _window = new MainWindow { DataContext = viewModel };

            // Closing the window keeps monitoring visible in the tray rather than ending
            // the session. The service keeps running either way, but a user who closed
            // the window would otherwise have no way back without finding the exe.
            _window.Closing += (_, e) =>
            {
                if (_settings.MinimiseToTray && !_isExiting)
                {
                    e.Cancel = true;
                    _window.Hide();
                }
            };

            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;

            // --tray is what the startup registration passes, so signing in does not
            // throw a window in the user's face.
            var startHidden = desktop.Args?.Contains("--tray", StringComparer.OrdinalIgnoreCase) == true;
            if (!startHidden)
            {
                _window.Show();
            }

            desktop.MainWindow = _window;
        }

        base.OnFrameworkInitializationCompleted();
    }

    private bool _isExiting;

    /// <summary>Brings the window back from the tray.</summary>
    public void ShowWindow()
    {
        if (_window is null)
        {
            return;
        }

        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    /// <summary>Exits for real, bypassing the close-to-tray behaviour.</summary>
    public void ExitApplication()
    {
        _isExiting = true;

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.Shutdown();
        }
    }

    internal static void ApplyTheme(string theme) =>
        Current!.RequestedThemeVariant = theme?.ToLowerInvariant() switch
        {
            "light" => ThemeVariant.Light,
            "dark" => ThemeVariant.Dark,
            _ => ThemeVariant.Default,
        };

    /// <summary>Invoked by the tray menu's Open entry.</summary>
    public void OnTrayOpen(object? sender, EventArgs e) => ShowWindow();

    /// <summary>Invoked by the tray menu's Exit entry.</summary>
    public void OnTrayExit(object? sender, EventArgs e) => ExitApplication();
}
