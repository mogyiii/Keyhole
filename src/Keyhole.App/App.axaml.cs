using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Keyhole.App.ViewModels;
using Keyhole.App.Views;
using Keyhole.Core.Ipc;

namespace Keyhole.App;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // Hand-wired for now. A container goes in once there are enough services
            // to justify it; at two it would only add indirection.
            var client = new KeyholeServiceClient();

            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(client),
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
