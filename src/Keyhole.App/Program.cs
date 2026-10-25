using Avalonia;

namespace Keyhole.App;

internal static class Program
{
    // Avalonia needs this before any SynchronizationContext-reliant code runs,
    // so keep initialisation out of the constructor and off other threads.
    [STAThread]
    public static int Main(string[] args) =>
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    // Also used by the Avalonia XAML previewer, which calls it by convention.
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
