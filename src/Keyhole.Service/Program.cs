using Keyhole.Core;
using Keyhole.Core.Ipc;
using Keyhole.Core.Storage;
using Keyhole.Service;
using Keyhole.Service.Ipc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

KeyholePaths.EnsureCreated();

// Serilog is configured before the host so that startup failures still land in the log file.
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File(
        Path.Combine(KeyholePaths.LogDirectory, "service-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        shared: true)
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);

    // Runs as a Windows Service in production and as a plain console app during development;
    // this call is a no-op outside the service control manager.
    builder.Services.AddWindowsService(options => options.ServiceName = "Keyhole");

    builder.Logging.ClearProviders();
    builder.Services.AddSerilog();

    builder.Services.AddSingleton<ServiceRuntimeInfo>();
    builder.Services.AddSingleton<KeyholeDatabase>(_ => new KeyholeDatabase());
    builder.Services.AddSingleton<MigrationRunner>();

    builder.Services.AddSingleton<IIpcMethodHandler, PingHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, GetStatusHandler>();
    builder.Services.AddHostedService<IpcServer>();

    var host = builder.Build();

    // Migrate before serving: handlers may assume the schema is current.
    var schemaVersion = host.Services.GetRequiredService<MigrationRunner>().Migrate();

    var runtime = host.Services.GetRequiredService<ServiceRuntimeInfo>();
    Log.Information(
        "Keyhole service {Version} starting. Elevated={Elevated}, WindowsService={IsService}, Schema=v{Schema}, Data={DataRoot}",
        runtime.Version,
        runtime.IsElevated,
        WindowsServiceHelpers.IsWindowsService(),
        schemaVersion,
        KeyholePaths.DataRoot);

    if (!runtime.IsElevated)
    {
        // Not fatal yet — M1 has nothing privileged — but every later milestone needs it.
        Log.Warning(
            "Service is not elevated. Flow monitoring, firewall rules and packet capture will fail.");
    }

    await host.RunAsync();
    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Keyhole service terminated unexpectedly.");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}
