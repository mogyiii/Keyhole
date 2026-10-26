using Keyhole.Core;
using Keyhole.Core.Blocking;
using Keyhole.Core.Capture;
using Keyhole.Core.Ipc;
using Keyhole.Core.Monitoring;
using Keyhole.Core.Storage;
using Keyhole.Native;
using Keyhole.Service;
using Keyhole.Service.Ipc;
using Keyhole.Service.Monitoring;
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
    builder.Services.AddSingleton<FlowRepository>();

    builder.Services.AddSingleton<ISocketTableReader, SocketTableReader>();
    builder.Services.AddSingleton<IProcessResolver, ProcessResolver>();
    builder.Services.AddSingleton<IHostnameResolver, HostnameResolver>();

    // Byte counting needs elevation. When it cannot start, monitoring continues without
    // volume figures rather than failing, and the reason is reported through get-status.
    builder.Services.AddSingleton<EtwByteCounter>();
    builder.Services.AddSingleton<IByteCounterSource>(sp => sp.GetRequiredService<EtwByteCounter>());

    builder.Services.AddSingleton<FlowTracker>();

    // Registered as a singleton as well as a hosted service so GetStatusHandler can read
    // live monitor state; AddHostedService alone would construct a second instance.
    builder.Services.AddSingleton<MonitorService>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<MonitorService>());

    // Blocking needs elevation too. Like byte counting, an unavailable firewall is
    // reported rather than fatal: monitoring is useful on its own.
    builder.Services.AddSingleton<IFirewall, WindowsFirewall>();
    builder.Services.AddSingleton<RuleRepository>();
    builder.Services.AddSingleton<BlockingService>();

    builder.Services.AddSingleton<IIpcMethodHandler, PingHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, GetStatusHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, ListAppsHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, ListFlowsHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, GetThroughputHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, ListRulesHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, BlockAppHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, UnblockAppHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, SetRuleEnabledHandler>();

    builder.Services.AddSingleton<SessionRepository>();
    builder.Services.AddSingleton<CaptureService>();
    builder.Services.AddSingleton<IIpcMethodHandler, ListCapturesHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, StartCaptureHandler>();
    builder.Services.AddSingleton<IIpcMethodHandler, StopCaptureHandler>();
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
        Log.Warning(
            "Service is not elevated. Byte counting and blocking are unavailable; " +
            "connection monitoring still works.");
    }

    // Captures running when the service stopped have long since lost their process, so
    // leaving them open would show finished captures as live forever.
    var orphanedCaptures = host.Services.GetRequiredService<SessionRepository>().CloseOrphanedSessions();
    if (orphanedCaptures > 0)
    {
        Log.Information("Closed {Count} capture sessions left open by a previous run.", orphanedCaptures);
    }

    // Keyhole and the firewall can drift apart while the service is not running: a rule
    // can be deleted by hand or wiped by a firewall reset. Re-apply the stored intent
    // before accepting requests, so a block the user asked for is actually in force.
    var reconciliation = host.Services.GetRequiredService<BlockingService>().Reconcile();
    if (reconciliation.SkippedReason is { } skipped)
    {
        Log.Information("Rule reconciliation skipped: {Reason}", skipped);
    }
    else if (reconciliation.DidAnything)
    {
        Log.Information(
            "Rule reconciliation: {Restored} re-applied, {Orphans} orphans removed, {Changed} executables changed.",
            reconciliation.Restored.Count,
            reconciliation.RemovedOrphans.Count,
            reconciliation.ChangedExecutables.Count);
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
