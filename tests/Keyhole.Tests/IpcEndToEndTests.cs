using Keyhole.Core.Ipc;
using Keyhole.Service;
using Keyhole.Service.Ipc;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Tests;

/// <summary>
/// Drives the real named pipe rather than a MemoryStream. These exist because a response
/// that serialises correctly can still be lost at connection teardown, which unit tests
/// over streams cannot see.
/// </summary>
[Collection(nameof(IpcEndToEndTests))]
[CollectionDefinition(nameof(IpcEndToEndTests), DisableParallelization = true)]
public class IpcEndToEndTests
{
    private static async Task<IpcServer> StartServerAsync(CancellationToken ct)
    {
        var runtime = new ServiceRuntimeInfo();
        var handlers = new IIpcMethodHandler[] { new PingHandler(), new GetStatusHandler(runtime) };
        var server = new IpcServer(handlers, NullLogger<IpcServer>.Instance);

        await server.StartAsync(ct);

        // The listen loop runs on a background task; give it a moment to create the pipe.
        await WaitForPipeAsync(ct);
        return server;
    }

    private static async Task WaitForPipeAsync(CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists($@"\\.\pipe\{IpcChannel.PipeName}"))
            {
                return;
            }

            await Task.Delay(25, ct);
        }

        throw new TimeoutException($"Pipe {IpcChannel.PipeName} did not appear.");
    }

    [Fact]
    public async Task Ping_gets_an_answer()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var server = await StartServerAsync(cts.Token);

        try
        {
            var client = new KeyholeServiceClient();

            // A payload-free response is the case most likely to be lost at teardown,
            // because it is small enough for the client to still be mid-read.
            Assert.True(await client.PingAsync(cts.Token));
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
            server.Dispose();
        }
    }

    [Fact]
    public async Task Repeated_pings_all_get_answers()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var server = await StartServerAsync(cts.Token);

        try
        {
            var client = new KeyholeServiceClient();

            // The response-drop this guards against was intermittent, so one call is not proof.
            for (var i = 0; i < 25; i++)
            {
                Assert.True(await client.PingAsync(cts.Token), $"Ping {i} got no response.");
            }
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
            server.Dispose();
        }
    }

    [Fact]
    public async Task Get_status_returns_runtime_facts()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var server = await StartServerAsync(cts.Token);

        try
        {
            var status = await new KeyholeServiceClient().GetStatusAsync(cts.Token);

            Assert.False(string.IsNullOrWhiteSpace(status.Version));
            Assert.True(status.StartedAtUtc <= DateTimeOffset.UtcNow);
            Assert.Null(status.MonitorState); // No monitoring backend until M2.
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
            server.Dispose();
        }
    }

    [Fact]
    public async Task Unknown_method_returns_a_structured_error()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var server = await StartServerAsync(cts.Token);

        try
        {
            var ex = await Assert.ThrowsAsync<ServiceCallException>(() =>
                new KeyholeServiceClient().InvokeAsync<object>("not-a-method", null, cts.Token));

            Assert.Equal(IpcErrorCodes.UnknownMethod, ex.Code);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
            server.Dispose();
        }
    }

    [Fact]
    public async Task Client_reports_unavailable_when_no_service_is_listening()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        // Nothing started: the UI must distinguish "service down" from "service errored".
        await Assert.ThrowsAsync<ServiceUnavailableException>(() =>
            new KeyholeServiceClient().GetStatusAsync(cts.Token));
    }
}
