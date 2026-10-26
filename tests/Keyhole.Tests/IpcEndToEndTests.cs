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
    /// <summary>
    /// A pipe name unique to each test. Sharing the well-known name means the client
    /// silently reaches an installed Keyhole service instead of the server under test —
    /// which passes, while exercising none of this code.
    /// </summary>
    private static async Task<(IpcServer Server, KeyholeServiceClient Client)> StartServerAsync(
        CancellationToken ct)
    {
        var pipeName = $"keyhole-test-{Guid.NewGuid():n}";
        var runtime = new ServiceRuntimeInfo();
        var handlers = new IIpcMethodHandler[] { new PingHandler(), new GetStatusHandler(runtime) };
        var server = new IpcServer(handlers, NullLogger<IpcServer>.Instance, pipeName);

        await server.StartAsync(ct);

        // The listen loop runs on a background task; give it a moment to create the pipe.
        await WaitForPipeAsync(pipeName, ct);
        return (server, new KeyholeServiceClient(logger: null, pipeName: pipeName));
    }

    private static async Task WaitForPipeAsync(string pipeName, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists($@"\\.\pipe\{pipeName}"))
            {
                return;
            }

            await Task.Delay(25, ct);
        }

        throw new TimeoutException($"Pipe {pipeName} did not appear.");
    }

    [Fact]
    public async Task Ping_gets_an_answer()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var (server, client) = await StartServerAsync(cts.Token);

        try
        {
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
        var (server, client) = await StartServerAsync(cts.Token);

        try
        {
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
        var (server, client) = await StartServerAsync(cts.Token);

        try
        {
            var status = await client.GetStatusAsync(cts.Token);

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
        var (server, client) = await StartServerAsync(cts.Token);

        try
        {
            var ex = await Assert.ThrowsAsync<ServiceCallException>(() =>
                client.InvokeAsync<object>("not-a-method", null, cts.Token));

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

        // A name nothing can be listening on, rather than relying on the real pipe being
        // free: once Keyhole is installed the real one is always up, and this assertion
        // would fail on exactly the machines the product is running on.
        var client = new KeyholeServiceClient(logger: null, pipeName: $"keyhole-absent-{Guid.NewGuid():n}");

        // The UI must distinguish "service down" from "service errored".
        await Assert.ThrowsAsync<ServiceUnavailableException>(() => client.GetStatusAsync(cts.Token));
    }
}
