using System.Text.Json;
using Keyhole.Core.Blocking;
using Keyhole.Core.Ipc;
using Keyhole.Core.Monitoring;

namespace Keyhole.Service.Ipc;

/// <summary>Answers <see cref="IpcMethods.ListApps"/> with the aggregated application list.</summary>
public sealed class ListAppsHandler(FlowTracker tracker, BlockingService? blocking = null) : IIpcMethodHandler
{
    public string Method => IpcMethods.ListApps;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        // Joined here rather than in the UI so the list and the rules cannot disagree
        // about what is blocked.
        var rulesByPath = blocking is null
            ? []
            : blocking.ListRules()
                .GroupBy(r => r.ExecutablePath, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First().Id, StringComparer.OrdinalIgnoreCase);

        var apps = tracker.GetAppActivity()
            .Select(a => ToSummary(a) with
            {
                BlockedByRuleId = a.ExecutablePath is { } path && rulesByPath.TryGetValue(path, out var id)
                    ? id
                    : null,
            })
            .ToList();

        return Task.FromResult<JsonElement?>(JsonSerializer.SerializeToElement(apps, IpcChannel.Json));
    }

    internal static AppSummary ToSummary(AppActivity activity) => new()
    {
        SentRate = activity.SentRate,
        ReceivedRate = activity.ReceivedRate,
        DisplayName = activity.DisplayName,
        ExecutablePath = activity.ExecutablePath,
        Publisher = activity.Publisher,
        Signature = activity.Signature.ToString(),
        ActiveConnections = activity.ActiveConnections,
        TotalConnections = activity.TotalConnections,
        BytesSent = activity.BytesSent,
        BytesReceived = activity.BytesReceived,
        LastActiveUtc = activity.LastActiveUtc,
        RecentRemoteHosts = activity.RecentRemoteHosts,
        ProcessIds = activity.ProcessIds,
    };
}

/// <summary>Answers <see cref="IpcMethods.GetThroughput"/> with the machine-wide graph history.</summary>
public sealed class GetThroughputHandler(FlowTracker tracker) : IIpcMethodHandler
{
    public string Method => IpcMethods.GetThroughput;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var samples = tracker.TotalThroughput.Snapshot()
            .Select(p => new ThroughputSample
            {
                TimestampUtc = p.TimestampUtc,
                SentPerSecond = p.BytesSentPerSecond,
                ReceivedPerSecond = p.BytesReceivedPerSecond,
            })
            .ToList();

        return Task.FromResult<JsonElement?>(JsonSerializer.SerializeToElement(samples, IpcChannel.Json));
    }
}

/// <summary>Answers <see cref="IpcMethods.ListFlows"/> with one application's connections.</summary>
public sealed class ListFlowsHandler(FlowTracker tracker) : IIpcMethodHandler
{
    public string Method => IpcMethods.ListFlows;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        if (parameters is null)
        {
            throw new IpcInvalidParamsException($"'{IpcMethods.ListFlows}' requires an application.");
        }

        ListFlowsRequest request;
        try
        {
            request = parameters.Value.Deserialize<ListFlowsRequest>(IpcChannel.Json)
                      ?? throw new IpcInvalidParamsException("Parameters deserialised to null.");
        }
        catch (JsonException ex)
        {
            throw new IpcInvalidParamsException($"Malformed parameters: {ex.Message}");
        }

        if (string.IsNullOrWhiteSpace(request.Application))
        {
            throw new IpcInvalidParamsException("'application' must not be empty.");
        }

        var flows = tracker.Snapshot()
            .Where(f => Matches(f, request.Application))
            .Where(f => request.IncludeClosed || f.IsActive)
            .OrderByDescending(f => f.LastSeenUtc)
            .Select(ToSummary)
            .ToList();

        return Task.FromResult<JsonElement?>(JsonSerializer.SerializeToElement(flows, IpcChannel.Json));
    }

    /// <summary>
    /// Mirrors how <see cref="FlowTracker.GetAppActivity"/> groups: by executable path,
    /// falling back to display name for processes with no readable path. The two must
    /// agree or the drill-down would come back empty for rows the list shows.
    /// </summary>
    private static bool Matches(TrackedFlow flow, string application) =>
        string.Equals(
            flow.Process.ExecutablePath ?? flow.Process.DisplayName,
            application,
            StringComparison.OrdinalIgnoreCase);

    internal static FlowSummary ToSummary(TrackedFlow flow) => new()
    {
        ProcessId = flow.Connection.ProcessId,
        Protocol = flow.Connection.Protocol.ToString().ToUpperInvariant(),
        LocalAddress = flow.Connection.LocalAddress.ToString(),
        LocalPort = flow.Connection.LocalPort,
        RemoteAddress = flow.Connection.RemoteAddress.ToString(),
        RemotePort = flow.Connection.RemotePort,
        RemoteHostname = flow.RemoteHostname,
        State = flow.Connection.State.ToString(),
        BytesSent = flow.BytesSent,
        BytesReceived = flow.BytesReceived,
        StartedUtc = flow.StartedUtc,
        LastSeenUtc = flow.LastSeenUtc,
        EndedUtc = flow.EndedUtc,
    };
}
