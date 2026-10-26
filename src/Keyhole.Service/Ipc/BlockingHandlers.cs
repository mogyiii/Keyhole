using System.Text.Json;
using Keyhole.Core.Blocking;
using Keyhole.Core.Ipc;

namespace Keyhole.Service.Ipc;

/// <summary>Answers <see cref="IpcMethods.ListRules"/> with every stored block rule.</summary>
public sealed class ListRulesHandler(BlockingService blocking) : IIpcMethodHandler
{
    public string Method => IpcMethods.ListRules;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var rules = blocking.ListRules().Select(ToSummary).ToList();

        return Task.FromResult<JsonElement?>(JsonSerializer.SerializeToElement(rules, IpcChannel.Json));
    }

    internal static RuleSummary ToSummary(BlockRule rule) => new()
    {
        Id = rule.Id,
        DisplayName = rule.DisplayName,
        ExecutablePath = rule.ExecutablePath,
        Direction = rule.Direction.ToString().ToLowerInvariant(),
        IsEnabled = rule.IsEnabled,
        Note = rule.Note,
        CreatedUtc = rule.CreatedUtc,
        ExecutableState = ExecutableHasher.Verify(rule.ExecutablePath, rule.Sha256) switch
        {
            HashVerdict.Match => "match",
            HashVerdict.Changed => "changed",
            _ => "unknown",
        },
    };
}

/// <summary>Answers <see cref="IpcMethods.BlockApp"/>. Only ever invoked by explicit user action.</summary>
public sealed class BlockAppHandler(BlockingService blocking) : IIpcMethodHandler
{
    public string Method => IpcMethods.BlockApp;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var request = IpcParams.Parse<BlockAppRequest>(parameters, Method);

        if (string.IsNullOrWhiteSpace(request.ExecutablePath))
        {
            throw new IpcInvalidParamsException("'executablePath' must not be empty.");
        }

        var direction = request.Direction?.ToLowerInvariant() switch
        {
            "inbound" => RuleDirection.Inbound,
            "both" => RuleDirection.Both,
            "outbound" or null or "" => RuleDirection.Outbound,
            _ => throw new IpcInvalidParamsException(
                $"'direction' must be outbound, inbound or both; got '{request.Direction}'."),
        };

        try
        {
            var rule = blocking.Block(request.ExecutablePath, direction, request.Note);

            return Task.FromResult<JsonElement?>(
                JsonSerializer.SerializeToElement(ListRulesHandler.ToSummary(rule), IpcChannel.Json));
        }
        catch (Exception ex) when (ex is BlockingException or FirewallException)
        {
            // These carry a user-facing explanation — missing elevation, missing file —
            // so they must reach the UI rather than being flattened into "internal error".
            throw new IpcInvalidParamsException(ex.Message);
        }
    }
}

/// <summary>Answers <see cref="IpcMethods.UnblockApp"/>.</summary>
public sealed class UnblockAppHandler(BlockingService blocking) : IIpcMethodHandler
{
    public string Method => IpcMethods.UnblockApp;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var request = IpcParams.Parse<UnblockAppRequest>(parameters, Method);

        try
        {
            var removed = blocking.Unblock(request.RuleId);

            return Task.FromResult<JsonElement?>(
                JsonSerializer.SerializeToElement(new { removed }, IpcChannel.Json));
        }
        catch (Exception ex) when (ex is BlockingException or FirewallException)
        {
            throw new IpcInvalidParamsException(ex.Message);
        }
    }
}

/// <summary>Answers <see cref="IpcMethods.SetRuleEnabled"/>.</summary>
public sealed class SetRuleEnabledHandler(BlockingService blocking) : IIpcMethodHandler
{
    public string Method => IpcMethods.SetRuleEnabled;

    public Task<JsonElement?> HandleAsync(JsonElement? parameters, CancellationToken ct)
    {
        var request = IpcParams.Parse<SetRuleEnabledRequest>(parameters, Method);

        try
        {
            var rule = blocking.SetEnabled(request.RuleId, request.Enabled);

            return Task.FromResult<JsonElement?>(
                JsonSerializer.SerializeToElement(ListRulesHandler.ToSummary(rule), IpcChannel.Json));
        }
        catch (Exception ex) when (ex is BlockingException or FirewallException)
        {
            throw new IpcInvalidParamsException(ex.Message);
        }
    }
}

/// <summary>Shared parameter parsing, so every handler reports malformed input the same way.</summary>
internal static class IpcParams
{
    public static T Parse<T>(JsonElement? parameters, string method)
    {
        if (parameters is null)
        {
            throw new IpcInvalidParamsException($"'{method}' requires parameters.");
        }

        try
        {
            return parameters.Value.Deserialize<T>(IpcChannel.Json)
                   ?? throw new IpcInvalidParamsException("Parameters deserialised to null.");
        }
        catch (JsonException ex)
        {
            throw new IpcInvalidParamsException($"Malformed parameters: {ex.Message}");
        }
    }
}
