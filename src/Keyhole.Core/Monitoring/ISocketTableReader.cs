namespace Keyhole.Core.Monitoring;

/// <summary>
/// Source of socket snapshots. Abstracted so the flow tracker can be tested against
/// scripted snapshots instead of whatever the machine happens to be doing.
/// </summary>
public interface ISocketTableReader
{
    IReadOnlyList<NetworkConnection> ReadAll();
}
