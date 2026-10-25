namespace Keyhole.Core.Monitoring;

/// <summary>
/// Turns a PID into something the user can recognise. Abstracted so the flow tracker
/// can be tested without depending on what happens to be running.
/// </summary>
public interface IProcessResolver
{
    /// <summary>
    /// Resolves a PID. Never throws: a process that exits mid-lookup, or one Keyhole
    /// cannot open, still yields an identity with whatever could be read.
    /// </summary>
    ProcessIdentity Resolve(int processId);
}
