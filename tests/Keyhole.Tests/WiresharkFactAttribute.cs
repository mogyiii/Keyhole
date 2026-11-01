namespace Keyhole.Tests;

/// <summary>
/// A fact that runs only where Wireshark's command line tools are installed.
///
/// These tests check Keyhole's capture output against the reference implementation of the
/// format, which is the only check that cannot be fooled by Keyhole misunderstanding
/// pcapng consistently. That makes them worth having even though they cannot run
/// everywhere: CI has no Wireshark, and a hard dependency would turn a useful extra
/// verification into a broken build.
///
/// Skipping is deliberate and visible — the runner reports it with the reason — so an
/// unverified run never looks like a verified one.
/// </summary>
public sealed class WiresharkFactAttribute : FactAttribute
{
    public WiresharkFactAttribute()
    {
        if (PcapngWiresharkTests.WiresharkTool("tshark.exe") is null)
        {
            Skip = "Wireshark is not installed, so Keyhole's capture files were not " +
                   "checked against it.";
        }
    }
}
