using Keyhole.Core.Capture;
using Keyhole.Core.Monitoring;
using Keyhole.Native;
using Keyhole.Native.Npcap;

namespace Keyhole.Tests;

/// <summary>
/// The probe reads real machine state, so these assert on what must hold on <em>any</em>
/// machine rather than on whether this particular one has Npcap. A test that only passes
/// on a developer box with Npcap installed would be worse than none: it would pass in CI
/// for the wrong reason.
/// </summary>
public class NpcapProbeTests
{
    [Fact]
    public void Detect_always_explains_itself()
    {
        var status = new NpcapProbe().Detect();

        // Whatever the verdict, the UI has to have a sentence to show. An empty detail
        // would leave the Capture tab saying nothing at all.
        Assert.False(string.IsNullOrWhiteSpace(status.Detail));
    }

    [Fact]
    public void Unavailable_reason_tracks_the_state()
    {
        var status = new NpcapProbe().Detect();

        if (status.State == NpcapState.Ready)
        {
            Assert.Null(status.UnavailableReason);
            Assert.True(status.IsReady);
        }
        else
        {
            Assert.NotNull(status.UnavailableReason);
            Assert.False(status.IsReady);
        }
    }

    [Fact]
    public void Install_is_only_offered_when_nothing_is_installed()
    {
        // Offering a download would not fix a stopped driver or a misplaced library, and
        // suggesting it would send the user down the wrong path.
        foreach (var state in Enum.GetValues<NpcapState>())
        {
            var status = new NpcapStatus(state, null, null, false, "detail");
            Assert.Equal(state == NpcapState.Missing, status.CanOfferInstall);
        }
    }

    [Fact]
    public void Library_lookup_agrees_with_the_verdict()
    {
        var probe = new NpcapProbe();
        var status = probe.Detect();
        var library = NpcapProbe.FindLibrary();

        // Ready or merely stopped, the library must have been found: both verdicts mean
        // the files are present. Only Missing and Unusable may have none.
        if (status.State is NpcapState.Ready or NpcapState.Stopped)
        {
            Assert.NotNull(library);
            Assert.True(File.Exists(library));
        }
    }
}

/// <summary>
/// Naming the signer is what makes the downloaded-installer check meaningful, so it is
/// tested against a file Windows itself signs rather than only through the download path.
/// </summary>
public class AuthenticodeSignerTests
{
    private static string SystemBinary => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");

    [Fact]
    public void Signer_of_a_system_binary_is_microsoft()
    {
        var signature = new AuthenticodeVerifier().Describe(SystemBinary);

        Assert.Equal(SignatureStatus.Valid, signature.Status);
        Assert.NotNull(signature.SignerName);
        Assert.Contains("Microsoft", signature.SignerName);
    }

    [Fact]
    public void IsSignedBy_requires_both_a_valid_signature_and_the_right_name()
    {
        var signature = new AuthenticodeVerifier().Describe(SystemBinary);

        Assert.True(signature.IsSignedBy("Microsoft"));
        Assert.False(signature.IsSignedBy("Nmap", "Insecure.Com"));

        // A name alone must never be enough: this is the check standing between a
        // downloaded executable and being run.
        Assert.False(new AuthenticodeSignature(SignatureStatus.Unsigned, "Microsoft Windows")
            .IsSignedBy("Microsoft"));
        Assert.False(new AuthenticodeSignature(SignatureStatus.Invalid, "Nmap Project")
            .IsSignedBy("Nmap"));
    }

    [Fact]
    public void An_unsigned_file_has_no_signer()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"keyhole-unsigned-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(temp, [0x4D, 0x5A, 0x90, 0x00]);

        try
        {
            var signature = new AuthenticodeVerifier().Describe(temp);

            Assert.NotEqual(SignatureStatus.Valid, signature.Status);
            Assert.Null(signature.SignerName);
            Assert.False(signature.IsSignedBy("Nmap"));
        }
        finally
        {
            File.Delete(temp);
        }
    }
}
