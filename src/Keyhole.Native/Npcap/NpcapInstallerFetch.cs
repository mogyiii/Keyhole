using System.Diagnostics;
using Keyhole.Core.Monitoring;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyhole.Native.Npcap;

/// <summary>
/// Fetches the Npcap installer from npcap.com and hands it to the user to install.
///
/// Keyhole does not ship Npcap. Its free licence forbids redistribution and bundling, so
/// the installer is pulled from the vendor by the machine that will run it — Keyhole only
/// saves the user the trip to the website.
///
/// Downloading an executable and running it is the riskiest thing Keyhole does, so it is
/// gated: the file is verified before it is ever launched, and the launch is a visible,
/// consent-prompting install rather than a silent one. A download that does not verify is
/// deleted, not run.
/// </summary>
public sealed class NpcapInstallerFetch(
    HttpClient? http = null,
    AuthenticodeVerifier? verifier = null,
    ILogger<NpcapInstallerFetch>? logger = null)
{
    private readonly AuthenticodeVerifier _verifier = verifier ?? new AuthenticodeVerifier();
    private readonly ILogger _logger = logger ?? NullLogger<NpcapInstallerFetch>.Instance;

    /// <summary>
    /// The version Keyhole fetches.
    ///
    /// Pinned rather than discovered: scraping a download page for the newest build would
    /// mean trusting whatever that page happens to say today. A pinned version can go
    /// stale, which is harmless — Npcap installers upgrade in place — whereas a wrong
    /// version chosen automatically is not. Bump it deliberately.
    /// </summary>
    public const string PinnedVersion = "1.90";

    public static Uri InstallerUri { get; } = new($"https://npcap.com/dist/npcap-{PinnedVersion}.exe");

    /// <summary>Where the vendor page lives, for the "do it yourself" path.</summary>
    public static Uri HomepageUri { get; } = new("https://npcap.com/#download");

    /// <summary>
    /// Organisations that sign Npcap. Checked against the signing certificate's subject,
    /// because a valid Authenticode signature on its own only proves <em>someone</em>
    /// signed the file — not that the right someone did.
    /// </summary>
    private static readonly string[] ExpectedSigners = ["Nmap", "Insecure.Com"];

    /// <summary>Guards against a redirect to something that is not an installer at all.</summary>
    private const long MaxInstallerBytes = 64 * 1024 * 1024;

    private readonly HttpClient _http = http ?? new HttpClient
    {
        Timeout = TimeSpan.FromMinutes(5),
    };

    /// <summary>
    /// Downloads the installer and verifies it. Returns the path to a file that is safe to
    /// launch, or a failure carrying a sentence explaining why nothing will be launched.
    /// </summary>
    public async Task<NpcapFetchResult> DownloadAsync(CancellationToken ct = default)
    {
        var target = Path.Combine(
            Path.GetTempPath(), $"keyhole-npcap-{PinnedVersion}-{Guid.NewGuid():N}.exe");

        try
        {
            _logger.LogInformation("Downloading Npcap {Version} from {Uri}", PinnedVersion, InstallerUri);

            using var response = await _http.GetAsync(
                InstallerUri, HttpCompletionOption.ResponseHeadersRead, ct);

            if (!response.IsSuccessStatusCode)
            {
                return NpcapFetchResult.Failed(
                    $"npcap.com answered {(int)response.StatusCode} for " +
                    $"npcap-{PinnedVersion}.exe. Install Npcap from {HomepageUri} instead.");
            }

            if (response.Content.Headers.ContentLength is > MaxInstallerBytes)
            {
                return NpcapFetchResult.Failed(
                    "The download is far larger than an Npcap installer should be; " +
                    "it was not saved.");
            }

            await using (var file = File.Create(target))
            {
                await response.Content.CopyToAsync(file, ct);
            }

            var length = new FileInfo(target).Length;
            if (length > MaxInstallerBytes)
            {
                Delete(target);
                return NpcapFetchResult.Failed(
                    "The download is far larger than an Npcap installer should be; " +
                    "it was discarded.");
            }

            if (Verify(target) is { } rejection)
            {
                // A file that fails verification must not survive on disk where a user
                // could find it in Downloads and run it by hand.
                Delete(target);
                _logger.LogWarning("Rejected the Npcap download: {Reason}", rejection);
                return NpcapFetchResult.Failed(rejection);
            }

            _logger.LogInformation(
                "Npcap {Version} downloaded and verified ({Bytes} bytes).", PinnedVersion, length);

            return NpcapFetchResult.Succeeded(target, length);
        }
        catch (OperationCanceledException)
        {
            Delete(target);
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException)
        {
            Delete(target);
            return NpcapFetchResult.Failed(
                $"Could not download Npcap: {ex.Message}. Install it from {HomepageUri} instead.");
        }
    }

    /// <summary>
    /// Why the downloaded file must not be launched, or null when it checks out.
    ///
    /// Two separate questions, and both have to hold: does the signature verify against a
    /// trusted chain, and is the signer actually the Nmap Project? Either one alone is not
    /// enough — the first accepts any signed malware, the second accepts a forged subject
    /// on an unsigned file.
    /// </summary>
    private string? Verify(string path)
    {
        var signature = _verifier.Describe(path);

        if (signature.Status != SignatureStatus.Valid)
        {
            return $"The downloaded Npcap installer is {signature.Status.ToString().ToLowerInvariant()} " +
                   "rather than validly signed, so Keyhole will not run it.";
        }

        if (!signature.IsSignedBy(ExpectedSigners))
        {
            return $"The downloaded file is signed by '{signature.SignerName ?? "an unreadable subject"}', " +
                   "not by the Nmap Project, so Keyhole will not run it.";
        }

        return null;
    }

    /// <summary>
    /// Starts the verified installer, elevating through the normal consent prompt.
    ///
    /// Deliberately not silent: this puts a third party's kernel driver on the machine, so
    /// the user sees the vendor's own installer and its licence rather than finding a new
    /// driver appear behind their back.
    /// </summary>
    public static bool Launch(string verifiedInstallerPath)
    {
        try
        {
            var process = Process.Start(new ProcessStartInfo
            {
                FileName = verifiedInstallerPath,
                UseShellExecute = true,
                Verb = "runas",
            });

            return process is not null;
        }
        catch (Exception)
        {
            // Declining the elevation prompt lands here. Not an error worth shouting about.
            return false;
        }
    }

    private static void Delete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best effort: a temp file left behind is a smaller problem than a throw here.
        }
    }
}

/// <summary>Outcome of fetching the installer.</summary>
/// <param name="InstallerPath">A verified file safe to launch, or null on failure.</param>
/// <param name="Bytes">Size of the downloaded installer.</param>
/// <param name="Error">Why nothing will be launched, or null on success.</param>
public sealed record NpcapFetchResult(string? InstallerPath, long Bytes, string? Error)
{
    public bool IsSuccess => InstallerPath is not null && Error is null;

    public static NpcapFetchResult Succeeded(string path, long bytes) => new(path, bytes, null);

    public static NpcapFetchResult Failed(string error) => new(null, 0, error);
}
