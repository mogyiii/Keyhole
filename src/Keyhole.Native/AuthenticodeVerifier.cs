using System.Runtime.InteropServices;
using Keyhole.Core.Monitoring;
using Keyhole.Native.Interop;

namespace Keyhole.Native;

/// <summary>
/// Verifies an executable's Authenticode signature through WinVerifyTrust.
/// Results are cached by path and write time: verification walks a certificate chain and
/// is far too slow to repeat for every connection sample.
/// </summary>
public sealed class AuthenticodeVerifier
{
    private readonly Dictionary<CacheKey, AuthenticodeSignature> _cache = [];
    private readonly Lock _gate = new();

    private const int MaxCacheEntries = 2048;

    public SignatureStatus Verify(string? executablePath) => Describe(executablePath).Status;

    /// <summary>
    /// Verifies the signature and names the signer.
    ///
    /// The signer matters whenever Keyhole is about to *act* on a file rather than merely
    /// describe it — launching a downloaded installer, for instance. "Validly signed" is
    /// not a sufficient test there: any signed binary passes it.
    /// </summary>
    public AuthenticodeSignature Describe(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            return new AuthenticodeSignature(SignatureStatus.Unknown, null);
        }

        CacheKey key;
        try
        {
            key = new CacheKey(executablePath, File.GetLastWriteTimeUtc(executablePath));
        }
        catch (IOException)
        {
            return new AuthenticodeSignature(SignatureStatus.Unknown, null);
        }
        catch (UnauthorizedAccessException)
        {
            return new AuthenticodeSignature(SignatureStatus.Unknown, null);
        }

        lock (_gate)
        {
            if (_cache.TryGetValue(key, out var cached))
            {
                return cached;
            }
        }

        var signature = VerifyUncached(executablePath);

        lock (_gate)
        {
            // Crude bound: signature results are cheap to recompute and the cache is only
            // an optimisation, so dropping everything beats tracking per-entry recency.
            if (_cache.Count >= MaxCacheEntries)
            {
                _cache.Clear();
            }

            _cache[key] = signature;
        }

        return signature;
    }

    private static AuthenticodeSignature VerifyUncached(string executablePath)
    {
        var fileInfo = new WinTrustApi.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustApi.WINTRUST_FILE_INFO>(),
            pcwszFilePath = executablePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustApi.WINTRUST_FILE_INFO>());
        var dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustApi.WINTRUST_DATA>());

        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);

            var data = new WinTrustApi.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustApi.WINTRUST_DATA>(),
                dwUIChoice = WinTrustApi.WTD_UI_NONE,
                // Revocation checking would reach the network, which is exactly what a
                // network monitor must not do while describing someone else's traffic.
                fdwRevocationChecks = WinTrustApi.WTD_REVOKE_NONE,
                dwUnionChoice = WinTrustApi.WTD_CHOICE_FILE,
                pFile = filePtr,
                dwStateAction = WinTrustApi.WTD_STATEACTION_VERIFY,
                dwProvFlags = WinTrustApi.WTD_SAFER_FLAG,
            };

            Marshal.StructureToPtr(data, dataPtr, false);

            var action = WinTrustApi.GenericVerifyV2;
            var result = WinTrustApi.WinVerifyTrust(IntPtr.Zero, ref action, dataPtr);

            var written = Marshal.PtrToStructure<WinTrustApi.WINTRUST_DATA>(dataPtr);

            // Read the signer before closing: the chain wintrust just built lives in the
            // state data, and CLOSE frees it.
            var signer = result == 0 ? ReadSignerName(written.hWVTStateData) : null;

            // Every VERIFY must be paired with a CLOSE or wintrust leaks its state block.
            written.dwStateAction = WinTrustApi.WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(written, dataPtr, false);
            WinTrustApi.WinVerifyTrust(IntPtr.Zero, ref action, dataPtr);

            var status = result switch
            {
                0 => SignatureStatus.Valid,
                WinTrustApi.TRUST_E_NOSIGNATURE => SignatureStatus.Unsigned,
                WinTrustApi.TRUST_E_SUBJECT_FORM_UNKNOWN => SignatureStatus.Unsigned,
                WinTrustApi.TRUST_E_PROVIDER_UNKNOWN => SignatureStatus.Unknown,

                // Anything else — bad digest, untrusted root, expired cert — means a
                // signature exists but does not hold. That is a stronger signal than
                // unsigned and must not be flattened into it.
                _ => SignatureStatus.Invalid,
            };

            return new AuthenticodeSignature(status, signer);
        }
        catch (Exception)
        {
            return new AuthenticodeSignature(SignatureStatus.Unknown, null);
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustApi.WINTRUST_FILE_INFO>(filePtr);
            Marshal.FreeHGlobal(filePtr);
            Marshal.FreeHGlobal(dataPtr);
        }
    }

    /// <summary>
    /// The leaf certificate's display name from the chain wintrust built, or null when the
    /// chain cannot be walked.
    ///
    /// Index 0 of the first signer's chain is the signing certificate itself; the rest of
    /// the chain is its issuers, which say nothing about who signed.
    /// </summary>
    private static string? ReadSignerName(IntPtr stateData)
    {
        if (stateData == IntPtr.Zero)
        {
            return null;
        }

        var providerData = WinTrustApi.WTHelperProvDataFromStateData(stateData);
        if (providerData == IntPtr.Zero)
        {
            return null;
        }

        var signer = WinTrustApi.WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
        if (signer == IntPtr.Zero)
        {
            return null;
        }

        var header = Marshal.PtrToStructure<WinTrustApi.CRYPT_PROVIDER_SGNR_HEAD>(signer);
        if (header.csCertChain == 0)
        {
            return null;
        }

        var providerCert = WinTrustApi.WTHelperGetProvCertFromChain(signer, 0);
        if (providerCert == IntPtr.Zero)
        {
            return null;
        }

        var certHeader = Marshal.PtrToStructure<WinTrustApi.CRYPT_PROVIDER_CERT_HEAD>(providerCert);
        if (certHeader.pCert == IntPtr.Zero)
        {
            return null;
        }

        // First call sizes the buffer; the count includes the terminating null.
        var required = WinTrustApi.CertGetNameString(
            certHeader.pCert, WinTrustApi.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, [], 0);

        if (required <= 1)
        {
            return null;
        }

        Span<char> buffer = required <= 256 ? stackalloc char[(int)required] : new char[required];

        var written = WinTrustApi.CertGetNameString(
            certHeader.pCert, WinTrustApi.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero,
            buffer, required);

        return written <= 1 ? null : new string(buffer[..((int)written - 1)]);
    }

    private readonly record struct CacheKey(string Path, DateTime LastWriteUtc);
}

/// <summary>
/// A signature verdict together with who signed, when that could be determined.
/// </summary>
/// <param name="Status">Whether the signature holds over the bytes on disk.</param>
/// <param name="SignerName">
/// The signing certificate's display name, or null when unsigned or unreadable. Only
/// meaningful alongside a <see cref="SignatureStatus.Valid"/> status — a name read from a
/// signature that does not verify proves nothing.
/// </param>
public sealed record AuthenticodeSignature(SignatureStatus Status, string? SignerName)
{
    /// <summary>
    /// Whether this file verifies <em>and</em> was signed by one of the named
    /// organisations. Both halves are required: the first alone accepts any signed
    /// binary, the second alone accepts a forged subject on a broken signature.
    /// </summary>
    public bool IsSignedBy(params string[] expected) =>
        Status == SignatureStatus.Valid &&
        SignerName is { } name &&
        expected.Any(e => name.Contains(e, StringComparison.OrdinalIgnoreCase));
}
