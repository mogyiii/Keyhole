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
    private readonly Dictionary<CacheKey, SignatureStatus> _cache = [];
    private readonly Lock _gate = new();

    private const int MaxCacheEntries = 2048;

    public SignatureStatus Verify(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
        {
            return SignatureStatus.Unknown;
        }

        CacheKey key;
        try
        {
            key = new CacheKey(executablePath, File.GetLastWriteTimeUtc(executablePath));
        }
        catch (IOException)
        {
            return SignatureStatus.Unknown;
        }
        catch (UnauthorizedAccessException)
        {
            return SignatureStatus.Unknown;
        }

        lock (_gate)
        {
            if (_cache.TryGetValue(key, out var cached))
            {
                return cached;
            }
        }

        var status = VerifyUncached(executablePath);

        lock (_gate)
        {
            // Crude bound: signature results are cheap to recompute and the cache is only
            // an optimisation, so dropping everything beats tracking per-entry recency.
            if (_cache.Count >= MaxCacheEntries)
            {
                _cache.Clear();
            }

            _cache[key] = status;
        }

        return status;
    }

    private static SignatureStatus VerifyUncached(string executablePath)
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

            // Every VERIFY must be paired with a CLOSE or wintrust leaks its state block.
            var written = Marshal.PtrToStructure<WinTrustApi.WINTRUST_DATA>(dataPtr);
            written.dwStateAction = WinTrustApi.WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(written, dataPtr, false);
            WinTrustApi.WinVerifyTrust(IntPtr.Zero, ref action, dataPtr);

            return result switch
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
        }
        catch (Exception)
        {
            return SignatureStatus.Unknown;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustApi.WINTRUST_FILE_INFO>(filePtr);
            Marshal.FreeHGlobal(filePtr);
            Marshal.FreeHGlobal(dataPtr);
        }
    }

    private readonly record struct CacheKey(string Path, DateTime LastWriteUtc);
}
