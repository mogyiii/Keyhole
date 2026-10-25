using System.Runtime.InteropServices;

namespace Keyhole.Native.Interop;

/// <summary>
/// wintrust.dll Authenticode verification.
/// Reading the embedded certificate alone proves nothing — it shows who signed *something*,
/// not that the signature still covers the bytes on disk. WinVerifyTrust is the API that
/// actually checks the hash and walks the trust chain.
/// </summary>
internal static partial class WinTrustApi
{
    internal const uint WTD_UI_NONE = 2;
    internal const uint WTD_REVOKE_NONE = 0;
    internal const uint WTD_CHOICE_FILE = 1;
    internal const uint WTD_STATEACTION_VERIFY = 1;
    internal const uint WTD_STATEACTION_CLOSE = 2;
    internal const uint WTD_SAFER_FLAG = 0x100;

    internal const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    internal const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    internal const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    internal const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);

    /// <summary>WINTRUST_ACTION_GENERIC_VERIFY_V2 — the standard Authenticode policy.</summary>
    internal static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [LibraryImport("wintrust.dll", EntryPoint = "WinVerifyTrust")]
    internal static partial int WinVerifyTrust(IntPtr hwnd, ref Guid actionId, IntPtr data);

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
