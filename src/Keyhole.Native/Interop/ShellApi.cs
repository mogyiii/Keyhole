using System.Runtime.InteropServices;

namespace Keyhole.Native.Interop;

/// <summary>
/// shell32 icon extraction. Uses the shell rather than reading the PE resource directly
/// so that whatever the user sees in Explorer is what Keyhole shows.
/// </summary>
internal static partial class ShellApi
{
    internal const uint SHGFI_ICON = 0x000000100;
    internal const uint SHGFI_LARGEICON = 0x000000000;
    internal const uint SHGFI_SMALLICON = 0x000000001;

    /// <summary>Treat the path as a plain string, so a missing file still yields a generic icon.</summary>
    internal const uint SHGFI_USEFILEATTRIBUTES = 0x000000010;

    internal const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct SHFILEINFO
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szDisplayName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
        public string szTypeName;
    }

    // Classic DllImport, not LibraryImport: SHFILEINFO carries ByValTStr strings, which
    // the P/Invoke source generator cannot marshal.
    [DllImport("shell32.dll", EntryPoint = "SHGetFileInfoW", CharSet = CharSet.Unicode)]
    internal static extern IntPtr SHGetFileInfo(
        string pszPath,
        uint dwFileAttributes,
        ref SHFILEINFO psfi,
        uint cbFileInfo,
        uint uFlags);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DestroyIcon(IntPtr hIcon);
}
