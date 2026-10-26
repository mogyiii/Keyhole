using System.Runtime.InteropServices;

namespace Keyhole.Native.Interop;

/// <summary>
/// gdi32 calls for turning an HICON into raw pixels.
/// Done this way rather than through System.Drawing.Common: that package is frozen at an
/// old version for modern .NET, and the only thing needed here is a pixel buffer, which
/// Avalonia consumes directly.
/// </summary>
internal static partial class GdiApi
{
    internal const int BI_RGB = 0;
    internal const uint DIB_RGB_COLORS = 0;

    [StructLayout(LayoutKind.Sequential)]
    internal struct ICONINFO
    {
        /// <summary>
        /// BOOL as int rather than bool: a MarshalAs'd bool makes the struct non-blittable,
        /// which source-generated P/Invoke cannot handle. Keyhole never reads this field.
        /// </summary>
        public int fIcon;

        public int xHotspot;
        public int yHotspot;
        public IntPtr hbmMask;
        public IntPtr hbmColor;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BITMAP
    {
        public int bmType;
        public int bmWidth;
        public int bmHeight;
        public int bmWidthBytes;
        public ushort bmPlanes;
        public ushort bmBitsPixel;
        public IntPtr bmBits;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth;

        /// <summary>Negative requests a top-down bitmap, matching how Avalonia reads rows.</summary>
        public int biHeight;

        public ushort biPlanes;
        public ushort biBitCount;
        public uint biCompression;
        public uint biSizeImage;
        public int biXPelsPerMeter;
        public int biYPelsPerMeter;
        public uint biClrUsed;
        public uint biClrImportant;
    }

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetIconInfo(IntPtr hIcon, out ICONINFO piconinfo);

    // EntryPoint is explicit: gdi32 exports GetObjectW, not GetObject. Classic DllImport
    // probes for the W suffix automatically, but source-generated P/Invoke does not.
    [LibraryImport("gdi32.dll", EntryPoint = "GetObjectW", SetLastError = true)]
    internal static partial int GetObject(IntPtr hgdiobj, int cbBuffer, out BITMAP lpvObject);

    [LibraryImport("gdi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DeleteObject(IntPtr hObject);

    [LibraryImport("user32.dll", SetLastError = true)]
    internal static partial IntPtr GetDC(IntPtr hWnd);

    [LibraryImport("user32.dll")]
    internal static partial int ReleaseDC(IntPtr hWnd, IntPtr hDC);

    [LibraryImport("gdi32.dll", SetLastError = true)]
    internal static partial int GetDIBits(
        IntPtr hdc,
        IntPtr hbmp,
        uint uStartScan,
        uint cScanLines,
        byte[]? lpvBits,
        ref BITMAPINFOHEADER lpbi,
        uint uUsage);
}
