using Keyhole.Native.Interop;

namespace Keyhole.Native;

/// <summary>Raw icon pixels, ready to hand to a UI toolkit.</summary>
public sealed record IconPixels(int Width, int Height, byte[] Bgra);

/// <summary>
/// Pulls an application's icon out of its executable.
///
/// Goes through the shell rather than reading the PE resource directly, so what Keyhole
/// shows is what the user sees in Explorer — including overlays and the shell's own
/// choice among several embedded icons.
/// </summary>
public sealed class IconExtractor
{
    private readonly Dictionary<string, IconPixels?> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();

    private const int MaxCacheEntries = 512;

    /// <summary>
    /// Icon for an executable, or null when none could be read. Cached by path: the UI
    /// asks for every row on every refresh, and shell icon lookups hit the disk.
    /// </summary>
    public IconPixels? TryGet(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return null;
        }

        lock (_gate)
        {
            if (_cache.TryGetValue(executablePath, out var cached))
            {
                return cached;
            }
        }

        var icon = Extract(executablePath);

        lock (_gate)
        {
            if (_cache.Count >= MaxCacheEntries)
            {
                _cache.Clear();
            }

            // Failures are cached too, otherwise an unreadable path is retried on
            // every refresh forever.
            _cache[executablePath] = icon;
        }

        return icon;
    }

    private static IconPixels? Extract(string executablePath)
    {
        var info = default(ShellApi.SHFILEINFO);

        // USEFILEATTRIBUTES means the shell works from the path string alone, so a file
        // Keyhole cannot open still yields the generic icon for its type.
        var flags = ShellApi.SHGFI_ICON | ShellApi.SHGFI_LARGEICON | ShellApi.SHGFI_USEFILEATTRIBUTES;

        var result = ShellApi.SHGetFileInfo(
            executablePath,
            ShellApi.FILE_ATTRIBUTE_NORMAL,
            ref info,
            (uint)System.Runtime.InteropServices.Marshal.SizeOf<ShellApi.SHFILEINFO>(),
            flags);

        if (result == IntPtr.Zero || info.hIcon == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return ToPixels(info.hIcon);
        }
        finally
        {
            ShellApi.DestroyIcon(info.hIcon);
        }
    }

    private static IconPixels? ToPixels(IntPtr hIcon)
    {
        if (!GdiApi.GetIconInfo(hIcon, out var iconInfo))
        {
            return null;
        }

        try
        {
            if (iconInfo.hbmColor == IntPtr.Zero)
            {
                // A 1-bit icon with no colour bitmap. Rare enough on modern binaries
                // that rendering it is not worth the extra mask handling.
                return null;
            }

            if (GdiApi.GetObject(
                    iconInfo.hbmColor,
                    System.Runtime.InteropServices.Marshal.SizeOf<GdiApi.BITMAP>(),
                    out var bitmap) == 0)
            {
                return null;
            }

            var header = new GdiApi.BITMAPINFOHEADER
            {
                biSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<GdiApi.BITMAPINFOHEADER>(),
                biWidth = bitmap.bmWidth,
                // Negative height asks GDI for top-down rows, which is the order a UI
                // toolkit expects; bottom-up would render the icon upside down.
                biHeight = -bitmap.bmHeight,
                biPlanes = 1,
                biBitCount = 32,
                biCompression = GdiApi.BI_RGB,
            };

            var buffer = new byte[bitmap.bmWidth * bitmap.bmHeight * 4];
            var dc = GdiApi.GetDC(IntPtr.Zero);

            try
            {
                var copied = GdiApi.GetDIBits(
                    dc, iconInfo.hbmColor, 0, (uint)bitmap.bmHeight, buffer, ref header, GdiApi.DIB_RGB_COLORS);

                if (copied == 0)
                {
                    return null;
                }
            }
            finally
            {
                GdiApi.ReleaseDC(IntPtr.Zero, dc);
            }

            return HasAnyOpaquePixel(buffer)
                ? new IconPixels(bitmap.bmWidth, bitmap.bmHeight, buffer)
                // Some icons come back fully transparent, which would render as a blank
                // gap in the list. Reporting none lets the UI fall back to a placeholder.
                : null;
        }
        finally
        {
            if (iconInfo.hbmColor != IntPtr.Zero)
            {
                GdiApi.DeleteObject(iconInfo.hbmColor);
            }

            if (iconInfo.hbmMask != IntPtr.Zero)
            {
                GdiApi.DeleteObject(iconInfo.hbmMask);
            }
        }
    }

    private static bool HasAnyOpaquePixel(byte[] bgra)
    {
        for (var i = 3; i < bgra.Length; i += 4)
        {
            if (bgra[i] != 0)
            {
                return true;
            }
        }

        return false;
    }
}
