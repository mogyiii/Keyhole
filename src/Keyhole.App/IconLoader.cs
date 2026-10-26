using System;
using System.Collections.Generic;
using Avalonia;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Keyhole.Native;

namespace Keyhole.App;

/// <summary>
/// Turns an executable's icon into an Avalonia bitmap.
///
/// Runs in the UI process rather than the service: the UI already has the path, runs as
/// the interactive user, and this avoids shipping image bytes over IPC on every refresh.
/// </summary>
internal static class IconLoader
{
    private static readonly IconExtractor Extractor = new();
    private static readonly Dictionary<string, Bitmap?> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Lock Gate = new();

    public static Bitmap? Load(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return null;
        }

        lock (Gate)
        {
            if (Cache.TryGetValue(executablePath, out var cached))
            {
                return cached;
            }
        }

        var bitmap = Build(executablePath);

        lock (Gate)
        {
            // Failures cached too: an unreadable icon must not be retried every refresh.
            Cache[executablePath] = bitmap;
        }

        return bitmap;
    }

    private static Bitmap? Build(string executablePath)
    {
        var pixels = Extractor.TryGet(executablePath);
        if (pixels is null)
        {
            return null;
        }

        try
        {
            var bitmap = new WriteableBitmap(
                new PixelSize(pixels.Width, pixels.Height),
                new Vector(96, 96),
                PixelFormat.Bgra8888,
                // Windows icon bitmaps carry straight alpha, not premultiplied; saying
                // otherwise darkens every semi-transparent edge.
                AlphaFormat.Unpremul);

            using (var buffer = bitmap.Lock())
            {
                System.Runtime.InteropServices.Marshal.Copy(
                    pixels.Bgra, 0, buffer.Address, pixels.Bgra.Length);
            }

            return bitmap;
        }
        catch (Exception)
        {
            // A bad icon must never take the window down.
            return null;
        }
    }
}
