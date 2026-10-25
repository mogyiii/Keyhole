using System.Buffers;
using System.Text;
using System.Text.Json;

namespace Keyhole.Core.Ipc;

/// <summary>
/// Reads and writes newline-delimited JSON frames over a stream. Shared by both ends so
/// framing bugs cannot differ between client and server.
/// </summary>
public static class IpcFraming
{
    public static async Task WriteFrameAsync<T>(Stream stream, T message, CancellationToken ct)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(message, IpcChannel.Json);
        if (json.Length > IpcChannel.MaxFrameBytes)
        {
            throw new IpcProtocolException(
                $"Refusing to send a {json.Length} byte frame; limit is {IpcChannel.MaxFrameBytes}.");
        }

        var buffer = new byte[json.Length + 1];
        json.CopyTo(buffer, 0);
        buffer[json.Length] = IpcChannel.FrameDelimiter;

        await stream.WriteAsync(buffer, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one frame. Returns null on a clean end of stream, which is how a peer
    /// disconnecting between requests looks and is not an error.
    /// </summary>
    public static async Task<T?> ReadFrameAsync<T>(Stream stream, CancellationToken ct)
        where T : class
    {
        var accumulated = new ArrayBufferWriter<byte>(1024);
        var chunk = new byte[4096];

        while (true)
        {
            var read = await stream.ReadAsync(chunk, ct).ConfigureAwait(false);
            if (read == 0)
            {
                if (accumulated.WrittenCount == 0)
                {
                    return null;
                }

                throw new IpcProtocolException("Stream ended mid-frame.");
            }

            var span = chunk.AsSpan(0, read);
            var newline = span.IndexOf(IpcChannel.FrameDelimiter);

            if (newline < 0)
            {
                accumulated.Write(span);
                if (accumulated.WrittenCount > IpcChannel.MaxFrameBytes)
                {
                    throw new IpcProtocolException(
                        $"Frame exceeded {IpcChannel.MaxFrameBytes} bytes without a delimiter.");
                }

                continue;
            }

            accumulated.Write(span[..newline]);

            // A peer that pipelines frames would leave bytes after the newline. We answer one
            // request per read loop, so treat trailing data as a protocol violation rather than
            // silently dropping it.
            if (newline + 1 < read)
            {
                throw new IpcProtocolException(
                    "Received data past the frame delimiter; pipelining is not supported.");
            }

            return Deserialize<T>(accumulated.WrittenSpan);
        }
    }

    private static T Deserialize<T>(ReadOnlySpan<byte> utf8) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(utf8, IpcChannel.Json)
                   ?? throw new IpcProtocolException("Frame deserialised to null.");
        }
        catch (JsonException ex)
        {
            var preview = Encoding.UTF8.GetString(utf8[..Math.Min(utf8.Length, 256)]);
            throw new IpcProtocolException($"Malformed frame: {preview}", ex);
        }
    }
}

public sealed class IpcProtocolException : Exception
{
    public IpcProtocolException(string message) : base(message) { }
    public IpcProtocolException(string message, Exception inner) : base(message, inner) { }
}
