using System.Text;
using System.Text.Json;
using Keyhole.Core.Ipc;

namespace Keyhole.Tests;

public class IpcFramingTests
{
    [Fact]
    public async Task Round_trips_a_request()
    {
        var sent = new IpcRequest
        {
            Id = "abc123",
            Method = IpcMethods.GetStatus,
            Params = JsonSerializer.SerializeToElement(new { verbose = true }, IpcChannel.Json),
        };

        using var stream = new MemoryStream();
        await IpcFraming.WriteFrameAsync(stream, sent, CancellationToken.None);
        stream.Position = 0;

        var received = await IpcFraming.ReadFrameAsync<IpcRequest>(stream, CancellationToken.None);

        Assert.NotNull(received);
        Assert.Equal(sent.Id, received.Id);
        Assert.Equal(sent.Method, received.Method);
        Assert.True(received.Params!.Value.GetProperty("verbose").GetBoolean());
    }

    [Fact]
    public async Task Writes_exactly_one_trailing_delimiter()
    {
        using var stream = new MemoryStream();
        await IpcFraming.WriteFrameAsync(
            stream,
            new IpcRequest { Id = "x", Method = IpcMethods.Ping },
            CancellationToken.None);

        var bytes = stream.ToArray();
        Assert.Equal(IpcChannel.FrameDelimiter, bytes[^1]);
        Assert.Equal(1, bytes.Count(b => b == IpcChannel.FrameDelimiter));
    }

    [Fact]
    public async Task Returns_null_on_clean_end_of_stream()
    {
        using var empty = new MemoryStream();

        var received = await IpcFraming.ReadFrameAsync<IpcRequest>(empty, CancellationToken.None);

        Assert.Null(received);
    }

    [Fact]
    public async Task Throws_when_stream_ends_mid_frame()
    {
        using var truncated = new MemoryStream("""{"id":"x","method":"pi"""u8.ToArray());

        await Assert.ThrowsAsync<IpcProtocolException>(() =>
            IpcFraming.ReadFrameAsync<IpcRequest>(truncated, CancellationToken.None));
    }

    [Fact]
    public async Task Throws_on_malformed_json()
    {
        using var garbage = new MemoryStream(Encoding.UTF8.GetBytes("not json at all\n"));

        await Assert.ThrowsAsync<IpcProtocolException>(() =>
            IpcFraming.ReadFrameAsync<IpcRequest>(garbage, CancellationToken.None));
    }

    [Fact]
    public async Task Rejects_data_past_the_delimiter()
    {
        // Two frames in one buffer: the reader answers one request per connection, so
        // silently dropping the second would lose a caller's message.
        var payload = Encoding.UTF8.GetBytes(
            """{"id":"1","method":"ping"}""" + "\n" + """{"id":"2","method":"ping"}""" + "\n");
        using var pipelined = new MemoryStream(payload);

        await Assert.ThrowsAsync<IpcProtocolException>(() =>
            IpcFraming.ReadFrameAsync<IpcRequest>(pipelined, CancellationToken.None));
    }

    [Fact]
    public async Task Reassembles_a_frame_split_across_reads()
    {
        var json = JsonSerializer.Serialize(
            new IpcRequest { Id = "split", Method = IpcMethods.GetStatus }, IpcChannel.Json);

        // Chunks smaller than the reader's 4096-byte buffer force multiple reads.
        using var stream = new ChunkedStream(Encoding.UTF8.GetBytes(json + "\n"), chunkSize: 7);

        var received = await IpcFraming.ReadFrameAsync<IpcRequest>(stream, CancellationToken.None);

        Assert.NotNull(received);
        Assert.Equal("split", received.Id);
    }

    [Fact]
    public async Task Refuses_to_write_an_oversized_frame()
    {
        var huge = new string('x', IpcChannel.MaxFrameBytes + 1);
        using var stream = new MemoryStream();

        await Assert.ThrowsAsync<IpcProtocolException>(() =>
            IpcFraming.WriteFrameAsync(
                stream,
                new IpcRequest
                {
                    Id = "big",
                    Method = IpcMethods.Ping,
                    Params = JsonSerializer.SerializeToElement(huge, IpcChannel.Json),
                },
                CancellationToken.None));
    }

    /// <summary>Hands out at most <c>chunkSize</c> bytes per read, to exercise frame reassembly.</summary>
    private sealed class ChunkedStream(byte[] data, int chunkSize) : Stream
    {
        private int _position;

        public override int Read(byte[] buffer, int offset, int count)
        {
            var remaining = data.Length - _position;
            if (remaining == 0)
            {
                return 0;
            }

            var toCopy = Math.Min(Math.Min(count, chunkSize), remaining);
            Array.Copy(data, _position, buffer, offset, toCopy);
            _position += toCopy;
            return toCopy;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
