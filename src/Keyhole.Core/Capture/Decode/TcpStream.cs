namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// Rebuilds one direction of a TCP connection into the byte stream the application sent.
///
/// A capture holds segments, not a stream: they can arrive out of order, be retransmitted,
/// or overlap after a retransmission covered slightly different bytes. TLS cannot be read
/// from segments — its records span them, and its AEAD counts records, so one byte in the
/// wrong place makes every record after it undecryptable.
///
/// Segments are therefore placed by sequence number rather than by arrival, and the stream
/// is only handed on in the order the sender wrote it. Duplicates are dropped by position,
/// which handles retransmissions without needing to recognise them as such.
/// </summary>
public sealed class TcpStream
{
    /// <summary>Segments not yet contiguous with what has been delivered, by sequence number.</summary>
    private readonly SortedDictionary<long, byte[]> _pending = [];

    private readonly MemoryStream _delivered = new();

    /// <summary>
    /// The sequence number of the stream's first byte, learned from the SYN or from the
    /// first segment seen.
    ///
    /// Needed because TCP sequence numbers start at a random value: without a base, a
    /// stream's offsets are meaningless and its 32-bit wraparound cannot be detected.
    /// </summary>
    private long? _base;

    /// <summary>How far the contiguous stream reaches, as an offset from the base.</summary>
    private long _delivery;

    /// <summary>
    /// A ceiling on out-of-order data held for one direction.
    ///
    /// A connection with a permanent gap — its filling segment was never captured, which
    /// happens whenever a capture starts mid-connection — would otherwise accumulate every
    /// later segment forever.
    /// </summary>
    private const int MaxPendingBytes = 4 * 1024 * 1024;

    private long _pendingBytes;

    /// <summary>Bytes delivered in order so far.</summary>
    public long Length => _delivered.Length;

    /// <summary>
    /// True once a gap was abandoned. The stream after a gap cannot be trusted for TLS:
    /// record boundaries and AEAD sequence numbers both depend on every byte being present.
    /// </summary>
    public bool HasGap { get; private set; }

    /// <summary>When the first byte of this direction was captured.</summary>
    public DateTimeOffset? FirstSeenUtc { get; private set; }

    /// <summary>When the most recent byte of this direction was captured.</summary>
    public DateTimeOffset? LastSeenUtc { get; private set; }

    /// <summary>
    /// Adds one segment.
    /// </summary>
    /// <param name="sequenceNumber">The segment's TCP sequence number.</param>
    /// <param name="isSyn">
    /// Whether this is a SYN. A SYN consumes one sequence number without carrying a
    /// payload byte, so the stream's first data byte is at the SYN's number plus one —
    /// miss that and every offset is out by one.
    /// </param>
    public void Add(
        uint sequenceNumber, ReadOnlyMemory<byte> payload, bool isSyn, DateTimeOffset timestamp)
    {
        if (isSyn)
        {
            _base ??= (long)sequenceNumber + 1;
        }

        if (payload.Length == 0)
        {
            return;
        }

        // A capture that began mid-connection has no SYN, so the first data segment seen
        // becomes the base. The stream is then a suffix of the real one, which is fine for
        // reporting but means TLS will not decrypt — and HasGap is not the right signal for
        // that, because nothing is actually missing from what we have.
        _base ??= sequenceNumber;

        FirstSeenUtc ??= timestamp;
        LastSeenUtc = timestamp;

        var offset = Offset(sequenceNumber);

        // Already delivered in full: a plain retransmission.
        if (offset + payload.Length <= _delivery)
        {
            return;
        }

        // Partially delivered: a retransmission covering a wider range than the original.
        // Keep only the new tail, so the delivered bytes are never rewritten.
        if (offset < _delivery)
        {
            var skip = (int)(_delivery - offset);
            payload = payload[skip..];
            offset = _delivery;
        }

        if (offset == _delivery)
        {
            Deliver(payload.Span);
            DrainPending();
            return;
        }

        // Out of order. Hold it until the gap in front of it is filled.
        if (_pendingBytes + payload.Length > MaxPendingBytes)
        {
            // The gap is not going to be filled. Give up on it rather than grow without
            // bound, and record that the stream is no longer complete.
            HasGap = true;
            return;
        }

        if (_pending.TryAdd(offset, payload.ToArray()))
        {
            _pendingBytes += payload.Length;
        }
    }

    /// <summary>
    /// Converts a sequence number to a stream offset, allowing for 32-bit wraparound.
    ///
    /// TCP sequence numbers are 32 bits and wrap, which a long-lived or high-volume
    /// connection does reach. Comparing them as plain integers across the wrap would place
    /// a later segment four gigabytes before an earlier one.
    /// </summary>
    private long Offset(uint sequenceNumber)
    {
        var raw = (long)sequenceNumber - _base!.Value;

        // Halfway round the sequence space is the conventional dividing line between
        // "behind" and "wrapped ahead": no real window comes near it.
        const long half = 1L << 31;
        const long full = 1L << 32;

        while (raw < _delivery - half)
        {
            raw += full;
        }

        while (raw > _delivery + half)
        {
            raw -= full;
        }

        return raw;
    }

    private void Deliver(ReadOnlySpan<byte> payload)
    {
        _delivered.Write(payload);
        _delivery += payload.Length;
    }

    /// <summary>
    /// Delivers whatever held segments have now become contiguous. One arriving segment
    /// can unblock a run of them.
    /// </summary>
    private void DrainPending()
    {
        while (_pending.Count > 0)
        {
            var (offset, payload) = _pending.First();

            if (offset > _delivery)
            {
                return;
            }

            _pending.Remove(offset);
            _pendingBytes -= payload.Length;

            // It may overlap what has since been delivered by another path.
            var skip = (int)(_delivery - offset);
            if (skip < payload.Length)
            {
                Deliver(payload.AsSpan(skip));
            }
        }
    }

    /// <summary>
    /// The reassembled bytes.
    ///
    /// Only the contiguous prefix: anything still waiting on a gap is excluded, because
    /// handing it over would place bytes at the wrong offsets, which for TLS is worse than
    /// omitting them.
    /// </summary>
    public ReadOnlyMemory<byte> Bytes => _delivered.GetBuffer().AsMemory(0, (int)_delivered.Length);

    /// <summary>
    /// True when segments are still held for a gap that never filled. Reported separately
    /// from <see cref="HasGap"/>, which is about having abandoned one.
    /// </summary>
    public bool HasUnfilledGap => _pending.Count > 0;
}
