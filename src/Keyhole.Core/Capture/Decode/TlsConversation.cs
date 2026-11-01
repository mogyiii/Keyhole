using System.Buffers.Binary;

namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// Decrypts one TLS connection, given the two reassembled directions of its TCP stream and
/// the session's keylog.
///
/// The hard part is not the cryptography — .NET provides the AEADs — but keeping count.
/// Record nonces come from a sequence number that is never transmitted, so the decoder has
/// to know exactly how many records preceded each one, and when the count resets. In TLS
/// 1.3 it resets once per direction, at the switch from handshake keys to application
/// keys, and nothing in the record says where that switch is: an encrypted handshake
/// record and an encrypted application record are indistinguishable from outside.
///
/// The switch is therefore found by attempting it. Handshake keys are tried first; the
/// first record they fail to open is the first one under application keys. The AEAD tag is
/// what makes this sound — a wrong key cannot produce a passing tag — so the detection is
/// as reliable as the authentication itself.
/// </summary>
public static class TlsConversation
{
    /// <summary>
    /// How many key updates one direction may be followed through.
    ///
    /// Each one is a guess validated by an AEAD tag, so a wrong guess costs one failed
    /// decryption and nothing else. A bound exists only so that a stream of undecryptable
    /// records cannot turn into an unbounded chain of derivations.
    /// </summary>
    private const int MaxKeyUpdates = 64;

    /// <summary>
    /// Decrypts both directions of a connection.
    /// </summary>
    /// <param name="clientStream">Bytes the client sent, reassembled in order.</param>
    /// <param name="serverStream">Bytes the server sent, reassembled in order.</param>
    /// <param name="keylog">The session's secrets.</param>
    public static TlsDecryption Decrypt(
        ReadOnlyMemory<byte> clientStream,
        ReadOnlyMemory<byte> serverStream,
        TlsKeylog keylog)
    {
        var clientRecords = TlsRecordLayer.Read(clientStream).ToList();
        var serverRecords = TlsRecordLayer.Read(serverStream).ToList();

        if (clientRecords.Count == 0)
        {
            return TlsDecryption.NotTls();
        }

        var clientRandom = clientRecords
            .Select(TlsRecordLayer.ReadClientRandom)
            .FirstOrDefault(r => r is not null);

        if (clientRandom is null)
        {
            // TLS records but no ClientHello: the capture began after this connection was
            // already established. Nothing identifies it, so nothing can decrypt it.
            return TlsDecryption.NoHandshake();
        }

        var hello = serverRecords
            .Select(TlsRecordLayer.ReadServerHello)
            .FirstOrDefault(h => h is not null);

        if (hello is null)
        {
            return TlsDecryption.NoHandshake();
        }

        if (!keylog.Knows(clientRandom))
        {
            // The overwhelmingly common case for an application on Windows' own TLS stack:
            // the connection is perfectly captured and permanently unreadable.
            return TlsDecryption.NoKeys(hello);
        }

        var suite = TlsCipherSuite.Find(hello.CipherSuite);
        if (suite is null)
        {
            return TlsDecryption.UnsupportedSuite(hello);
        }

        return hello.IsTls13
            ? DecryptTls13(clientRecords, serverRecords, clientRandom, suite, keylog, hello)
            : DecryptTls12(clientRecords, serverRecords, clientRandom, suite, keylog, hello);
    }

    private static TlsDecryption DecryptTls13(
        List<TlsRecord> clientRecords,
        List<TlsRecord> serverRecords,
        byte[] clientRandom,
        TlsCipherSuite suite,
        TlsKeylog keylog,
        ServerHello hello)
    {
        var client = DecryptTls13Direction(
            clientRecords,
            keylog.Find(clientRandom, TlsKeylog.ClientHandshakeTrafficSecret),
            keylog.Find(clientRandom, TlsKeylog.ClientTrafficSecret0),
            suite);

        var server = DecryptTls13Direction(
            serverRecords,
            keylog.Find(clientRandom, TlsKeylog.ServerHandshakeTrafficSecret),
            keylog.Find(clientRandom, TlsKeylog.ServerTrafficSecret0),
            suite);

        if (client.Length == 0 && server.Length == 0)
        {
            return TlsDecryption.Failed(
                hello, suite, "the keys in the capture did not open any record");
        }

        return TlsDecryption.Succeeded(hello, suite, client, server);
    }

    /// <summary>
    /// Decrypts one direction of a TLS 1.3 connection.
    /// </summary>
    /// <param name="handshakeSecret">
    /// Opens the encrypted handshake records. Their contents are not wanted — they are
    /// certificates and Finished messages — but they must be counted, because the
    /// application records' sequence numbers depend on finding where they end.
    /// </param>
    /// <param name="applicationSecret">Opens the records carrying the actual payload.</param>
    private static byte[] DecryptTls13Direction(
        List<TlsRecord> records,
        byte[]? handshakeSecret,
        byte[]? applicationSecret,
        TlsCipherSuite suite)
    {
        var handshakeKeys = handshakeSecret is null
            ? null
            : TlsKeySchedule.FromTrafficSecret(handshakeSecret, suite);

        var applicationKeys = applicationSecret is null
            ? null
            : TlsKeySchedule.FromTrafficSecret(applicationSecret, suite);

        var plaintext = new MemoryStream();

        var handshakeSequence = 0UL;
        var applicationSequence = 0UL;
        var inHandshake = true;

        // The secret the application keys were derived from, kept because a key update
        // derives the next one from it.
        var currentSecret = applicationSecret;
        var keyUpdates = 0;

        foreach (var record in records)
        {
            // Plaintext records: the initial hello, and the ChangeCipherSpec that TLS 1.3
            // sends purely so middleboxes see a familiar sequence. Neither is encrypted
            // and neither advances a sequence number.
            if (record.ContentType != TlsRecordLayer.ContentTypeApplicationData)
            {
                continue;
            }

            if (inHandshake && handshakeKeys is not null)
            {
                var opened = Open(suite, handshakeKeys, handshakeSequence, record);

                if (opened is not null)
                {
                    handshakeSequence++;
                    continue;
                }

                // The handshake key stopped working, which is the switch to application
                // keys. The sequence number restarts from zero here.
                inHandshake = false;
            }
            else
            {
                inHandshake = false;
            }

            if (applicationKeys is null)
            {
                break;
            }

            var application = Open(suite, applicationKeys, applicationSequence, record);

            if (application is null && currentSecret is not null && keyUpdates < MaxKeyUpdates)
            {
                // A key update. Either side may send one mid-connection, after which the
                // traffic secret is derived from the current one and the sequence number
                // restarts at zero. The keylog only ever holds secret 0, so a decoder that
                // stops here loses the rest of a long connection — which is exactly what a
                // real browser session downloading tens of megabytes produces, and what
                // showed up as "a key that Keyhole could not use".
                //
                // Nothing in the record says an update happened: the KeyUpdate message is
                // itself encrypted under the old key. So the derivation is attempted, and
                // the AEAD tag decides whether it was right.
                currentSecret = TlsKeySchedule.ExpandLabel(
                    currentSecret, "traffic upd", [], suite.HashLength, suite.HashName);

                applicationKeys = TlsKeySchedule.FromTrafficSecret(currentSecret, suite);
                applicationSequence = 0;
                keyUpdates++;

                application = Open(suite, applicationKeys, applicationSequence, record);
            }

            if (application is null)
            {
                // A genuine loss: a missing record, or more updates than we will chase.
                // Everything after it would be nonsense, so stop and keep what is good.
                break;
            }

            applicationSequence++;

            // TLS 1.3 hides the real content type at the end of the plaintext, after any
            // padding. A record can hold a handshake message — a session ticket, say —
            // even in the application phase, and that is not payload.
            var (contentLength, innerType) = StripInnerType(application);

            if (innerType == TlsRecordLayer.ContentTypeApplicationData)
            {
                plaintext.Write(application.AsSpan(0, contentLength));
            }
        }

        return plaintext.ToArray();
    }

    /// <summary>
    /// Separates a TLS 1.3 record's payload from the content type hidden at its end.
    ///
    /// The layout is content, then the real type, then any number of zero bytes as
    /// padding. So the type is the last non-zero byte, and everything before it is the
    /// content.
    /// </summary>
    /// <returns>
    /// How many leading bytes are content, and the real content type. A length rather than
    /// a slice because a span cannot be returned in a tuple.
    /// </returns>
    private static (int ContentLength, byte Type) StripInnerType(byte[] plaintext)
    {
        var end = plaintext.Length - 1;

        while (end >= 0 && plaintext[end] == 0)
        {
            end--;
        }

        return end < 0 ? (0, (byte)0) : (end, plaintext[end]);
    }

    /// <summary>
    /// Opens a TLS 1.3 record. The associated data is the record header exactly as it
    /// appeared on the wire.
    /// </summary>
    private static byte[]? Open(
        TlsCipherSuite suite, TlsDirectionKeys keys, ulong sequence, TlsRecord record)
    {
        var nonce = TlsKeySchedule.Nonce(keys.Iv, sequence);

        return suite.Open(keys.Key, nonce, record.Payload.Span, record.Header.Span);
    }

    private static TlsDecryption DecryptTls12(
        List<TlsRecord> clientRecords,
        List<TlsRecord> serverRecords,
        byte[] clientRandom,
        TlsCipherSuite suite,
        TlsKeylog keylog,
        ServerHello hello)
    {
        var masterSecret = keylog.Find(clientRandom, TlsKeylog.ClientRandom);

        if (masterSecret is null)
        {
            // A TLS 1.2 connection needs the CLIENT_RANDOM line specifically. A keylog
            // with only 1.3 secrets cannot open it.
            return TlsDecryption.NoKeys(hello);
        }

        var keys = TlsKeySchedule.FromMasterSecret(
            masterSecret, clientRandom, hello.ServerRandom, suite);

        var client = DecryptTls12Direction(clientRecords, keys.Client, suite);
        var server = DecryptTls12Direction(serverRecords, keys.Server, suite);

        if (client.Length == 0 && server.Length == 0)
        {
            return TlsDecryption.Failed(
                hello, suite, "the master secret in the capture did not open any record");
        }

        return TlsDecryption.Succeeded(hello, suite, client, server);
    }

    /// <summary>
    /// Decrypts one direction of a TLS 1.2 connection.
    ///
    /// Simpler than 1.3 in one way — there is no mid-stream key change, so the sequence
    /// number runs from zero after ChangeCipherSpec and never resets — and more awkward in
    /// another: the GCM suites put eight nonce bytes in the clear at the front of every
    /// record, and the associated data includes the plaintext length, which must be
    /// computed by subtracting those bytes and the tag.
    /// </summary>
    private static byte[] DecryptTls12Direction(
        List<TlsRecord> records, TlsDirectionKeys keys, TlsCipherSuite suite)
    {
        var plaintext = new MemoryStream();
        var sequence = 0UL;
        var encrypted = false;

        foreach (var record in records)
        {
            if (record.ContentType == TlsRecordLayer.ContentTypeChangeCipherSpec)
            {
                // Everything after this point is encrypted, counting from zero.
                encrypted = true;
                sequence = 0;
                continue;
            }

            if (!encrypted)
            {
                continue;
            }

            var payload = record.Payload.Span;

            if (payload.Length < suite.ExplicitNonceLength + suite.TagLength)
            {
                break;
            }

            byte[] nonce;
            ReadOnlySpan<byte> ciphertext;

            if (suite.ExplicitNonceLength > 0)
            {
                // GCM in TLS 1.2: a 4-byte salt from the key schedule, then 8 bytes from
                // the record itself.
                nonce = new byte[12];
                keys.Iv.CopyTo(nonce, 0);
                payload[..suite.ExplicitNonceLength].CopyTo(nonce.AsSpan(suite.FixedIvLength));
                ciphertext = payload[suite.ExplicitNonceLength..];
            }
            else
            {
                // ChaCha20-Poly1305 in TLS 1.2 uses the TLS 1.3 nonce construction.
                nonce = TlsKeySchedule.Nonce(keys.Iv, sequence);
                ciphertext = payload;
            }

            var plaintextLength = ciphertext.Length - suite.TagLength;
            var associatedData = Tls12AssociatedData(
                sequence, record.ContentType, record.Version, plaintextLength);

            var opened = suite.Open(keys.Key, nonce, ciphertext, associatedData);
            if (opened is null)
            {
                break;
            }

            sequence++;

            if (record.ContentType == TlsRecordLayer.ContentTypeApplicationData)
            {
                plaintext.Write(opened);
            }
        }

        return plaintext.ToArray();
    }

    /// <summary>
    /// TLS 1.2's associated data: the sequence number, then the record header with the
    /// <em>plaintext</em> length rather than the length on the wire.
    /// </summary>
    private static byte[] Tls12AssociatedData(
        ulong sequence, byte contentType, ushort version, int plaintextLength)
    {
        var data = new byte[13];
        BinaryPrimitives.WriteUInt64BigEndian(data, sequence);
        data[8] = contentType;
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(9), version);
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(11), (ushort)plaintextLength);
        return data;
    }
}

/// <summary>
/// What came of trying to decrypt one connection.
///
/// The failure cases are distinguished rather than collapsed, because they mean different
/// things to a user: no keys in the capture is expected for a Schannel application, while
/// keys that do not work is a bug in Keyhole.
/// </summary>
public sealed record TlsDecryption
{
    public required TlsDecryptionOutcome Outcome { get; init; }

    /// <summary>Bytes the client sent, decrypted.</summary>
    public byte[] ClientPlaintext { get; init; } = [];

    /// <summary>Bytes the server sent, decrypted.</summary>
    public byte[] ServerPlaintext { get; init; } = [];

    public ServerHello? Hello { get; init; }

    public TlsCipherSuite? Suite { get; init; }

    /// <summary>A sentence for the user when the outcome needs explaining.</summary>
    public string? Detail { get; init; }

    public bool IsDecrypted => Outcome == TlsDecryptionOutcome.Decrypted;

    /// <summary>
    /// Whether this was TLS at all. Used to tell an encrypted connection with no keys
    /// apart from a connection that simply was not TLS.
    /// </summary>
    public bool IsTls => Outcome != TlsDecryptionOutcome.NotTls;

    public static TlsDecryption NotTls() => new() { Outcome = TlsDecryptionOutcome.NotTls };

    public static TlsDecryption NoHandshake() => new()
    {
        Outcome = TlsDecryptionOutcome.NoHandshake,
        Detail = "the capture began after this connection was established",
    };

    public static TlsDecryption NoKeys(ServerHello hello) => new()
    {
        Outcome = TlsDecryptionOutcome.NoKeys,
        Hello = hello,
        Detail = "no key for this connection is in the capture",
    };

    public static TlsDecryption UnsupportedSuite(ServerHello hello) => new()
    {
        Outcome = TlsDecryptionOutcome.UnsupportedSuite,
        Hello = hello,
        Detail = $"cipher suite 0x{hello.CipherSuite:X4} is not one Keyhole can decrypt",
    };

    public static TlsDecryption Failed(ServerHello hello, TlsCipherSuite suite, string detail) => new()
    {
        Outcome = TlsDecryptionOutcome.Failed,
        Hello = hello,
        Suite = suite,
        Detail = detail,
    };

    public static TlsDecryption Succeeded(
        ServerHello hello, TlsCipherSuite suite, byte[] client, byte[] server) => new()
    {
        Outcome = TlsDecryptionOutcome.Decrypted,
        Hello = hello,
        Suite = suite,
        ClientPlaintext = client,
        ServerPlaintext = server,
    };
}

public enum TlsDecryptionOutcome
{
    /// <summary>The stream is not TLS. Plain HTTP, or another protocol entirely.</summary>
    NotTls,

    /// <summary>TLS, but the handshake was not captured, so the connection cannot be identified.</summary>
    NoHandshake,

    /// <summary>
    /// TLS with a handshake, but the capture holds no secret for it. Expected for anything
    /// on Windows' own TLS stack, which ignores SSLKEYLOGFILE.
    /// </summary>
    NoKeys,

    /// <summary>A cipher suite outside what Keyhole implements.</summary>
    UnsupportedSuite,

    /// <summary>Keys were present but opened nothing. A bug, not a limitation.</summary>
    Failed,

    Decrypted,
}
