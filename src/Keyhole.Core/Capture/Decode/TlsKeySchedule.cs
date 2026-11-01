using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// Turns the secrets from a keylog into the keys and nonces that open records.
///
/// The keylog does not contain keys. It contains the secrets one step above them, which is
/// what makes a keylog portable across cipher suites — the derivation from secret to key
/// depends on the suite, and is done here.
/// </summary>
public static class TlsKeySchedule
{
    /// <summary>
    /// TLS 1.3: derives a direction's key and nonce from its traffic secret.
    ///
    /// Both come from the same secret through HKDF with different labels, which is why a
    /// single keylog line is enough to read a whole direction of a connection.
    /// </summary>
    public static TlsDirectionKeys FromTrafficSecret(byte[] trafficSecret, TlsCipherSuite suite) =>
        new(
            ExpandLabel(trafficSecret, "key", [], suite.KeyLength, suite.HashName),
            ExpandLabel(trafficSecret, "iv", [], 12, suite.HashName));

    /// <summary>
    /// HKDF-Expand-Label from RFC 8446.
    ///
    /// The label is prefixed with "tls13 " and the whole structure is length-prefixed, so
    /// that a secret derived for one purpose can never be mistaken for one derived for
    /// another — which is also why getting the encoding slightly wrong yields a key that
    /// decrypts nothing rather than one that nearly works.
    /// </summary>
    public static byte[] ExpandLabel(
        byte[] secret,
        string label,
        ReadOnlySpan<byte> context,
        int length,
        HashAlgorithmName hash)
    {
        var fullLabel = Encoding.ASCII.GetBytes("tls13 " + label);

        var info = new byte[2 + 1 + fullLabel.Length + 1 + context.Length];
        BinaryPrimitives.WriteUInt16BigEndian(info, (ushort)length);
        info[2] = (byte)fullLabel.Length;
        fullLabel.CopyTo(info, 3);
        info[3 + fullLabel.Length] = (byte)context.Length;
        context.CopyTo(info.AsSpan(4 + fullLabel.Length));

        var output = new byte[length];
        HKDF.Expand(hash, secret, output, info);
        return output;
    }

    /// <summary>
    /// TLS 1.2: derives both directions' keys from the master secret.
    ///
    /// Unlike 1.3, one secret covers the whole connection and the key block is split
    /// between the two directions. It also needs both randoms, in an order that is the
    /// reverse of the one in the handshake — server then client — which is a classic place
    /// to introduce a bug that silently decrypts nothing.
    /// </summary>
    public static TlsConnectionKeys FromMasterSecret(
        byte[] masterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        TlsCipherSuite suite)
    {
        var seed = new byte[clientRandom.Length + serverRandom.Length];
        serverRandom.CopyTo(seed);
        clientRandom.CopyTo(seed.AsSpan(serverRandom.Length));

        // AEAD suites have no MAC keys, so the block is two keys followed by two nonces.
        var blockLength = 2 * suite.KeyLength + 2 * suite.FixedIvLength;
        var block = Prf(masterSecret, "key expansion", seed, blockLength, suite.HashName);

        var offset = 0;
        var clientKey = block.AsSpan(offset, suite.KeyLength).ToArray();
        offset += suite.KeyLength;
        var serverKey = block.AsSpan(offset, suite.KeyLength).ToArray();
        offset += suite.KeyLength;
        var clientIv = block.AsSpan(offset, suite.FixedIvLength).ToArray();
        offset += suite.FixedIvLength;
        var serverIv = block.AsSpan(offset, suite.FixedIvLength).ToArray();

        return new TlsConnectionKeys(
            new TlsDirectionKeys(clientKey, clientIv),
            new TlsDirectionKeys(serverKey, serverIv));
    }

    /// <summary>
    /// The TLS 1.2 PRF: P_hash as defined in RFC 5246, which is HMAC iterated over a
    /// chained seed until enough output exists.
    /// </summary>
    private static byte[] Prf(
        byte[] secret, string label, ReadOnlySpan<byte> seed, int length, HashAlgorithmName hash)
    {
        var labelAndSeed = new byte[label.Length + seed.Length];
        Encoding.ASCII.GetBytes(label).CopyTo(labelAndSeed, 0);
        seed.CopyTo(labelAndSeed.AsSpan(label.Length));

        var output = new byte[length];
        var written = 0;

        // A(0) is the seed itself; each round rehashes A to get the next one.
        var a = labelAndSeed;

        while (written < length)
        {
            a = Hmac(secret, a, hash);

            var input = new byte[a.Length + labelAndSeed.Length];
            a.CopyTo(input, 0);
            labelAndSeed.CopyTo(input, a.Length);

            var round = Hmac(secret, input, hash);
            var take = Math.Min(round.Length, length - written);
            round.AsSpan(0, take).CopyTo(output.AsSpan(written));
            written += take;
        }

        return output;
    }

    private static byte[] Hmac(byte[] key, byte[] data, HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA384
            ? HMACSHA384.HashData(key, data)
            : HMACSHA256.HashData(key, data);

    /// <summary>
    /// The nonce for one record.
    ///
    /// The sequence number is exclusive-ORed into the low eight bytes of the derived
    /// nonce, so every record under one key gets a distinct nonce without any of them
    /// being transmitted. Nothing in the record says which number it was — the decoder has
    /// to count records, which is why a single missing record makes everything after it
    /// undecryptable.
    /// </summary>
    public static byte[] Nonce(ReadOnlySpan<byte> iv, ulong sequenceNumber)
    {
        var nonce = iv.ToArray();

        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(counter, sequenceNumber);

        for (var i = 0; i < 8; i++)
        {
            nonce[nonce.Length - 8 + i] ^= counter[i];
        }

        return nonce;
    }
}

/// <summary>Key and nonce for one direction of a connection.</summary>
public sealed record TlsDirectionKeys(byte[] Key, byte[] Iv);

/// <summary>Both directions' keys, as TLS 1.2 derives them together.</summary>
public sealed record TlsConnectionKeys(TlsDirectionKeys Client, TlsDirectionKeys Server);
