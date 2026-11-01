using System.Security.Cryptography;

namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// The cipher suites Keyhole can decrypt, and the parameters each one implies.
///
/// A suite number fixes everything the decoder needs: which hash drives key derivation,
/// how long the key and nonce are, and which AEAD opens the records. None of it can be
/// guessed — a wrong hash or key length produces plausible-looking garbage rather than an
/// error, so an unknown suite has to be refused outright.
///
/// Only AEAD suites are here. The older CBC-with-HMAC suites would need a different record
/// layout and are long gone from anything that negotiates TLS with a browser; a capture
/// using one is reported as undecryptable rather than decoded wrongly.
/// </summary>
/// <param name="Name">The suite's registered name, for reporting.</param>
/// <param name="Hash">The hash used for key derivation and, in TLS 1.2, the PRF.</param>
/// <param name="KeyLength">Bytes of key material.</param>
/// <param name="FixedIvLength">
/// Bytes of nonce taken from the key schedule. In TLS 1.3 and in ChaCha20 suites this is
/// the whole 12-byte nonce; in TLS 1.2's GCM suites it is a 4-byte salt that the record's
/// own explicit nonce completes.
/// </param>
/// <param name="Aead">Which AEAD construction opens a record.</param>
public sealed record TlsCipherSuite(
    string Name,
    TlsHash Hash,
    int KeyLength,
    int FixedIvLength,
    TlsAead Aead)
{
    /// <summary>Bytes of authentication tag at the end of every record. 16 for all of these.</summary>
    public int TagLength => 16;

    /// <summary>
    /// Bytes of per-record nonce carried in the record itself.
    ///
    /// Only TLS 1.2's GCM suites have one: they build a nonce from a 4-byte salt plus 8
    /// bytes sent in the clear. TLS 1.3 and the ChaCha20 suites derive the whole nonce
    /// from the sequence number instead, so nothing is transmitted.
    /// </summary>
    public int ExplicitNonceLength => 12 - FixedIvLength;

    /// <summary>
    /// The suite for a number from a ServerHello, or null when Keyhole cannot decrypt it.
    /// </summary>
    public static TlsCipherSuite? Find(ushort value) => value switch
    {
        // TLS 1.3. These three are what browsers actually negotiate.
        0x1301 => new("TLS_AES_128_GCM_SHA256", TlsHash.Sha256, 16, 12, TlsAead.AesGcm),
        0x1302 => new("TLS_AES_256_GCM_SHA384", TlsHash.Sha384, 32, 12, TlsAead.AesGcm),
        0x1303 => new("TLS_CHACHA20_POLY1305_SHA256", TlsHash.Sha256, 32, 12, TlsAead.ChaCha20Poly1305),
        0x1304 => new("TLS_AES_128_CCM_SHA256", TlsHash.Sha256, 16, 12, TlsAead.AesCcm),

        // TLS 1.2 with AEAD. The GCM suites take a 4-byte salt and an 8-byte explicit
        // nonce; the ChaCha20 ones use the TLS 1.3 nonce construction (RFC 7905).
        0xC02B => new("ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", TlsHash.Sha256, 16, 4, TlsAead.AesGcm),
        0xC02C => new("ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", TlsHash.Sha384, 32, 4, TlsAead.AesGcm),
        0xC02F => new("ECDHE_RSA_WITH_AES_128_GCM_SHA256", TlsHash.Sha256, 16, 4, TlsAead.AesGcm),
        0xC030 => new("ECDHE_RSA_WITH_AES_256_GCM_SHA384", TlsHash.Sha384, 32, 4, TlsAead.AesGcm),
        0x009C => new("RSA_WITH_AES_128_GCM_SHA256", TlsHash.Sha256, 16, 4, TlsAead.AesGcm),
        0x009D => new("RSA_WITH_AES_256_GCM_SHA384", TlsHash.Sha384, 32, 4, TlsAead.AesGcm),
        0xCCA8 => new("ECDHE_RSA_WITH_CHACHA20_POLY1305", TlsHash.Sha256, 32, 12, TlsAead.ChaCha20Poly1305),
        0xCCA9 => new("ECDHE_ECDSA_WITH_CHACHA20_POLY1305", TlsHash.Sha256, 32, 12, TlsAead.ChaCha20Poly1305),

        _ => null,
    };

    public HashAlgorithmName HashName => Hash switch
    {
        TlsHash.Sha384 => HashAlgorithmName.SHA384,
        _ => HashAlgorithmName.SHA256,
    };

    public int HashLength => Hash == TlsHash.Sha384 ? 48 : 32;

    /// <summary>
    /// Opens one record.
    /// </summary>
    /// <returns>
    /// The plaintext, or null when the tag does not verify — which means the key, nonce or
    /// associated data was wrong, and is how the decoder knows to stop rather than emit
    /// nonsense.
    /// </returns>
    public byte[]? Open(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertextWithTag,
        ReadOnlySpan<byte> associatedData)
    {
        if (ciphertextWithTag.Length < TagLength)
        {
            return null;
        }

        var ciphertext = ciphertextWithTag[..^TagLength];
        var tag = ciphertextWithTag[^TagLength..];
        var plaintext = new byte[ciphertext.Length];

        try
        {
            switch (Aead)
            {
                case TlsAead.AesGcm:
                {
                    using var aes = new AesGcm(key, TagLength);
                    aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                    break;
                }

                case TlsAead.ChaCha20Poly1305:
                {
                    using var chacha = new ChaCha20Poly1305(key);
                    chacha.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                    break;
                }

                case TlsAead.AesCcm:
                {
                    using var ccm = new AesCcm(key);
                    ccm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                    break;
                }

                default:
                    return null;
            }

            return plaintext;
        }
        catch (AuthenticationTagMismatchException)
        {
            // The expected failure, and a load-bearing one: it is what distinguishes
            // "wrong key" from "decrypted successfully", and the decoder relies on it to
            // detect the switch from handshake keys to application keys.
            return null;
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            // A key or nonce of the wrong length for this AEAD. Means the suite table and
            // the key schedule disagree, which is a bug — but one that must not take a
            // decode pass down.
            return null;
        }
    }
}

public enum TlsHash
{
    Sha256,
    Sha384,
}

public enum TlsAead
{
    AesGcm,
    ChaCha20Poly1305,
    AesCcm,
}
