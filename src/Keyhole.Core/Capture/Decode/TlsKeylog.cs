namespace Keyhole.Core.Capture.Decode;

/// <summary>
/// The TLS secrets a captured application wrote, indexed the way a decoder needs them.
///
/// The format is NSS's key log: one secret per line, each naming a label, the connection's
/// client random, and the secret itself in hex. The client random is the join — it appears
/// in the ClientHello on the wire, so a connection in the capture can be matched to its
/// keys without any other state.
///
/// <code>
/// CLIENT_HANDSHAKE_TRAFFIC_SECRET &lt;client_random&gt; &lt;secret&gt;
/// SERVER_TRAFFIC_SECRET_0 &lt;client_random&gt; &lt;secret&gt;
/// CLIENT_RANDOM &lt;client_random&gt; &lt;master_secret&gt;
/// </code>
///
/// The last of those is the TLS 1.2 form, where one master secret covers the connection
/// and the per-direction keys are derived from it. The others are TLS 1.3, where each
/// direction and each phase has its own secret.
/// </summary>
public sealed class TlsKeylog
{
    /// <summary>
    /// Secrets by client random, then by label. Both are case-folded: the labels are
    /// written upper-case and the randoms lower-case by convention, but nothing enforces
    /// it and a mismatch would silently fail to decrypt.
    /// </summary>
    private readonly Dictionary<string, Dictionary<string, byte[]>> _secrets =
        new(StringComparer.OrdinalIgnoreCase);

    public int ConnectionCount => _secrets.Count;

    /// <summary>Labels for the secrets Keyhole uses.</summary>
    public const string ClientHandshakeTrafficSecret = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
    public const string ServerHandshakeTrafficSecret = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    public const string ClientTrafficSecret0 = "CLIENT_TRAFFIC_SECRET_0";
    public const string ServerTrafficSecret0 = "SERVER_TRAFFIC_SECRET_0";

    /// <summary>The TLS 1.2 form: a master secret rather than per-direction secrets.</summary>
    public const string ClientRandom = "CLIENT_RANDOM";

    public static TlsKeylog Parse(string? contents)
    {
        var keylog = new TlsKeylog();

        if (string.IsNullOrWhiteSpace(contents))
        {
            return keylog;
        }

        foreach (var line in contents.Split('\n'))
        {
            var trimmed = line.Trim();

            // Comments and blanks. NSS writes a header comment, and a keylog appended to
            // across several runs can have several.
            if (trimmed.Length == 0 || trimmed[0] == '#')
            {
                continue;
            }

            var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3)
            {
                continue;
            }

            var label = parts[0];
            var clientRandom = parts[1];
            var secret = FromHex(parts[2]);

            if (secret is null || clientRandom.Length == 0)
            {
                continue;
            }

            if (!keylog._secrets.TryGetValue(clientRandom, out var byLabel))
            {
                byLabel = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                keylog._secrets[clientRandom] = byLabel;
            }

            // First write wins. A keylog can hold two entries for one label if the
            // application re-handshaked onto the same client random, which does not
            // happen in practice; taking the first is the stable choice either way.
            byLabel.TryAdd(label, secret);
        }

        return keylog;
    }

    /// <summary>
    /// The secret for one connection and label, or null when the capture holds none.
    ///
    /// A null here is the normal outcome for an application on Windows' own TLS stack: it
    /// never wrote a keylog, so its connections appear in the capture as encrypted bytes
    /// with no way in. That is a fact to report, not an error.
    /// </summary>
    public byte[]? Find(ReadOnlySpan<byte> clientRandom, string label) =>
        Find(Convert.ToHexStringLower(clientRandom), label);

    public byte[]? Find(string clientRandom, string label) =>
        _secrets.TryGetValue(clientRandom, out var byLabel) &&
        byLabel.TryGetValue(label, out var secret)
            ? secret
            : null;

    /// <summary>Whether any secret at all is known for this connection.</summary>
    public bool Knows(ReadOnlySpan<byte> clientRandom) =>
        _secrets.ContainsKey(Convert.ToHexStringLower(clientRandom));

    private static byte[]? FromHex(string hex)
    {
        if (hex.Length == 0 || hex.Length % 2 != 0)
        {
            return null;
        }

        try
        {
            return Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
