using System.Buffers.Binary;

namespace Keyhole.Core.Capture.Pcapng;

/// <summary>
/// Rewrites a pcapng file with the session's TLS secrets placed ahead of its packets.
///
/// The secrets cannot be written while capturing, because they do not exist yet: the
/// target process writes its keylog as it negotiates connections. But a reader wants the
/// Decryption Secrets Block <em>before</em> the packets it unlocks — it applies secrets as
/// it walks the file, so a block at the end arrives after every decision it could have
/// informed.
///
/// So the file is written packets-first and fixed up once, at the end of the session: copy
/// the header blocks, insert the secrets, copy the rest. One sequential pass, and the
/// original is replaced only after the new file is complete — a failure here leaves the
/// capture intact and merely undecrypted.
/// </summary>
public static class PcapngSecretsInjector
{
    /// <summary>
    /// Inserts <paramref name="keylogContents"/> into <paramref name="pcapngPath"/> in place.
    /// </summary>
    /// <returns>
    /// What happened, as something the UI can report. Doing nothing is a normal outcome:
    /// a session whose application wrote no secrets has nothing to inject.
    /// </returns>
    public static InjectionResult Inject(string pcapngPath, string keylogContents)
    {
        if (string.IsNullOrWhiteSpace(keylogContents))
        {
            return InjectionResult.NothingToDo(
                "The application wrote no TLS secrets.",
                Ipc.ReasonCodes.RecordingNoSecrets);
        }

        if (!File.Exists(pcapngPath))
        {
            return InjectionResult.NothingToDo(
                "No packets were recorded.", Ipc.ReasonCodes.DecodeNoCapture);
        }

        var temporary = pcapngPath + ".rewriting";

        try
        {
            using (var source = new FileStream(
                       pcapngPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024))
            using (var destination = new FileStream(
                       temporary, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024))
            {
                if (!CopyWithSecrets(source, destination, keylogContents))
                {
                    destination.Dispose();
                    Delete(temporary);

                    return InjectionResult.Failed(
                        "The capture file's structure could not be read, so the TLS secrets " +
                        "were left in the keylog beside it.");
                }
            }

            File.Move(temporary, pcapngPath, overwrite: true);

            return InjectionResult.Injected();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Delete(temporary);

            return InjectionResult.Failed(
                $"The TLS secrets could not be written into the capture ({ex.Message}); " +
                "the keylog beside it still has them.");
        }
    }

    /// <summary>
    /// Copies blocks across, emitting the secrets block at the first packet.
    /// Returns false when the input does not parse as pcapng, in which case the caller
    /// must keep the original rather than replace it with a partial copy.
    /// </summary>
    private static bool CopyWithSecrets(Stream source, Stream destination, string keylogContents)
    {
        var header = new byte[8];
        var injected = false;
        var sawSectionHeader = false;

        while (true)
        {
            var read = source.ReadAtLeast(header, 8, throwOnEndOfStream: false);
            if (read == 0)
            {
                break;
            }

            if (read < 8)
            {
                // A trailing fragment means the capture was cut off mid-block. Everything
                // before it is still good, so stop cleanly rather than fail the rewrite.
                break;
            }

            var blockType = BinaryPrimitives.ReadUInt32LittleEndian(header);
            var totalLength = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4));

            if (blockType == PcapngBlocks.BlockSectionHeader)
            {
                sawSectionHeader = true;
            }
            else if (!sawSectionHeader)
            {
                // A pcapng file opens with a section header. Anything else means this is
                // not the format we think it is.
                return false;
            }

            // A block is at least its own frame, and lengths are always aligned.
            if (totalLength < PcapngBlocks.FrameBytes ||
                totalLength % PcapngBlocks.Alignment != 0 ||
                totalLength > int.MaxValue)
            {
                return false;
            }

            // Anything that is not section or interface metadata begins the payload, which
            // is the point by which the secrets must already be in the file.
            var isLeadingMetadata = blockType
                is PcapngBlocks.BlockSectionHeader
                or PcapngBlocks.BlockInterfaceDescription;

            if (!injected && !isLeadingMetadata)
            {
                PcapngBlocks.WriteTlsSecrets(destination, keylogContents);
                injected = true;
            }

            destination.Write(header);

            var remaining = (int)totalLength - 8;
            if (!Copy(source, destination, remaining))
            {
                break;
            }
        }

        // A capture with no packets at all still deserves its secrets.
        if (!injected)
        {
            AppendSecrets(destination, keylogContents);
        }

        return true;
    }

    private static void AppendSecrets(Stream destination, string keylogContents) =>
        PcapngBlocks.WriteTlsSecrets(destination, keylogContents);

    /// <summary>Streams <paramref name="count"/> bytes across. False if the input ran out.</summary>
    private static bool Copy(Stream source, Stream destination, int count)
    {
        var buffer = new byte[Math.Min(count, 64 * 1024)];
        var left = count;

        while (left > 0)
        {
            var read = source.Read(buffer, 0, Math.Min(left, buffer.Length));
            if (read == 0)
            {
                return false;
            }

            destination.Write(buffer, 0, read);
            left -= read;
        }

        return true;
    }

    private static void Delete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The rewrite already failed; a leftover temp file is the lesser problem.
        }
    }
}

/// <summary>Outcome of placing TLS secrets into a capture file.</summary>
/// <param name="Succeeded">Whether the capture now carries its own secrets.</param>
/// <param name="Detail">
/// Null when it worked and there is nothing to say; otherwise a sentence explaining what
/// the user will have to do by hand instead.
/// </param>
/// <param name="DetailCode">
/// The same answer as a code the UI can translate, from <see cref="Ipc.ReasonCodes"/>.
/// The sentence above is for the log.
/// </param>
public sealed record InjectionResult(bool Succeeded, string? Detail, string? DetailCode = null)
{
    public static InjectionResult Injected() => new(true, null);

    public static InjectionResult NothingToDo(string detail, string code) =>
        new(false, detail, code);

    public static InjectionResult Failed(string detail) =>
        new(false, detail, Ipc.ReasonCodes.RecordingSecretsNotEmbedded);
}
