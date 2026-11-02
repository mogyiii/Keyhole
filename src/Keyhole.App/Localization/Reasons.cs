using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Keyhole.Core.Ipc;

namespace Keyhole.App.Localization;

/// <summary>
/// Turns the codes the service reports into sentences in the user's language.
///
/// This is the half of the arrangement that lives in the interface. The service says what
/// is wrong — <c>not-elevated</c>, <c>recording-size-limit</c> — and nothing about how to
/// phrase it; everything phrased here can therefore exist in as many languages as the
/// resources do. Values the service supplies alongside a code, such as a folder path or a
/// megabyte count, are substituted in rather than being baked into a sentence upstream.
///
/// An unrecognised code falls back to the code itself. That is deliberate: a user seeing
/// "recording-no-npcap" has something to search for and report, where a blank or a
/// generic "unknown error" has nothing.
/// </summary>
public static class Reasons
{
    private static Loc L => Loc.Current;

    /// <summary>
    /// The sentence for one reason code, with any supplied values substituted in.
    /// </summary>
    public static string Describe(string? code, params object?[] values)
    {
        if (string.IsNullOrEmpty(code))
        {
            return "";
        }

        if (KeyFor(code) is not { } key)
        {
            return code;
        }

        var text = L[key];

        return values.Length == 0
            ? text
            : SafeFormat(text, values);
    }

    /// <summary>
    /// Formats without letting a mismatched placeholder take the window down.
    ///
    /// A resource whose braces do not match the arguments is a translation bug, and
    /// showing the unformatted sentence is a far better outcome than an exception on a
    /// refresh timer.
    /// </summary>
    private static string SafeFormat(string text, object?[] values)
    {
        try
        {
            return string.Format(CultureInfo.CurrentCulture, text, values);
        }
        catch (FormatException)
        {
            return text;
        }
    }

    private static string? KeyFor(string code) => code switch
    {
        ReasonCodes.NotElevated => "ReasonNotElevated",
        ReasonCodes.EtwUnavailable => "ReasonEtwUnavailable",
        ReasonCodes.FirewallUnreachable => "ReasonFirewallUnreachable",
        ReasonCodes.BlockNoExecutable => "ReasonBlockNoExecutable",
        ReasonCodes.BlockNoRule => "ReasonBlockNoRule",
        ReasonCodes.BlockRuleFailed => "ReasonBlockRuleFailed",

        ReasonCodes.GeoIpNoDatabase => "ReasonGeoIpNone",
        ReasonCodes.GeoIpNoCountryDatabase => "ReasonGeoIpNoCountry",
        ReasonCodes.GeoIpNoAsnDatabase => "ReasonGeoIpNoAsn",

        ReasonCodes.RecordingNoNpcap => "ReasonRecordingNoNpcap",
        ReasonCodes.RecordingNoAdapter => "ReasonRecordingNoAdapter",
        ReasonCodes.RecordingFileError => "ReasonRecordingFileError",
        ReasonCodes.RecordingSizeLimit => "ReasonRecordingSizeLimit",
        ReasonCodes.RecordingNoSecrets => "ReasonRecordingNoSecrets",
        ReasonCodes.RecordingSecretsNotEmbedded => "ReasonRecordingSecretsNotEmbedded",

        ReasonCodes.DecodeNoCapture => "ReasonDecodeNoCapture",
        ReasonCodes.DecodeFileMissing => "ReasonDecodeFileMissing",
        ReasonCodes.DecodeUnreadable => "ReasonDecodeUnreadable",
        ReasonCodes.DecodeTooManyConversations => "ReasonDecodeTooMany",
        ReasonCodes.DecodeFailed => "ReasonDecodeFailed",

        ReasonCodes.ExchangeNoResponse => "ReasonExchangeNoResponse",
        ReasonCodes.ExchangeResponseTruncated => "ReasonExchangeResponseTruncated",
        ReasonCodes.ExchangeBodyTruncated => "ReasonExchangeBodyTruncated",
        ReasonCodes.ExchangeHeadersBroken => "ReasonExchangeHeadersBroken",

        ReasonCodes.CaptureNoExecutable => "ReasonCaptureNoExecutable",
        ReasonCodes.CaptureLaunchFailed => "ReasonCaptureLaunchFailed",

        _ => null,
    };

    /// <summary>
    /// What to say about packet capture, from Npcap's state alone.
    ///
    /// The four states are exactly the four different pieces of advice, which is why the
    /// service sends no separate sentence: install it, start the driver, reinstall it, or
    /// nothing at all.
    /// </summary>
    public static string? DescribeNpcap(string? state) => state switch
    {
        "missing" => L["NpcapMissing"],
        "stopped" => L["NpcapStopped"],
        "unusable" => L["NpcapUnusable"],
        _ => null,
    };

    /// <summary>
    /// The one line covering whatever elevation makes unavailable.
    ///
    /// Byte counting and blocking fail for the same reason, so two separate strips would
    /// say the same thing twice while costing the list a third of its height. When the
    /// causes differ, both sentences are shown in full rather than summarised into
    /// something that fits neither.
    /// </summary>
    public static string? DescribeCapabilities(string? byteCounting, string? blocking)
    {
        if (byteCounting is null && blocking is null)
        {
            return null;
        }

        var bothNeedElevation =
            (byteCounting is null || byteCounting == ReasonCodes.NotElevated) &&
            (blocking is null || blocking == ReasonCodes.NotElevated);

        if (!bothNeedElevation)
        {
            return string.Join(
                " ",
                new[] { Describe(byteCounting), Describe(blocking) }
                    .Where(s => s.Length > 0));
        }

        var missing = new List<string>(2);

        if (byteCounting is not null)
        {
            missing.Add(L["CapabilityByteCounting"]);
        }

        if (blocking is not null)
        {
            missing.Add(L["CapabilityBlocking"]);
        }

        return SafeFormat(
            L["CapabilityNotElevated"],
            [string.Join(L["CapabilityAnd"], missing)]);
    }
}
