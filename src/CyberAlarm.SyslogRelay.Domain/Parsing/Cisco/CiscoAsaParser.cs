using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;
using static CyberAlarm.SyslogRelay.Domain.Parsing.Cisco.CiscoAsaRegexes;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

internal sealed class CiscoAsaParser : IParser
{
    public Result Initialise(object? config) => Result.Ok();

    public Result<ParseResult> Parse(string log)
    {
        ArgumentException.ThrowIfNullOrEmpty(log);

        var match = MainPattern().Match(log);
        if (!match.Success)
        {
            return new FormatError();
        }

        var messageId = ExtractMessageId(match);
        var content = ExtractMessageContent(match);

        var result = ParseContent(messageId, content);
        if (result is null)
        {
            return new UnparsableEventError([
                new(nameof(messageId), messageId),
                new(nameof(content), content)]);
        }

        return result;
    }

    private static int ExtractMessageId(Match match) =>
        int.Parse(match.Groups["message_id"].ValueSpan);

    private static string ExtractMessageContent(Match match) =>
        match.Groups["message_content"].Value.Trim();

    private static string? ExtractOptional(Match match, string groupKey) =>
        match.Groups[groupKey].Success ? match.Groups[groupKey].Value : null;

    private static ParseResult? ParseContent(int messageId, string content)
    {
        var parsingInfo = GetContentParsingInfo(messageId);
        if (parsingInfo is null)
        {
            return null;
        }

        var match = parsingInfo.Regex.Match(content);
        if (!match.Success)
        {
            return null;
        }

        var sourceIp = match.From("src_ip");
        var destinationIp = parsingInfo.SkipDestinationIp ? null : ExtractOptional(match, "dst_ip");
        var sourcePort = parsingInfo.SkipSourcePort ? (int?)null : match.NumberFrom("src_port");
        var destinationPort = parsingInfo.SkipDestinationPort ? (int?)null : match.NumberFrom("dst_port");

        if (ShouldSwapBuiltOutboundConnection(messageId, match))
        {
            (sourceIp, destinationIp) = (destinationIp!, sourceIp);
            (sourcePort, destinationPort) = (destinationPort, sourcePort);
        }

        if (ShouldSwapTeardownConnection(messageId, match, sourcePort, destinationPort))
        {
            (sourceIp, destinationIp) = (destinationIp!, sourceIp);
            (sourcePort, destinationPort) = (destinationPort, sourcePort);
        }

        var protocol = EventProtocol.Unknown;
        if (parsingInfo.HasProtocolNumber || match.Groups["protocol_num"].Success)
        {
            protocol = match.From("protocol_num").ToProtocol();
        }
        else if (!parsingInfo.SkipProtocol)
        {
            protocol = parsingInfo.Protocol ?? match.From("protocol").ToProtocol();
        }

        var duration = ExtractDuration(messageId, content);
        var bytes = ExtractBytes(messageId, content);
        var action = ResolveAction(messageId, parsingInfo, match, content);

        return new(sourceIp, destinationIp, sourcePort, destinationPort, protocol, action, duration, bytes);
    }

    private static bool ShouldSwapBuiltOutboundConnection(int messageId, Match match) =>
        (messageId == 302013 || messageId == 302015)
        && match.Groups["direction"].Success
        && match.Groups["direction"].ValueSpan.Equals("out", StringComparison.OrdinalIgnoreCase);

    private static bool ShouldSwapTeardownConnection(int messageId, Match match, int? sourcePort, int? destinationPort) =>
        messageId is 302014 or 302016 or 303002
        && match.Groups["first_iface"].Success
        && match.Groups["first_iface"].ValueSpan.Equals("outside", StringComparison.OrdinalIgnoreCase)
        && sourcePort < destinationPort;

    private static EventAction ResolveAction(int messageId, ContentParsingInfo parsingInfo, Match match, string content)
    {
        if (messageId is 302014 or 302016 or 302021 or 303002)
        {
            return GetTeardownAction(messageId, content);
        }

        return parsingInfo.Action ?? ToAction(match.From("action"));
    }

    private static EventAction GetTeardownAction(int messageId, string content)
    {
        if (messageId is 302016 or 302021)
        {
            return EventAction.Timeout;
        }

        if (content.Contains("TCP FIN", StringComparison.OrdinalIgnoreCase))
        {
            return EventAction.Close;
        }

        if (content.Contains("Reset", StringComparison.OrdinalIgnoreCase)
            || content.Contains("segment out of order", StringComparison.OrdinalIgnoreCase)
            || content.Contains("Invalid SYN", StringComparison.OrdinalIgnoreCase))
        {
            return EventAction.Reset;
        }

        if (content.Contains("SYN Limit", StringComparison.OrdinalIgnoreCase)
            || content.Contains("Deny", StringComparison.OrdinalIgnoreCase))
        {
            return EventAction.Drop;
        }

        if (content.Contains("timeout", StringComparison.OrdinalIgnoreCase)
            || content.Contains("No data", StringComparison.OrdinalIgnoreCase))
        {
            return EventAction.Timeout;
        }

        return EventAction.Close;
    }

    private static TimeSpan? ExtractDuration(int messageId, string content)
    {
        if (messageId is not (302014 or 302016 or 302021 or 303002))
        {
            return null;
        }

        var durationStart = content.IndexOf(" duration ", StringComparison.OrdinalIgnoreCase);
        if (durationStart < 0)
        {
            return null;
        }

        durationStart += " duration ".Length;
        var durationEnd = content.IndexOf(' ', durationStart);
        if (durationEnd < 0)
        {
            durationEnd = content.Length;
        }

        return content[durationStart..durationEnd].ToDuration();
    }

    private static long? ExtractBytes(int messageId, string content)
    {
        if (messageId is not (302014 or 302016 or 302021 or 303002))
        {
            return null;
        }

        var bytesStart = content.IndexOf(" bytes ", StringComparison.OrdinalIgnoreCase);
        if (bytesStart < 0)
        {
            return null;
        }

        bytesStart += " bytes ".Length;
        var bytesEnd = content.IndexOf(' ', bytesStart);
        if (bytesEnd < 0)
        {
            bytesEnd = content.Length;
        }

        return content[bytesStart..bytesEnd].ToLong();
    }

    private static ContentParsingInfo? GetContentParsingInfo(int messageId) =>
        messageId switch
        {
            106001 => new() { Regex = Regex_106001(), Action = EventAction.Deny },
            106006 => new() { Regex = Regex_106006(), Action = EventAction.Deny },
            106007 => new() { Regex = Regex_106007(), Action = EventAction.Deny },
            106014 => new() { Regex = Regex_106014(), SkipSourcePort = true, SkipDestinationPort = true, Action = EventAction.Deny },
            106015 => new() { Regex = Regex_106015(), Action = EventAction.Deny },
            106016 => new() { Regex = Regex_106016(), SkipSourcePort = true, SkipDestinationPort = true, SkipProtocol = true, Action = EventAction.Drop },
            106017 => new() { Regex = Regex_106017(), SkipSourcePort = true, SkipDestinationPort = true, SkipProtocol = true, Action = EventAction.Drop },
            106018 => new() { Regex = Regex_106018(), SkipSourcePort = true, SkipDestinationPort = true, Action = EventAction.Deny },
            106020 => new() { Regex = Regex_106020(), SkipSourcePort = true, SkipDestinationPort = true, Protocol = EventProtocol.Tcp, Action = EventAction.Deny },
            106021 => new() { Regex = Regex_106021(), SkipSourcePort = true, SkipDestinationPort = true, HasProtocolNumber = true, Action = EventAction.Deny },
            106023 => new() { Regex = Regex_106023(), Action = EventAction.Deny },
            106100 => new() { Regex = Regex_106100() },
            302013 => new() { Regex = Regex_302013(), Action = EventAction.Allow },
            302014 or 303002 => new() { Regex = Regex_302014_303002() },
            302015 => new() { Regex = Regex_302015(), Action = EventAction.Allow },
            302016 => new() { Regex = Regex_302016() },
            302020 => new() { Regex = Regex_302020_302021(), Protocol = EventProtocol.Icmp, Action = EventAction.Allow, SkipSourcePort = true, SkipDestinationPort = true },
            302021 => new() { Regex = Regex_302020_302021(), Protocol = EventProtocol.Icmp, SkipSourcePort = true, SkipDestinationPort = true },
            313001 => new() { Regex = Regex_313001(), SkipSourcePort = true, SkipDestinationPort = true, Protocol = EventProtocol.Icmp, Action = EventAction.Deny },
            313004 => new() { Regex = Regex_313004(), SkipSourcePort = true, SkipDestinationPort = true, Protocol = EventProtocol.Icmp, Action = EventAction.Deny },
            >= 400000 and <= 400050 => new() { Regex = Regex_400000_400050(), Protocol = EventProtocol.Tcp, Action = EventAction.Deny },
            419001 => new() { Regex = Regex_419001(), Protocol = EventProtocol.Tcp, Action = EventAction.Drop },
            419002 => new() { Regex = Regex_419002(), Action = EventAction.Drop },
            710001 or 710003 => new() { Regex = Regex_710001_710003(), Action = EventAction.Deny },
            710002 => new() { Regex = Regex_710002(), Protocol = EventProtocol.Tcp, Action = EventAction.Allow },
            710005 => new() { Regex = Regex_710005(), Action = EventAction.Drop },
            733101 => new() { Regex = Regex_733101(), SkipDestinationIp = true, SkipSourcePort = true, SkipDestinationPort = true, SkipProtocol = true, Action = EventAction.Unknown },
            733102 => new() { Regex = Regex_733102(), SkipDestinationIp = true, SkipSourcePort = true, SkipDestinationPort = true, SkipProtocol = true, Action = EventAction.Unknown },
            733201 => new() { Regex = Regex_733201(), SkipDestinationIp = true, SkipSourcePort = true, SkipDestinationPort = true, SkipProtocol = true, Action = EventAction.Unknown },
            _ => null,
        };

    private static EventAction ToAction(string value) =>
        value.ToLower() switch
        {
            "permitted" => EventAction.Allow,
            "denied" => EventAction.Deny,
            _ => EventAction.Unknown,
        };
}
