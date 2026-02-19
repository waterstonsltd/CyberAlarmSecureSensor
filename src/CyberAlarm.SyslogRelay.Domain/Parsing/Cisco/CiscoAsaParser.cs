using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;
using static CyberAlarm.SyslogRelay.Domain.Parsing.Cisco.CiscoAsaRegexes;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

internal sealed class CiscoAsaParser : IParser
{
    public string Name => nameof(CiscoAsaParser);

    public Result<ParsedFirewallEvent> Parse(string log)
    {
        ArgumentNullException.ThrowIfNull(log);

        var match = MainPattern().Match(log);
        if (!match.Success)
        {
            return new FormatError();
        }

        var messageId = ExtractMessageId(match);
        var content = ExtractMessageContent(match);

        var parsedEvent = ParseContent(messageId, content);
        if (parsedEvent is null)
        {
            return new UnparsableEventError([
                new(nameof(messageId), messageId),
                new(nameof(content), content)]);
        }

        return parsedEvent;
    }

    private static int ExtractMessageId(Match match) =>
        int.Parse(match.Groups["message_id"].Value);

    private static string ExtractMessageContent(Match match) =>
        match.Groups["message_content"].Value.Trim();

    private static ParsedFirewallEvent? ParseContent(int messageId, string content)
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

        var sourceIp = match.SourceIp();
        var destinationIp = parsingInfo.SkipDestinationIp ? null : match.DestinationIp();
        var sourcePort = parsingInfo.SkipSourcePort ? (int?)null : match.SourcePort();
        var destinationPort = parsingInfo.SkipDestinationPort ? (int?)null : match.DestinationPort();

        var protocol = EventProtocol.Unknown;
        if (parsingInfo.HasProtocolNumber)
        {
            protocol = match.ProtocolNumber();
        }
        else if (!parsingInfo.SkipProtocol)
        {
            protocol = parsingInfo.Protocol ?? match.Protocol();
        }

        var action = parsingInfo.Action ?? match.Action();

        return new(sourceIp, destinationIp, sourcePort, destinationPort, protocol, action);
    }

    private static ContentParsingInfo? GetContentParsingInfo(int messageId) =>
        messageId switch
        {
            106001 => new() { Regex = Regex_106001(), Action = EventAction.Deny },
            106006 => new() { Regex = Regex_106006(), Action = EventAction.Deny },
            106007 => new() { Regex = Regex_106007(), Action = EventAction.Deny },
            106014 => new() { Regex = Regex_106014(), SkipSourcePort = true, SkipDestinationPort = true, Action = EventAction.Deny },
            106015 => new() { Regex = Regex_106015(), Action = EventAction.Deny },
            106018 => new() { Regex = Regex_106018(), SkipSourcePort = true, SkipDestinationPort = true, Action = EventAction.Deny },
            106020 => new() { Regex = Regex_106020(), SkipSourcePort = true, SkipDestinationPort = true, Action = EventAction.Deny },
            106021 => new() { Regex = Regex_106021(), SkipSourcePort = true, SkipDestinationPort = true, HasProtocolNumber = true, Action = EventAction.Deny },
            106023 => new() { Regex = Regex_106023(), Action = EventAction.Deny },
            106100 => new() { Regex = Regex_106100() },
            302013 => new() { Regex = Regex_302013(), Action = EventAction.Allow },
            302014 or 303002 => new() { Regex = Regex_302014_303002(), Action = EventAction.Allow },
            302015 => new() { Regex = Regex_302015(), Action = EventAction.Allow },
            302016 => new() { Regex = Regex_302016(), Action = EventAction.Allow },
            313001 => new() { Regex = Regex_313001(), SkipSourcePort = true, SkipDestinationPort = true, Action = EventAction.Deny },
            >= 400000 and <= 400050 => new() { Regex = Regex_400000_400050(), Protocol = EventProtocol.Tcp, Action = EventAction.Deny },
            419001 => new() { Regex = Regex_419001(), Protocol = EventProtocol.Tcp, Action = EventAction.Deny },
            419002 => new() { Regex = Regex_419002(), Action = EventAction.Deny },
            733101 => new() { Regex = Regex_733101(), SkipDestinationIp = true, SkipSourcePort = true, SkipDestinationPort = true, SkipProtocol = true, Action = EventAction.Unknown },
            733102 => new() { Regex = Regex_733102(), SkipDestinationIp = true, SkipSourcePort = true, SkipDestinationPort = true, SkipProtocol = true, Action = EventAction.Unknown },
            733201 => new() { Regex = Regex_733201(), SkipDestinationIp = true, SkipSourcePort = true, SkipDestinationPort = true, SkipProtocol = true, Action = EventAction.Unknown },
            _ => null,
        };
}
