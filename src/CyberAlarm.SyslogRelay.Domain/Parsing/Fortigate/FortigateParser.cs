using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Fortigate;

internal sealed class FortigateParser : IParser
{
    public string Name => nameof(FortigateParser);

    public Result<ParseResult> Parse(string log)
    {
        ArgumentException.ThrowIfNullOrEmpty(log);

        var keyValues = log.ParseKeyValues();
        if (keyValues is null)
        {
            return new FormatError();
        }

        if (!keyValues.TryGetValue("srcip", out var sourceIp) ||
            !keyValues.TryGetValue("dstip", out var destinationIp) ||
            !keyValues.TryGetValue("srcport", out var sourcePortValue) ||
            !keyValues.TryGetValue("dstport", out var destinationPortValue) ||
            !keyValues.TryGetValue("proto", out var protocolValue) ||
            !keyValues.TryGetValue("action", out var actionValue))
        {
            return new UnparsableEventError();
        }

        var sourcePort = int.TryParse(sourcePortValue, out var port) ? port : (int?)null;
        var destinationPort = int.TryParse(destinationPortValue, out port) ? port : (int?)null;
        var protocol = protocolValue.ToProtocol();
        var action = ToAction(actionValue);

        return new ParseResult(
            sourceIp,
            destinationIp,
            sourcePort,
            destinationPort,
            protocol,
            action);
    }

    private static EventAction ToAction(string value) =>
        value.ToLower() switch
        {
            "accept" => EventAction.Allow,
            "close" => EventAction.Allow,
            "server-rst" => EventAction.Allow,
            "client-rst" => EventAction.Allow,
            "timeout" => EventAction.Allow,
            "deny" => EventAction.Deny,
            _ => EventAction.Unknown,
        };
}
