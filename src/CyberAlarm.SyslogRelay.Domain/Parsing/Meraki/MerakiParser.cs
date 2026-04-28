using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.Meraki;

internal sealed partial class MerakiParser : IParser
{
    private static readonly HashSet<string> SupportedEventTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "ip_flow_start",
        "ip_flow_end",
        "flows",
        "firewall",
        "vpn_firewall",
        "cellular_firewall",
        "bridge_anyconnect_client_vpn_firewall",
    };

    public Result Initialise(object? config) => Result.Ok();

    public Result<ParseResult> Parse(string log)
    {
        ArgumentException.ThrowIfNullOrEmpty(log);

        var match = LogPattern().Match(log);
        if (!match.Success)
        {
            return new FormatError();
        }

        var eventType = match.Groups["event_type"].Value;
        if (!SupportedEventTypes.Contains(eventType))
        {
            return new UnparsableEventError([
                new(nameof(eventType), eventType),
            ]);
        }

        var content = match.Groups["content"].Value;
        var (keyValues, patternValue) = ParseContent(content);
        if (keyValues.Count == 0)
        {
            return new FormatError();
        }

        if (!keyValues.TryGetValue("src", out var sourceIp)
            || !keyValues.TryGetValue("dst", out var destinationIp)
            || !keyValues.TryGetValue("protocol", out var protocolValue))
        {
            return new UnparsableEventError([
                new(nameof(eventType), eventType),
                new(nameof(content), content),
            ]);
        }

        keyValues.TryGetValue("sport", out var sourcePortValue);
        keyValues.TryGetValue("dport", out var destinationPortValue);

        return new ParseResult(
            sourceIp,
            destinationIp,
            sourcePortValue.ToPort(),
            destinationPortValue.ToPort(),
            protocolValue.ToProtocol(),
            ResolveAction(eventType, patternValue));
    }

    private static (Dictionary<string, string> KeyValues, string? PatternValue) ParseContent(string content)
    {
        var patternIndex = content.IndexOf(" pattern:", StringComparison.OrdinalIgnoreCase);
        var keyValueSection = patternIndex >= 0 ? content[..patternIndex] : content;
        var patternValue = patternIndex >= 0
            ? content[(patternIndex + " pattern:".Length)..].Trim()
            : null;

        var keyValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var token in keyValueSection.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separatorIndex = token.IndexOf('=');
            if (separatorIndex <= 0 || separatorIndex == token.Length - 1)
            {
                continue;
            }

            var key = token[..separatorIndex];
            var value = token[(separatorIndex + 1)..];
            keyValues[key] = value;
        }

        return (keyValues, patternValue);
    }

    private static EventAction ResolveAction(string eventType, string? patternValue)
    {
        var actionToken = GetActionToken(patternValue);
        if (actionToken is not null)
        {
            return actionToken.ToLowerInvariant() switch
            {
                "0" or "allow" => EventAction.Allow,
                "1" or "deny" => EventAction.Deny,
                _ => EventAction.Unknown,
            };
        }

        return eventType.Equals("ip_flow_start", StringComparison.OrdinalIgnoreCase)
            || eventType.Equals("ip_flow_end", StringComparison.OrdinalIgnoreCase)
            ? EventAction.Allow
            : EventAction.Unknown;
    }

    private static string? GetActionToken(string? patternValue)
    {
        if (string.IsNullOrWhiteSpace(patternValue))
        {
            return null;
        }

        var separatorIndex = patternValue.IndexOf(' ');
        return separatorIndex >= 0 ? patternValue[..separatorIndex] : patternValue;
    }

    [GeneratedRegex(@"^(?:<\d+>1\s+)?\d+\.\d+\s+\S+\s+(?<event_type>\S+)\s+(?<content>.+)$", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex LogPattern();
}
