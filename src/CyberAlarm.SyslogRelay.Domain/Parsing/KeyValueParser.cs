using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class KeyValueParser : IParser
{
    private KeyValueParserConfig? _config;

    public Result Initialise(object? config)
    {
        try
        {
            if (config is JsonElement configElement)
            {
                _config = configElement.Deserialize<KeyValueParserConfig>(SerializationOptions.ParserConfig);
            }
            else if (config is KeyValueParserConfig keyValueParserConfig)
            {
                _config = keyValueParserConfig;
            }

            return Result.FailIf(_config is null, "Failed to parse config.");
        }
        catch (Exception ex)
        {
            return Result.Fail(ex.Message);
        }
    }

    public Result<ParseResult> Parse(string log)
    {
        ArgumentException.ThrowIfNullOrEmpty(log);
        ArgumentNullException.ThrowIfNull(_config);

        var keyValues = ParseKeyValues(log, _config.Regex);
        if (keyValues is null or { Count: 0 })
        {
            return new FormatError();
        }

        if (!TryGetValue(keyValues, _config.SourceIpKeys, out var sourceIp) ||
            (!TryGetValue(keyValues, _config.DestinationIpKeys, out var destinationIp) && !_config.IsDestinationIpOptional) ||
            (!TryGetValue(keyValues, _config.SourcePortKeys, out var sourcePortValue) && !_config.IsSourcePortOptional) ||
            (!TryGetValue(keyValues, _config.DestinationPortKeys, out var destinationPortValue) && !_config.IsDestinationPortOptional) ||
            (!TryGetValue(keyValues, _config.ProtocolKeys, out var protocolValue) && !_config.IsProtocolOptional) ||
            (!TryGetValue(keyValues, _config.ActionKeys, out var actionValue) && !_config.IsActionOptional))
        {
            return new UnparsableEventError();
        }

        return new ParseResult(
            sourceIp,
            destinationIp,
            sourcePortValue.ToPort(),
            destinationPortValue.ToPort(),
            protocolValue.ToProtocol(),
            ToAction(actionValue));
    }

    private static Dictionary<string, string>? ParseKeyValues(string log, Regex regex)
    {
        var matches = regex.Matches(log);
        if (matches.Count == 0)
        {
            return null;
        }

        var keyValues = new Dictionary<string, string>();
        foreach (Match match in matches)
        {
            var key = match.Groups[1].Value;
            var value = match.Groups[2].Success ? match.Groups[2].Value : match.Groups[3].Value;
            keyValues[key] = value;
        }

        return keyValues;
    }

    private static bool TryGetValue(Dictionary<string, string> keyValues, string[] keys, [MaybeNullWhen(false)] out string value)
    {
        value = null;

        foreach (var key in keys ?? [])
        {
            if (keyValues.TryGetValue(key, out value))
            {
                return true;
            }
        }

        return false;
    }

    private EventAction ToAction(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return EventAction.Unknown;
        }

        if (_config!.AllowActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Allow;
        }

        if (_config.DenyActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Deny;
        }

        return EventAction.Unknown;
    }
}
