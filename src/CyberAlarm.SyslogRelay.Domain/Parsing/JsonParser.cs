using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class JsonParser : KeyValueParserBase<JsonParserConfig>
{
    private string? _jsonStartToken;
    private bool _protocolIsNumber;

    protected override Result ProcessConfig(JsonParserConfig config)
    {
        _jsonStartToken = string.IsNullOrEmpty(config.JsonStartToken) ? null : config.JsonStartToken;
        _protocolIsNumber = config.ProtocolIsNumber;
        return Result.Ok();
    }

    protected override Result<ParseResult> ParseLog(string log, JsonParserConfig config)
    {
        var jsonStart = FindJsonStart(log, _jsonStartToken);
        if (jsonStart < 0)
        {
            return new FormatError();
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(log.AsMemory(jsonStart));
        }
        catch (JsonException)
        {
            return new FormatError();
        }

        using (doc)
        {
            var root = doc.RootElement;

            if (!TryGetStringProperty(root, config.SourceIpKeys, out var sourceIp) || string.IsNullOrEmpty(sourceIp))
            {
                return new UnparsableEventError();
            }

            TryGetStringProperty(root, config.DestinationIpKeys, out var destinationIp);

            int? sourcePort = TryGetIntProperty(root, config.SourcePortKeys, out var spt) ? spt : null;
            int? destinationPort = TryGetIntProperty(root, config.DestinationPortKeys, out var dpt) ? dpt : null;

            var protocol = ResolveProtocol(root, config.ProtocolKeys, _protocolIsNumber);

            TryGetStringProperty(root, config.ActionKeys, out var action);

            return new ParseResult(
                sourceIp,
                destinationIp,
                sourcePort,
                destinationPort,
                protocol,
                ToAction(action, config));
        }
    }

    private static int FindJsonStart(string log, string? startToken)
    {
        if (startToken is null)
        {
            var idx = log.IndexOf('{');
            return idx >= 0 ? idx : -1;
        }

        var tokenIdx = log.IndexOf(startToken, StringComparison.Ordinal);
        if (tokenIdx < 0)
        {
            return -1;
        }

        var afterToken = tokenIdx + startToken.Length;
        return afterToken < log.Length && log[afterToken] == '{' ? afterToken : -1;
    }

    private static bool TryGetStringProperty(JsonElement root, string[] keys, out string? value)
    {
        foreach (var key in keys ?? [])
        {
            if (root.TryGetProperty(key, out var element) && element.ValueKind == JsonValueKind.String)
            {
                value = element.GetString();
                return !string.IsNullOrEmpty(value);
            }
        }

        value = null;
        return false;
    }

    private static bool TryGetIntProperty(JsonElement root, string[] keys, out int value)
    {
        foreach (var key in keys ?? [])
        {
            if (root.TryGetProperty(key, out var element) && element.TryGetInt32(out value))
            {
                return true;
            }
        }

        value = 0;
        return false;
    }

    private static EventProtocol ResolveProtocol(JsonElement root, string[] keys, bool isNumber)
    {
        foreach (var key in keys ?? [])
        {
            if (!root.TryGetProperty(key, out var element))
            {
                continue;
            }

            if (isNumber)
            {
                if (element.TryGetInt32(out var num))
                {
                    var candidate = (EventProtocol)num;
                    return Enum.IsDefined(candidate) ? candidate : EventProtocol.Unknown;
                }
            }
            else if (element.ValueKind == JsonValueKind.String)
            {
                return element.GetString().ToProtocol();
            }
        }

        return EventProtocol.Unknown;
    }
}
