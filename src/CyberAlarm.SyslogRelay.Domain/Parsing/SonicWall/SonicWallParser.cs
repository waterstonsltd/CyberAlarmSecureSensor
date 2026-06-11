using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.SonicWall;

internal sealed class SonicWallParser : IParser
{
    [ThreadStatic]
    private static Dictionary<string, string>? _keyValueBuffer;

    private SonicWallParserConfig? _config;

    public Result Initialise(object? config)
    {
        try
        {
            _config = config.ParseConfig<SonicWallParserConfig>();
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

        var keyValues = log.ParseKeyValues(GetBuffer());
        if (keyValues is null)
        {
            return new FormatError();
        }

        if (!keyValues.TryGetValue("src", out var srcValue) || string.IsNullOrEmpty(srcValue))
        {
            return new UnparsableEventError();
        }

        if (!keyValues.TryGetValue("dst", out var dstValue) || string.IsNullOrEmpty(dstValue))
        {
            return new UnparsableEventError();
        }

        var srcParts = srcValue.Split(':');
        var sourceIp = srcParts[0];
        var sourcePort = srcParts.Length > 1 ? srcParts[1].ToPort() : null;

        var dstParts = dstValue.Split(':');
        var destinationIp = dstParts[0];
        var destinationPort = dstParts.Length > 1 ? dstParts[1].ToPort() : null;

        var protocol = EventProtocol.Unknown;
        if (keyValues.TryGetValue("proto", out var protoValue) && !string.IsNullOrEmpty(protoValue))
        {
            var slashIndex = protoValue.IndexOf('/');
            var protocolPart = slashIndex >= 0 ? protoValue[..slashIndex] : protoValue;
            protocol = protocolPart.ToProtocol();
        }

        keyValues.TryGetValue("fw_action", out var actionValue);
        var action = ToAction(actionValue, _config);

        var bytes = keyValues.ExtractBytes([], [], _config.ReceivedBytesKeys);

        return new ParseResult(
            sourceIp,
            destinationIp,
            sourcePort,
            destinationPort,
            protocol,
            action,
            null,
            bytes);
    }

    private static Dictionary<string, string> GetBuffer()
    {
        _keyValueBuffer ??= new Dictionary<string, string>();
        _keyValueBuffer.Clear();
        return _keyValueBuffer;
    }

    private static EventAction ToAction(string? value, SonicWallParserConfig config)
    {
        if (string.IsNullOrEmpty(value))
        {
            return EventAction.Unknown;
        }

        if (config.AllowActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Allow;
        }

        if (config.DenyActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Deny;
        }

        if (config.DropActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Drop;
        }

        return EventAction.Unknown;
    }
}
