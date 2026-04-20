using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal abstract class KeyValueParserBase<TParserConfig> : IParser
    where TParserConfig : ParserConfig
{
    private TParserConfig? _config;

    public Result Initialise(object? config)
    {
        try
        {
            if (config is JsonElement configElement)
            {
                _config = configElement.Deserialize<TParserConfig>(SerializationOptions.ParserConfig);
            }
            else if (config is TParserConfig parsedConfig)
            {
                _config = parsedConfig;
            }

            if (_config is null)
            {
                return Result.Fail("Failed to parse config.");
            }

            return ProcessConfig(_config);
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

        return ParseLog(log, _config);
    }

    protected virtual Result ProcessConfig(TParserConfig config) => Result.Ok();

    protected abstract Result<ParseResult> ParseLog(string log, TParserConfig config);

    protected static Result<ParseResult> ParseKeyValues(Dictionary<string, string> keyValues, TParserConfig config)
    {
        if (!TryGetValue(keyValues, config.SourceIpKeys, out var sourceIp) ||
            (!TryGetValue(keyValues, config.DestinationIpKeys, out var destinationIp) && !config.IsDestinationIpOptional) ||
            (!TryGetValue(keyValues, config.SourcePortKeys, out var sourcePortValue) && !config.IsSourcePortOptional) ||
            (!TryGetValue(keyValues, config.DestinationPortKeys, out var destinationPortValue) && !config.IsDestinationPortOptional) ||
            (!TryGetValue(keyValues, config.ProtocolKeys, out var protocolValue) && !config.IsProtocolOptional) ||
            (!TryGetValue(keyValues, config.ActionKeys, out var actionValue) && !config.IsActionOptional))
        {
            return new UnparsableEventError();
        }

        var duration = ExtractDuration(keyValues, config);
        var bytes = ExtractBytes(keyValues, config);

        return ToParseResult(
            config,
            sourceIp,
            destinationIp,
            sourcePortValue,
            destinationPortValue,
            protocolValue,
            actionValue,
            duration,
            bytes);
    }

    protected static bool TryGetValue(Dictionary<string, string> keyValues, string[] keys, [MaybeNullWhen(false)] out string value)
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

    [SuppressMessage("Critical Code Smell", "S107:Methods should not have too many parameters", Justification = "All 9 parameters are distinct parsed network-event fields (source/dest IP, ports, protocol, action, duration, bytes) plus config for action resolution. A parameter object would add a type with no semantic meaning.")]
    protected static ParseResult ToParseResult(
        TParserConfig config,
        string sourceIp,
        string? destinationIp = null,
        string? sourcePort = null,
        string? destinationPort = null,
        string? protocol = null,
        string? action = null,
        TimeSpan? duration = null,
        long? bytes = null) =>
        new(
            sourceIp,
            destinationIp,
            sourcePort.ToPort(),
            destinationPort.ToPort(),
            protocol.ToProtocol(),
            ToAction(action, config),
            duration,
            bytes);

    protected static EventAction ToAction(string? value, TParserConfig config)
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

        if (config.CloseActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Close;
        }

        if (config.ResetActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Reset;
        }

        if (config.TimeoutActionValues.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return EventAction.Timeout;
        }

        return EventAction.Unknown;
    }

    protected static TimeSpan? ExtractDuration(Dictionary<string, string> keyValues, TParserConfig config)
    {
        if (config.DurationKeys.Length == 0 || !TryGetValue(keyValues, config.DurationKeys, out var durationValue))
        {
            return null;
        }

        if (config.DurationIsSeconds && long.TryParse(durationValue, out var seconds))
        {
            return TimeSpan.FromSeconds(seconds);
        }

        return durationValue.ToDuration();
    }

    protected static long? ExtractBytes(Dictionary<string, string> keyValues, TParserConfig config)
    {
        TryGetValue(keyValues, config.TotalBytesKeys, out var totalBytesValue);
        TryGetValue(keyValues, config.SentBytesKeys, out var sentBytesValue);
        TryGetValue(keyValues, config.ReceivedBytesKeys, out var receivedBytesValue);

        var total = totalBytesValue.ToLong();
        var sent = sentBytesValue.ToLong();
        var received = receivedBytesValue.ToLong();

        if (total.HasValue)
        {
            return total;
        }

        if (sent.HasValue || received.HasValue)
        {
            return (sent ?? 0) + (received ?? 0);
        }

        return null;
    }
}
