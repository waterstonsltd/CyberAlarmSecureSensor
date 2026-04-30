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
        if (!keyValues.TryGetValueFrom(config.SourceIpKeys, out var sourceIp) ||
            (!keyValues.TryGetValueFrom(config.DestinationIpKeys, out var destinationIp) && !config.IsDestinationIpOptional) ||
            (!keyValues.TryGetValueFrom(config.SourcePortKeys, out var sourcePortValue) && !config.IsSourcePortOptional) ||
            (!keyValues.TryGetValueFrom(config.DestinationPortKeys, out var destinationPortValue) && !config.IsDestinationPortOptional) ||
            (!keyValues.TryGetValueFrom(config.ProtocolKeys, out var protocolValue) && !config.IsProtocolOptional) ||
            (!keyValues.TryGetValueFrom(config.ActionKeys, out var actionValue) && !config.IsActionOptional))
        {
            return new UnparsableEventError();
        }

        var duration = keyValues.ExtractDuration(config.DurationKeys, config.DurationIsSeconds);
        var bytes = keyValues.ExtractBytes(config.TotalBytesKeys, config.SentBytesKeys, config.ReceivedBytesKeys);

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
}
