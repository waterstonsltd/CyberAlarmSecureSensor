using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing.WatchGuard;

internal abstract class WatchGuardParserBase : IParser
{
    [ThreadStatic]
    private static Dictionary<string, string>? _keyValueBuffer;

    private WatchGuardParserConfig? _config;

    public Result Initialise(object? config)
    {
        try
        {
            _config = config.ParseConfig<WatchGuardParserConfig>();
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

        return ParseLog(log, _config);
    }

    protected abstract Result<ParseResult> ParseLog(string log, WatchGuardParserConfig config);

    protected static EventAction ToAction(string? value, WatchGuardParserConfig config)
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

        return EventAction.Unknown;
    }

    protected static Dictionary<string, string>? ParseKeyValuesFromRegex(string log)
    {
        _keyValueBuffer ??= new Dictionary<string, string>();
        _keyValueBuffer.Clear();

        return log.ParseKeyValues(_keyValueBuffer);
    }
}
