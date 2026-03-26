using System.Text.RegularExpressions;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing.Errors;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Parsing;

internal sealed class KeyValueParser : KeyValueParserBase<KeyValueParserConfig>
{
    // One dictionary per thread, cleared and reused each call.
    // Safe because ParseKeyValues is fully synchronous — no awaits cross the use of this buffer.
    // ASYNC SAFETY: [ThreadStatic] is unsafe with async/await — a continuation may resume on a
    // different thread and see a different (or null) buffer instance. If Parse or ParseKeyValues
    // ever becomes async, replace this with a per-call local or an ArrayPool-backed approach.
    [ThreadStatic]
    private static Dictionary<string, string>? _keyValueBuffer;

    private bool _useRegex;
    private Regex? _regex;
    private char? _pairDelimiter;
    private char? _valueDelimiter;

    protected override Result ProcessConfig(KeyValueParserConfig config)
    {
        _useRegex = config.UseRegex ?? !string.IsNullOrEmpty(config.RegexPatternOverride);

        if (_useRegex)
        {
            if (!string.IsNullOrEmpty(config.RegexPatternOverride))
            {
                _regex = new(config.RegexPatternOverride, RegexOptions.Compiled, matchTimeout: TimeSpan.FromSeconds(1));
            }
        }
        else
        {
            _pairDelimiter = char.TryParse(config.PairDelimiter, out var pairDelimiter) ? pairDelimiter : ' ';
            _valueDelimiter = char.TryParse(config.ValueDelimiter, out var valueDelimiter) ? valueDelimiter : '=';
        }

        return Result.Ok();
    }

    protected override Result<ParseResult> ParseLog(string log, KeyValueParserConfig config)
    {
        var keyValues = _useRegex
            ? ParseKeyValuesFromRegex(log, _regex)
            : log.ParseKeyValues(_pairDelimiter!.Value, _valueDelimiter!.Value);

        if (keyValues is null or { Count: 0 })
        {
            return new FormatError();
        }

        return ParseKeyValues(keyValues, config);
    }

    private static Dictionary<string, string>? ParseKeyValuesFromRegex(string log, Regex? regex)
    {
        _keyValueBuffer ??= new Dictionary<string, string>(32);

        // ASYNC SAFETY: if this method ever becomes async, Clear() could race with
        // a continuation that resumed on the same thread after an await.
        _keyValueBuffer.Clear();

        return log.ParseKeyValues(_keyValueBuffer, regex);
    }
}
