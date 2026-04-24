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
    private bool _hasInterestingKeys;
    private Regex? _regex;
    private char? _pairDelimiter;
    private char? _valueDelimiter;

    // Span-based lookup over the set of keys we actually need from each log line.
    // Used only in the regex path to skip allocating strings for key-value pairs we will never read.
    // StringComparer.Ordinal is required — GetAlternateLookup<ReadOnlySpan<char>> only works
    // when the comparer implements IAlternateEqualityComparer<ReadOnlySpan<char>, string>.
    // Note: the AlternateLookup struct holds an internal reference to the HashSet, keeping it
    // alive without needing a separate field.
    private HashSet<string>.AlternateLookup<ReadOnlySpan<char>> _interestingKeysLookup;

    // Pre-allocated key strings keyed by their span for zero-alloc dictionary insertion on the hot path.
    // StringComparer.Ordinal is required — see _interestingKeysLookup comment above.
    private Dictionary<string, string>.AlternateLookup<ReadOnlySpan<char>> _interestingKeyStringsLookup;

    protected override Result ProcessConfig(KeyValueParserConfig config)
    {
        _useRegex = config.UseRegex ?? !string.IsNullOrEmpty(config.RegexPatternOverride);

        if (_useRegex)
        {
            _regex = string.IsNullOrEmpty(config.RegexPatternOverride)
                ? ParsingExtensions.DefaultKeyValueRegex()
                : new(config.RegexPatternOverride, RegexOptions.Compiled, matchTimeout: TimeSpan.FromSeconds(1));

            var interestingKeys = new HashSet<string>(StringComparer.Ordinal);
            interestingKeys.UnionWith(config.SourceIpKeys);
            interestingKeys.UnionWith(config.DestinationIpKeys);
            interestingKeys.UnionWith(config.SourcePortKeys);
            interestingKeys.UnionWith(config.DestinationPortKeys);
            interestingKeys.UnionWith(config.ProtocolKeys);
            interestingKeys.UnionWith(config.ActionKeys);
            interestingKeys.UnionWith(config.DurationKeys);
            interestingKeys.UnionWith(config.TotalBytesKeys);
            interestingKeys.UnionWith(config.SentBytesKeys);
            interestingKeys.UnionWith(config.ReceivedBytesKeys);

            _interestingKeysLookup = interestingKeys.GetAlternateLookup<ReadOnlySpan<char>>();
            _hasInterestingKeys = interestingKeys.Count > 0;

            // Identity map: span → already-allocated string, so ToString() is never called in the hot path.
            var interestingKeyStrings = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var key in interestingKeys)
            {
                interestingKeyStrings[key] = key;
            }

            _interestingKeyStringsLookup = interestingKeyStrings.GetAlternateLookup<ReadOnlySpan<char>>();

            // Clear non-regex state in case ProcessConfig is called more than once.
            _pairDelimiter = null;
            _valueDelimiter = null;
        }
        else
        {
            _pairDelimiter = char.TryParse(config.PairDelimiter, out var pairDelimiter) ? pairDelimiter : ' ';
            _valueDelimiter = char.TryParse(config.ValueDelimiter, out var valueDelimiter) ? valueDelimiter : '=';

            // Clear regex state in case ProcessConfig is called more than once.
            _regex = null;
            _hasInterestingKeys = false;
        }

        return Result.Ok();
    }

    protected override Result<ParseResult> ParseLog(string log, KeyValueParserConfig config)
    {
        var keyValues = _useRegex
            ? ParseKeyValuesFromRegex(log, _regex!, _hasInterestingKeys, _interestingKeysLookup, _interestingKeyStringsLookup)
            : log.ParseKeyValues(_pairDelimiter!.Value, _valueDelimiter!.Value);

        if (keyValues is null or { Count: 0 })
        {
            return new FormatError();
        }

        // CONTRACT: ParseKeyValues must consume keyValues synchronously and must not retain
        // a reference past the call — the regex path returns the thread-static _keyValueBuffer
        // directly, which is cleared on the next call to ParseLog on the same thread.
        return ParseKeyValues(keyValues, config);
    }

    private static Dictionary<string, string>? ParseKeyValuesFromRegex(
        string log,
        Regex regex,
        bool hasInterestingKeys,
        HashSet<string>.AlternateLookup<ReadOnlySpan<char>> interestingKeysLookup,
        Dictionary<string, string>.AlternateLookup<ReadOnlySpan<char>> interestingKeyStringsLookup)
    {
        _keyValueBuffer ??= new Dictionary<string, string>(32);

        // ASYNC SAFETY: if this method ever becomes async, Clear() could race with
        // a continuation that resumed on the same thread after an await.
        _keyValueBuffer.Clear();

        var match = regex.Match(log);
        if (!match.Success)
        {
            return null;
        }

        while (match.Success)
        {
            var keySpan = match.Groups[1].ValueSpan;

            // Skip keys we don't need — avoids materialising value strings for ~60-70% of pairs
            // in a typical Sophos UTM log line.
            if (!hasInterestingKeys || interestingKeysLookup.Contains(keySpan))
            {
                // Use the pre-allocated key string rather than ToString() to avoid a heap allocation per interesting key.
                // When hasInterestingKeys is true, TryGetValue is guaranteed to succeed — the lookup and string map
                // are built from the same source, so the ToString() fallback only fires in the "take everything" mode
                // (hasInterestingKeys == false), where we need to materialise an arbitrary key.
                var key = hasInterestingKeys && interestingKeyStringsLookup.TryGetValue(keySpan, out var cached) ? cached : keySpan.ToString();
                _keyValueBuffer[key] = match.Groups[2].Success
                    ? match.Groups[2].Value
                    : match.Groups[3].Value;
            }

            match = match.NextMatch();
        }

        return _keyValueBuffer.Count > 0 ? _keyValueBuffer : null;
    }
}
