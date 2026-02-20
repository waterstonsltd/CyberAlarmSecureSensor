using System.Diagnostics.CodeAnalysis;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Status.Models;

namespace CyberAlarm.SyslogRelay.Domain.PatternMatching;

[SuppressMessage("Minor Code Smell", "S3267:Loops should be simplified with \"LINQ\" expressions", Justification = "Contains ref-like type.")]
internal sealed class PatternMatcher
{
    private readonly List<Pattern> _patterns;
    private readonly int _scanLength;

    public PatternMatcher(List<Pattern> patterns, int scanLength)
    {
        ArgumentNullException.ThrowIfNull(patterns);

        // Sort by priority (highest first)
        _patterns = [.. patterns.OrderByDescending(p => p.Priority)];

        _scanLength = scanLength;
    }

    public bool TryMatch(ReadOnlySpan<char> log, [NotNullWhen(true)] out PatternMatchResult? match)
    {
        foreach (var pattern in _patterns)
        {
            if (MatchesPattern(log, pattern))
            {
                match = new(pattern.Name, pattern.Parser);
                return true;
            }
        }

        match = null;
        return false;
    }

    private bool MatchesPattern(ReadOnlySpan<char> log, Pattern pattern)
    {
        foreach (var rule in pattern.Rules)
        {
            if (!EvaluateRule(log, rule))
            {
                return false;  // All rules must pass
            }
        }

        return true;
    }

    private bool EvaluateRule(ReadOnlySpan<char> log, PatternRule rule) =>
        rule.Type switch
        {
            RuleType.StartsWith => CheckStartsWith(log, rule.Values),
            RuleType.EndsWith => CheckEndsWith(log, rule.Values),
            RuleType.ContainsAll => CheckContainsAll(log, rule.Values, _scanLength),
            RuleType.ContainsAny => CheckContainsAny(log, rule.Values, _scanLength),
            RuleType.MustNotContain => !CheckContainsAny(log, rule.Values, _scanLength),
            RuleType.MinimumMatches => CheckMinimumMatches(log, rule.Values, _scanLength, rule.MinimumCount ?? 1),
            RuleType.LengthRange => log.Length >= (rule.MinimumCount ?? 0),
            _ => false,
        };

    private static bool CheckStartsWith(ReadOnlySpan<char> log, List<string> values)
    {
        if (values == null || values.Count == 0)
        {
            return false;
        }

        foreach (var value in values)
        {
            if (log.StartsWith(value.AsSpan(), StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool CheckEndsWith(ReadOnlySpan<char> log, List<string> values)
    {
        if (values == null || values.Count == 0)
        {
            return false;
        }

        foreach (var value in values)
        {
            if (log.EndsWith(value.AsSpan(), StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool CheckContainsAll(ReadOnlySpan<char> log, List<string> values, int scanLength)
    {
        if (values == null || values.Count == 0)
        {
            return false;
        }

        scanLength = Math.Min(scanLength, log.Length);
        var scanSpan = log[..scanLength];

        foreach (var value in values)
        {
            if (!scanSpan.Contains(value.AsSpan(), StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static bool CheckContainsAny(ReadOnlySpan<char> log, List<string> values, int scanLength)
    {
        if (values == null || values.Count == 0)
        {
            return false;
        }

        scanLength = Math.Min(scanLength, log.Length);
        var scanSpan = log[..scanLength];

        foreach (var value in values)
        {
            if (scanSpan.Contains(value.AsSpan(), StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool CheckMinimumMatches(ReadOnlySpan<char> log, List<string> values, int scanLength, int minimumCount)
    {
        if (values == null || values.Count == 0)
        {
            return false;
        }

        scanLength = Math.Min(scanLength, log.Length);
        var scanSpan = log[..scanLength];
        var totalMatches = 0;

        foreach (var value in values)
        {
            totalMatches += CountOccurrences(scanSpan, value);

            // Early exit if we've already hit the minimum
            if (totalMatches >= minimumCount)
            {
                return true;
            }
        }

        return totalMatches >= minimumCount;
    }

    private static int CountOccurrences(ReadOnlySpan<char> log, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return 0;
        }

        var count = 0;
        var index = 0;

        while (index <= log.Length - value.Length)
        {
            if (log.Slice(index, value.Length).SequenceEqual(value.AsSpan()))
            {
                count++;
                index += value.Length;
            }
            else
            {
                index++;
            }
        }

        return count;
    }
}
