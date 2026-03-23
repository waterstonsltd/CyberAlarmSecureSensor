using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class ParsingStage(
    PipelineStageServices services,
    ILogger<ParsingStage> logger,
    TimeProvider? timeProvider = null)
    : PipelineStageBase<PatternMatchingStageOutput, ParsingStageOutput>(services, logger)
{
    private readonly ILogger<ParsingStage> _logger = logger;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    // Precomputed interval in timestamp ticks to avoid a division in GetElapsedTime on every event.
    private readonly long _failureLogIntervalTicks =
        (long)(TimeSpan.FromMinutes(services.Options.ParseFailureLogIntervalInMinutes).TotalSeconds
            * (timeProvider ?? TimeProvider.System).TimestampFrequency);

    private readonly Dictionary<(string PatternName, string ParserName), (int Count, long LastLoggedTicks)> _parseFailureState = [];

    private int _noPatternMatchCount;
    private long _noPatternMatchLastLoggedTicks;

    protected override Task<ParsingStageOutput> ProcessMessageAsync(PatternMatchingStageOutput input, CancellationToken cancellationToken)
    {
        var matchResult = input.PatternMatchResult;
        if (matchResult is null)
        {
            LogNoPatternMatch();
            return Output();
        }

        var parseResult = matchResult.Parser.Parse(input.SyslogEvent.RawData);
        if (parseResult.IsFailed)
        {
            if (matchResult.Parser is not NullParser)
            {
                LogParseFailure(matchResult);
            }

            return Output();
        }

        return Output(parseResult.Value);

        Task<ParsingStageOutput> Output(ParseResult? parseResult = default)
        {
            return Task.FromResult(new ParsingStageOutput(input.SyslogEvent, input.PatternMatchResult, parseResult));
        }
    }

    private void LogNoPatternMatch()
    {
        _noPatternMatchCount++;

        if (ShouldLog(ref _noPatternMatchLastLoggedTicks))
        {
            _logger.LogDebug("Skipped parsing for {Count} event(s) with no matching pattern.", _noPatternMatchCount);
        }
    }

    private void LogParseFailure(PatternMatchResult matchResult)
    {
        var parserName = matchResult.Parser.GetType().Name;
        var key = (matchResult.PatternName, parserName);

        _parseFailureState.TryGetValue(key, out var state);
        state = (state.Count + 1, state.LastLoggedTicks);
        _parseFailureState[key] = state;

        var lastLoggedTicks = state.LastLoggedTicks;
        if (ShouldLog(ref lastLoggedTicks))
        {
            _parseFailureState[key] = (state.Count, lastLoggedTicks);

            _logger.LogDebug(
                "Failed to parse {Count} event(s) with pattern '{Pattern}' and parser '{Parser}'.",
                state.Count,
                matchResult.PatternName,
                parserName);
        }
    }

    private bool ShouldLog(ref long lastLoggedTicks)
    {
        var nowTicks = _timeProvider.GetTimestamp();

        if (lastLoggedTicks == 0 || (nowTicks - lastLoggedTicks) >= _failureLogIntervalTicks)
        {
            lastLoggedTicks = nowTicks;
            return true;
        }

        return false;
    }
}
