using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class ParsingStage(
    IOptions<PipelineOptions> options,
    ILogger<ParsingStage> logger) : PipelineStageBase<PatternMatchingStageOutput, ParsingStageOutput>(options, logger)
{
    private readonly ILogger<ParsingStage> _logger = logger;

    protected override Task<ParsingStageOutput> ProcessMessageAsync(PatternMatchingStageOutput input, CancellationToken cancellationToken)
    {
        var matchResult = input.PatternMatchResult;
        if (matchResult is null)
        {
            _logger.LogDebug("No pattern matched for event {RawData}: skipping parsing.", input.SyslogEvent.RawData);
            return Output();
        }

        var parseResult = matchResult.Parser.Parse(input.SyslogEvent.RawData);
        if (parseResult.IsFailed)
        {
            if (matchResult.Parser is not NullParser)
            {
                _logger.LogDebug(
                    "Failed to parse '{RawData}' with pattern '{Pattern}' and parser '{Parser}'.",
                    input.SyslogEvent.RawData,
                    matchResult.PatternName,
                    matchResult.Parser.Name);
            }

            return Output();
        }

        return Output(parseResult.Value);

        Task<ParsingStageOutput> Output(ParseResult? parseResult = default)
        {
            return Task.FromResult(new ParsingStageOutput(input.SyslogEvent, input.PatternMatchResult, parseResult));
        }
    }
}
