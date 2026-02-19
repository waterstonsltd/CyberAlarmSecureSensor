using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class ParsingStage(
    IParserFactory parserFactory,
    IOptions<PipelineOptions> options,
    ILogger<ParsingStage> logger) : PipelineStageBase<PatternMatchingStageOutput, ParsingStageOutput>(options, logger)
{
    private readonly IParserFactory _parserFactory = parserFactory;
    private readonly ILogger<ParsingStage> _logger = logger;

    protected override Task<ParsingStageOutput> ProcessMessageAsync(PatternMatchingStageOutput input, CancellationToken cancellationToken)
    {
        if (input.MatchedFirewallEvent is null)
        {
            _logger.LogDebug("No pattern matched for event {RawData}: skipping parsing.", input.SyslogEvent.RawData);
            return Output();
        }

        var eventPattern = input.MatchedFirewallEvent.EventPattern;

        var parser = _parserFactory.Create(eventPattern);
        if (parser is null)
        {
            _logger.LogError("No parser found for pattern {EventPattern}: skipping parsing.", eventPattern);
            return Output();
        }

        var result = parser.Parse(input.SyslogEvent.RawData);
        if (result.IsFailed)
        {
            _logger.LogDebug(
                "Failed to parse '{RawData}' with pattern {EventPattern}: {ErrorMessage}",
                input.SyslogEvent.RawData,
                eventPattern,
                result.ErrorMessage);

            return Output();
        }

        return Output(result.Value);

        Task<ParsingStageOutput> Output(ParsedFirewallEvent? parsedEvent = default)
        {
            return Task.FromResult(new ParsingStageOutput(input.SyslogEvent, input.MatchedFirewallEvent, parsedEvent));
        }
    }
}
