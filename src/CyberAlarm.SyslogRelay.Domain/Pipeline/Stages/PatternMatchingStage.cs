using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.PatternMatching;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class PatternMatchingStage(
    IPatternMatchingService patternMatchingService,
    IOptions<PipelineOptions> options,
    ILogger<PatternMatchingStage> logger) : PipelineStageBase<SyslogEvent, PatternMatchingStageOutput>(options, logger)
{
    private readonly IPatternMatchingService _patternMatchingService = patternMatchingService;

    protected override async Task<PatternMatchingStageOutput> ProcessMessageAsync(SyslogEvent input, CancellationToken cancellationToken)
    {
        var result = await _patternMatchingService.MatchPatternAsync(input.RawData, cancellationToken);
        return new(input, result);
    }
}
