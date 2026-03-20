using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.PatternMatching;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class PatternMatchingStage(
    IPatternMatchingService patternMatchingService,
    PipelineStageServices services,
    ILogger<PatternMatchingStage> logger)
    : PipelineStageBase<SyslogEvent, PatternMatchingStageOutput>(services, logger)
{
    private readonly IPatternMatchingService _patternMatchingService = patternMatchingService;

    protected override async Task<PatternMatchingStageOutput> ProcessMessageAsync(SyslogEvent input, CancellationToken cancellationToken)
    {
        var result = await _patternMatchingService.MatchPatternAsync(input.RawData, cancellationToken);
        return new(input, result);
    }
}
