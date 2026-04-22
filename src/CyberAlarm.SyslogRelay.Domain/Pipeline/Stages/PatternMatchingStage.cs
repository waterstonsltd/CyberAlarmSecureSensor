using System.Diagnostics;
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
    private readonly PipelineMetrics _metrics = services.Metrics;
    private readonly int _degreeOfParallelism = services.Options.PatternMatchingDegreeOfParallelism;

    protected override int DegreeOfParallelism => _degreeOfParallelism;

    protected override async Task<PatternMatchingStageOutput> ProcessMessageAsync(SyslogEvent input, CancellationToken cancellationToken)
    {
        var result = await _patternMatchingService.MatchPatternAsync(input.RawData, cancellationToken);

        if (result is not null)
        {
            _metrics.PatternMatches.Add(1, new TagList { { "pattern", result.PatternName } });
        }

        return new(input, result);
    }
}
