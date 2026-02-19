using CyberAlarm.SyslogRelay.Common.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

internal sealed class PatternMatchingStage(
    IOptions<PipelineOptions> options,
    ILogger<PatternMatchingStage> logger) : PipelineStageBase<SyslogEvent, PatternMatchingStageOutput>(options, logger)
{
    protected override Task<PatternMatchingStageOutput> ProcessMessageAsync(SyslogEvent input, CancellationToken cancellationToken) =>
        Task.FromResult(new PatternMatchingStageOutput(input, new(EventPattern.CiscoAsa)));
}
