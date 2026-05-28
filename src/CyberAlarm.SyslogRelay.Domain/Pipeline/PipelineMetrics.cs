using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline;

internal sealed class PipelineMetrics
{
    public const string MeterName = "CyberAlarm.SyslogRelay.Pipeline";

    private readonly Meter _meter;

    public PipelineMetrics(IMeterFactory meterFactory)
    {
        _meter = meterFactory.Create(MeterName);

        ProcessingDuration = _meter.CreateHistogram<double>(
            "pipeline.stage.processing_duration",
            unit: "ms",
            description: "Time spent processing a single item in a pipeline stage, including enqueue to the next stage.");

        ItemsProcessed = _meter.CreateCounter<long>(
            "pipeline.stage.items_processed",
            description: "Number of items processed by a pipeline stage.");

        ValidationOutcomes = _meter.CreateCounter<long>(
            "pipeline.validation.outcomes",
            description: "Number of events classified by validation outcome (Success, UnableToPatternMatch, UnableToParse, LocalOnlyEvent, OutboundEvent).");

        BufferFlushes = _meter.CreateCounter<long>(
            "pipeline.buffer.flushes",
            description: "Number of times the persistence buffer has been flushed, tagged by the reason that triggered the flush.");

        BufferFlushSize = _meter.CreateHistogram<int>(
            "pipeline.buffer.flush_size",
            unit: "{events}",
            description: "Number of events written to disk in a single buffer flush.");

        PatternMatches = _meter.CreateCounter<long>(
            "pipeline.pattern_matching.matches",
            description: "Number of events matched to a pattern, tagged by pattern name.");
    }

    public Histogram<double> ProcessingDuration { get; }

    public Counter<long> ItemsProcessed { get; }

    public Counter<long> ValidationOutcomes { get; }

    public Counter<long> BufferFlushes { get; }

    public Histogram<int> BufferFlushSize { get; }

    public Counter<long> PatternMatches { get; }

    public void RegisterChannelDepth(string stageName, Func<int> getCount)
    {
        _meter.CreateObservableGauge(
            "pipeline.channel.pending_items",
            () => new Measurement<int>(getCount(), new TagList { { "stage", stageName } }),
            unit: "{items}",
            description: "Number of items currently waiting in a pipeline stage's input channel.");
    }
}
