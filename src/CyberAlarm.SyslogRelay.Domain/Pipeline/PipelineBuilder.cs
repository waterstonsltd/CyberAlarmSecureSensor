using System.Diagnostics.CodeAnalysis;
using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline;

internal static class PipelineBuilder
{
    public static PipelineBuilder<TStart, TNext> StartWith<TStart, TNext>(Func<IServiceProvider, PipelineStageBase<TStart, TNext>> factory) =>
        PipelineBuilder<TStart, TNext>.Start(factory);
}

[SuppressMessage("StyleCop.CSharp.MaintainabilityRules", "SA1402:File may only contain a single type", Justification = "Both are related types.")]
internal sealed class PipelineBuilder<TStart, TCurrent>
{
    private readonly Func<IServiceProvider, (IPipelineStage<TStart> Start, IPipelineStageLink<TCurrent> Current)> _build;

    private PipelineBuilder(Func<IServiceProvider, (IPipelineStage<TStart> Head, IPipelineStageLink<TCurrent> Current)> factory) =>
        _build = factory;

    public static PipelineBuilder<TStart, TNext> Start<TNext>(Func<IServiceProvider, PipelineStageBase<TStart, TNext>> factory) =>
        new(sp =>
        {
            var start = factory(sp);
            return (start, start);
        });

    public PipelineBuilder<TStart, TNext> Then<TNext>(Func<IServiceProvider, PipelineStageBase<TCurrent, TNext>> factory) =>
        new(sp =>
        {
            var (start, current) = _build(sp);
            var next = factory(sp);

            current.NextStage = next;

            return (start, next);
        });

    public ISyslogRelayPipeline<TStart> Build(IServiceProvider serviceProvider) =>
        new SyslogRelayPipeline<TStart>(_build(serviceProvider).Start);
}
