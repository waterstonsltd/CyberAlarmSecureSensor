using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class SyslogRelayPipelineBuilder<TInput>
{
    public SyslogRelayPipelineBuilder()
    {
        FinalStage = Substitute.For<IPipelineStage>();
        FinalStage.NextStage.Returns(default(IPipelineStage));

        MiddleStage = Substitute.For<IPipelineStage>();
        MiddleStage.NextStage.Returns(FinalStage);

        InitialStage = Substitute.For<IPipelineStage<TInput>>();
        InitialStage.NextStage.Returns(MiddleStage);
    }

    public IPipelineStage<TInput> InitialStage { get; }

    public IPipelineStage MiddleStage { get; }

    public IPipelineStage FinalStage { get; }

    public SyslogRelayPipeline<TInput> Build() => new(InitialStage);
}
