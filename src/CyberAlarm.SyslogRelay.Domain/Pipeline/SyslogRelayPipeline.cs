using CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

namespace CyberAlarm.SyslogRelay.Domain.Pipeline;

public sealed class SyslogRelayPipeline<TInput>(IPipelineStage<TInput> initialStage) : ISyslogRelayPipeline<TInput>
{
    private readonly IPipelineStage<TInput> _initialStage = initialStage;

    public Task EnqueueAsync(TInput input, CancellationToken cancellationToken) =>
        _initialStage.EnqueueAsync(input, cancellationToken);

    public Task StartAsync(CancellationToken cancellationToken) =>
        Traverse(stage => stage.StartAsync(cancellationToken));

    public Task StopAsync(CancellationToken cancellationToken) =>
        Traverse(stage => stage.StopAsync(cancellationToken));

    private async Task Traverse(Func<IPipelineStage, Task> visit)
    {
        IPipelineStage? stage = _initialStage;
        while (stage != null)
        {
            await visit(stage);
            stage = stage.NextStage;
        }
    }
}
