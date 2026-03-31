namespace CyberAlarm.SyslogRelay.Domain.Pipeline.Stages;

public interface IPipelineStage
{
    IPipelineStage? NextStage { get; }

    Task StartAsync(CancellationToken cancellationToken);

    Task StopAsync(CancellationToken cancellationToken);
}

public interface IPipelineStage<in TInput> : IPipelineStage
{
    Task EnqueueAsync(TInput input, CancellationToken cancellationToken);
}
