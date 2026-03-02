namespace CyberAlarm.SyslogRelay.Domain.Pipeline;

public interface ISyslogRelayPipeline<in TInput>
{
    Task EnqueueAsync(TInput input, CancellationToken cancellationToken);

    Task StartAsync(CancellationToken cancellationToken);

    Task StopAsync(CancellationToken cancellationToken);
}
