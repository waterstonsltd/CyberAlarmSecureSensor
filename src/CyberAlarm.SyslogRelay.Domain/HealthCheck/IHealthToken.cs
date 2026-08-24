namespace CyberAlarm.SyslogRelay.Domain.HealthCheck;

public interface IHealthToken
{
    Task HealthyAsync(CancellationToken cancellationToken);

    Task UnhealthyAsync(CancellationToken cancellationToken);

    Task UnregisterAsync(CancellationToken cancellationToken);
}
