namespace CyberAlarm.SyslogRelay.Domain.HealthCheck;

public interface IHealthCheckService
{
    void Reset();

    Task<HealthCheckResult> CheckHealthAsync(CancellationToken cancellationToken);

    Task SetHealthyAsync(string service, CancellationToken cancellationToken);

    Task SetUnhealthyAsync(string service, CancellationToken cancellationToken);
}
