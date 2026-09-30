using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.HealthCheck;

public interface IHealthCheckService
{
    IHealthToken GetHealthToken(string service);

    Task<Result> InitialiseAsync(CancellationToken cancellationToken);

    Task<HealthCheckResult> CheckHealthAsync(CancellationToken cancellationToken);
}
