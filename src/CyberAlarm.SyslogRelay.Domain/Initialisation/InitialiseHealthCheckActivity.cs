using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

internal sealed class InitialiseHealthCheckActivity(
    IHealthCheckService healthCheckService,
    ILogger<InitialiseHealthCheckActivity> logger) : IStartupActivity
{
    private readonly IHealthCheckService _healthCheckService = healthCheckService;
    private readonly ILogger<InitialiseHealthCheckActivity> _logger = logger;

    public async Task<Result> RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Initialising health checks.");
        return await _healthCheckService.InitialiseAsync(cancellationToken);
    }
}
