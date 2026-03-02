using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

internal sealed class ResetHealthCheckActivity(
    IHealthCheckService healthCheckService,
    ILogger<ResetHealthCheckActivity> logger) : IStartupActivity
{
    private readonly IHealthCheckService _healthCheckService = healthCheckService;
    private readonly ILogger<ResetHealthCheckActivity> _logger = logger;

    public Task<Result> RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Resetting health checks.");
        _healthCheckService.Reset();

        return Task.FromResult(Result.Ok());
    }
}
