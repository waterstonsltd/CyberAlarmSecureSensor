using CyberAlarm.SyslogRelay.Domain.HealthCheck;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

public sealed class InitialisationService(
    IEnumerable<IStartupActivity> activities,
    IHealthCheckService healthCheckService,
    ILogger<InitialisationService> logger)
{
    private readonly IEnumerable<IStartupActivity> _activities = activities;
    private readonly IHealthCheckService _healthCheckService = healthCheckService;
    private readonly ILogger<InitialisationService> _logger = logger;

    public async Task<Result> InitialiseAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Initialising application: running startup activities and checks.");

        foreach (var activity in _activities)
        {
            var result = await activity.RunAsync(cancellationToken);
            if (result.IsFailed)
            {
                return result;
            }
        }

        _logger.LogInformation("Initialisation complete: all checks passed.");
        await _healthCheckService.SetHealthyAsync(nameof(InitialisationService), cancellationToken);

        return Result.Ok();
    }
}
