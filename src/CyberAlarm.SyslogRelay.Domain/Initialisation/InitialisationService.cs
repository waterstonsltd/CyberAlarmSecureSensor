using CyberAlarm.SyslogRelay.Domain.Initialisation;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Initialisation;

public sealed class InitialisationService(
    IEnumerable<IStartupActivity> activities,
    ILogger<InitialisationService> logger)
{
    private readonly IEnumerable<IStartupActivity> _activities = activities;
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
        return Result.Ok();
    }
}
