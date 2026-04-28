using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;

public class Scheduler(
    Func<TimeSpan, IPeriodicTimer> timerFactory,
    ILogger<Scheduler> logger) : IScheduler
{
    private readonly ILogger<Scheduler> _logger = logger;

    public async Task RunOnSchedule(TimeSpan interval, Func<CancellationToken, Task> task, CancellationToken stoppingToken)
    {
        var timer = timerFactory(interval);

        await task(stoppingToken);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await task(stoppingToken);
            }
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogError(ex, "Scheduled service cancellation requested");
        }
    }
}
