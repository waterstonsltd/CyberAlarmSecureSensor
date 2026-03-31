namespace CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;

public interface IScheduler
{
    Task RunOnSchedule(TimeSpan interval, Func<CancellationToken, Task> task, CancellationToken stoppingToken);
}
