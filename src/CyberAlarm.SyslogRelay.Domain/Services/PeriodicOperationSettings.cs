namespace CyberAlarm.SyslogRelay.Domain.Services;

public record PeriodicOperationSettings(TimeSpan Interval, Func<CancellationToken, Task> Operation, string OperationDescription);
