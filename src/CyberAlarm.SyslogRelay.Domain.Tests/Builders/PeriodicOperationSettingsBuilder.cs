using CyberAlarm.SyslogRelay.Domain.Services;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class PeriodicOperationSettingsBuilder
{
    public PeriodicOperationSettingsBuilder()
    {
        Interval = TimeSpan.FromMilliseconds(10);
        Operation = Substitute.For<Func<CancellationToken, Task>>();
        OperationDescription = Guid.NewGuid().ToString();
    }

    public TimeSpan Interval { get; private set; }

    public Func<CancellationToken, Task> Operation { get; private set; }

    public string OperationDescription { get; }

    public PeriodicOperationSettings Build() => new(Interval, Operation, OperationDescription);

    public PeriodicOperationSettingsBuilder WithInterval(TimeSpan interval)
    {
        Interval = interval;
        return this;
    }

    public PeriodicOperationSettingsBuilder WithOperation(Func<CancellationToken, Task>? operation)
    {
        Operation = operation!;
        return this;
    }
}
