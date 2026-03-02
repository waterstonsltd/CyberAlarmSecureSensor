using CyberAlarm.SyslogRelay.Domain.Upload.Scheduling;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class SchedulerBuilder : IDisposable
{
    public IExecutableService Service { get; }
    public ILogger<Scheduler> Logger { get; }
    private IPeriodicTimer _periodicTimer;
    private readonly ScheduleOptions _options;

    public SchedulerBuilder()
    {
        Service = Substitute.For<IExecutableService>();
        Logger = Substitute.For<ILogger<Scheduler>>();
        _periodicTimer = new MockPeriodicTimerBuilder().RunOnce().Build();
        _options = new ScheduleOptions();
    }

    public SchedulerBuilder WithPeriodicTimer(IPeriodicTimer periodicTimer)
    {
        _periodicTimer = periodicTimer;
        return this;
    }

    public Scheduler Build() => new(_interval => _periodicTimer, Logger);

    public void Dispose()
    {
        _periodicTimer.Dispose();
    }
}
