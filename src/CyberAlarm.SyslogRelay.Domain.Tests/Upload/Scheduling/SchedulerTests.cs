using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using CyberAlarm.SyslogRelay.Domain.Upload.Services;
using CyberAlarm.SyslogRelay.Tests.Common;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Upload.Scheduling;

public sealed class SchedulerTests : IDisposable
{
    private readonly SchedulerBuilder _builder;

    public SchedulerTests()
    {
        _builder = new SchedulerBuilder();
    }

    [Fact]
    public async Task ExecutesServiceOnStartup()
    {
        var systemUnderTest = _builder.Build();
        var callCollector = Substitute.For<IFileSelector>();
        Func<CancellationToken, Task> task = callCollector.SelectFilesAsync;
        var cancellationTokenSource = new CancellationTokenSource();

        await systemUnderTest.RunOnSchedule(
            TimeSpan.FromMilliseconds(100),
            task,
            cancellationTokenSource.Token
            );

        await callCollector.Received().SelectFilesAsync(cancellationTokenSource.Token);
    }

    [Fact]
    public async Task ExecutesServiceOnTimerTick()
    {
        var periodicTimer = new MockPeriodicTimerBuilder();
        var systemUnderTest = _builder
            .WithPeriodicTimer(periodicTimer.Build())
            .Build();
        var callCollector = Substitute.For<IFileSelector>();
        Func<CancellationToken, Task> task = callCollector.SelectFilesAsync;
        var cancellationTokenSource = new CancellationTokenSource();

        var executeTask = systemUnderTest.RunOnSchedule(
            TimeSpan.FromMilliseconds(100),
            task,
            cancellationTokenSource.Token
            );
        await periodicTimer.WaitUntilNextTickRequested();
        periodicTimer.Tick();
        await periodicTimer.WaitUntilNextTickRequested();
        periodicTimer.Complete();
        await executeTask;

        await callCollector.Received(2).SelectFilesAsync(cancellationTokenSource.Token);
    }

    [Fact]
    public async Task StopsOnCancellation()
    {
        var periodicTimer = new MockPeriodicTimerBuilder();
        var cancellationTokenSource = new CancellationTokenSource();
        var callCollector = Substitute.For<IFileSelector>();
        Func<CancellationToken, Task> task = callCollector.SelectFilesAsync;
        var systemUnderTest = _builder
            .WithPeriodicTimer(periodicTimer.Build())
            .Build();

        var executeTask = systemUnderTest.RunOnSchedule(
            TimeSpan.FromMilliseconds(100),
            task,
            cancellationTokenSource.Token
            );
        await periodicTimer.WaitUntilNextTickRequested();
        periodicTimer.Tick();
        periodicTimer.Cancel(cancellationTokenSource);
        await executeTask;

        Assert.Contains(_builder.Logger.ReceivedLogs(),
            log => log.LogLevel == LogLevel.Error && log.Message == "Scheduled service cancellation requested");
    }

    public void Dispose()
    {
        _builder.Dispose();
    }
}
