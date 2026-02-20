using CyberAlarm.SyslogRelay.Domain.Initialisation;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class InitialisationServiceBuilder
{
    private readonly List<IStartupActivity> _activities = [];

    public InitialisationServiceBuilder() =>
        Logger = Substitute.For<ILogger<InitialisationService>>();

    public List<IStartupActivity> Activities => _activities;

    public ILogger<InitialisationService> Logger { get; }

    public InitialisationService Build() => new(_activities, Logger);

    public InitialisationServiceBuilder AddFailedActivity()
    {
        _activities.Add(NewActivityReturning(Result.Fail()));
        return this;
    }

    public InitialisationServiceBuilder AddSuccessfulActivity()
    {
        _activities.Add(NewActivityReturning(Result.Ok()));
        return this;
    }

    private static IStartupActivity NewActivityReturning(Result result)
    {
        var activity = Substitute.For<IStartupActivity>();
        activity
            .RunAsync(Arg.Any<CancellationToken>())
            .Returns(result);

        return activity;
    }
}
