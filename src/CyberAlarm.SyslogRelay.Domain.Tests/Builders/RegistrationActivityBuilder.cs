using CyberAlarm.SyslogRelay.Domain.Initialisation;
using CyberAlarm.SyslogRelay.Domain.Registration;
using FluentResults;
using Microsoft.Extensions.Logging;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class RegistrationActivityBuilder
{
    public RegistrationActivityBuilder()
    {
        RegistrationService = Substitute.For<IRegistrationService>();
        RegistrationService
            .RegisterAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Ok());

        Logger = Substitute.For<ILogger<RegistrationActivity>>();
    }

    public IRegistrationService RegistrationService { get; }

    public ILogger<RegistrationActivity> Logger { get; }

    public RegistrationActivity Build() => new(RegistrationService, Logger);
}
