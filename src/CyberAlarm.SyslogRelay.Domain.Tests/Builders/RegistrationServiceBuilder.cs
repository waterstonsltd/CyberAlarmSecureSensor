using CyberAlarm.SyslogRelay.Domain.Registration;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.State;
using FluentResults;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Builders;

internal sealed class RegistrationServiceBuilder
{
    private RelayOptions _options = new RelayOptionsBuilder().Build();

    public RegistrationServiceBuilder()
    {
        PlatformService = Substitute.For<IPlatformService>();

        RegistrationClient = Substitute.For<IRegistrationClient>();
        RegistrationClient
            .PostRegistrationAsync(Arg.Any<RegistrationRequest>(), Arg.Any<CancellationToken>())
            .Returns(Result.Ok());

        RsaKeyProvider = Substitute.For<IRsaKeyProvider>();
        RsaKeyProvider
            .KeysExist()
            .Returns(true);

        StateService = Substitute.For<IStateService>();
        StateService
            .GetStateAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStateBuilder().WithIsRegistered(false).Build());

        Logger = Substitute.For<ILogger<RegistrationService>>();
    }

    public IPlatformService PlatformService { get; }

    public IRegistrationClient RegistrationClient { get; }

    public IRsaKeyProvider RsaKeyProvider { get; }

    public IStateService StateService { get; }

    public ILogger<RegistrationService> Logger { get; }

    public RegistrationService Build() =>
        new(PlatformService, RegistrationClient, RsaKeyProvider, StateService, Options.Create(_options), Logger);

    public RegistrationServiceBuilder WithOptions(RelayOptions options)
    {
        _options = options;
        return this;
    }
}
