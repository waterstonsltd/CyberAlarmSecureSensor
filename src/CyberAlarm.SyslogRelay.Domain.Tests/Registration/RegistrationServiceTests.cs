using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Registration;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Registration;

public sealed class RegistrationServiceTests
{
    private readonly RegistrationServiceBuilder _builder = new();

    [Fact]
    public async Task RegisterAsync_should_fail_when_already_registered_and_registration_token_is_missing_from_state()
    {
        // Arrange
        _builder.StateService
            .GetStateAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStateBuilder()
                .WithIsRegistered(true)
                .WithRegistrationToken(string.Empty)
                .Build());

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RegisterAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Registration token missing from the state.", result.ErrorMessage);
        await _builder.StateService.Received(1).GetStateAsync(CancellationToken.None);
        await _builder.RegistrationClient.Received(0).PostRegistrationAsync(Arg.Any<RegistrationRequest>(), CancellationToken.None);
    }

    [Fact]
    public async Task RegisterAsync_should_fail_when_already_registered_and_keys_are_missing()
    {
        // Arrange
        _builder.StateService
            .GetStateAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStateBuilder().WithIsRegistered(true).Build());

        _builder.RsaKeyProvider
            .KeysExist()
            .Returns(false);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RegisterAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Registered already but missing RSA keys.", result.ErrorMessage);
        await _builder.StateService.Received(1).GetStateAsync(CancellationToken.None);
        await _builder.RegistrationClient.Received(0).PostRegistrationAsync(Arg.Any<RegistrationRequest>(), CancellationToken.None);
    }

    [Fact]
    public async Task RegisterAsync_should_not_call_registration_client_when_already_registered_and_registration_token_has_not_changed()
    {
        // Arrange
        _builder.StateService
            .GetStateAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStateBuilder()
                .WithIsRegistered(true)
                .WithRegistrationToken("1.same.token")
                .Build());

        var options = new RelayOptionsBuilder()
            .WithRegistrationToken("1.same.token")
            .Build();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        var result = await unitUnderTest.RegisterAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        await _builder.StateService.Received(1).GetStateAsync(CancellationToken.None);
        await _builder.RegistrationClient.Received(0).PostRegistrationAsync(Arg.Any<RegistrationRequest>(), CancellationToken.None);
    }

    [Fact]
    public async Task RegisterAsync_should_call_registration_client_when_already_registered_and_registration_token_has_changed()
    {
        // Arrange
        _builder.StateService
            .GetStateAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStateBuilder()
                .WithIsRegistered(true)
                .WithRegistrationToken("1.old.token")
                .Build());

        var options = new RelayOptionsBuilder()
            .WithRegistrationToken("1.new.token")
            .Build();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        var result = await unitUnderTest.RegisterAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        await _builder.StateService.Received(1).GetStateAsync(CancellationToken.None);
        await _builder.RegistrationClient.Received(1).PostRegistrationAsync(Arg.Any<RegistrationRequest>(), CancellationToken.None);
    }

    [Fact]
    public async Task RegisterAsync_should_fail_when_not_yet_registered_and_calling_registration_client_fails()
    {
        // Arrange
        _builder.RegistrationClient
            .PostRegistrationAsync(Arg.Any<RegistrationRequest>(), Arg.Any<CancellationToken>())
            .Returns(Result.Fail());

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RegisterAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        await _builder.StateService.Received(1).GetStateAsync(CancellationToken.None);
        await _builder.RegistrationClient.Received(1).PostRegistrationAsync(Arg.Any<RegistrationRequest>(), CancellationToken.None);
    }

    [Fact]
    public async Task RegisterAsync_should_update_state_and_succeed_when_calling_registration_client_succeeds()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RegisterAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        await _builder.StateService.Received(1).GetStateAsync(CancellationToken.None);
        await _builder.RegistrationClient.Received(1).PostRegistrationAsync(Arg.Any<RegistrationRequest>(), CancellationToken.None);
        await _builder.RsaKeyProvider.Received(1).GetPublicKeyPem(CancellationToken.None);
        await _builder.StateService.Received(1).SetStateAsync(Arg.Any<RelayState>(), CancellationToken.None);
    }
}
