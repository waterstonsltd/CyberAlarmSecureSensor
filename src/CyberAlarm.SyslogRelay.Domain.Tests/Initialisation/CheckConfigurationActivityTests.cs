using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Tests;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Initialisation;

public sealed class CheckConfigurationActivityTests
{
    private readonly CheckConfigurationActivityBuilder _builder = new();

    [Theory]
    [InlineData("", "Build version is not configured.")]
    [InlineData("x", "Build version 'x' could not be parsed.")]
    public async Task RunAsync_should_fail_when_build_version_is_missing_or_not_parsable(string buildVersion, string errorMessage)
    {
        // Arrange
        var options = new RelayOptionsBuilder()
            .WithBuildVersion(buildVersion)
            .Build();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal(errorMessage, result.ErrorMessage);
    }

    [Fact]
    public async Task RunAsync_should_fail_when_status_endpoint_is_missing()
    {
        // Arrange
        var options = new RelayOptionsBuilder()
            .WithStatusEndpoint(string.Empty)
            .Build();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Status endpoint is not configured.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("")]
    [InlineData("x")]
    public async Task RunAsync_should_fail_when_registration_token_is_missing(string registrationToken)
    {
        // Arrange
        var options = new RelayOptionsBuilder()
            .WithRegistrationToken(registrationToken)
            .Build();

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
    }

    [Fact]
    public async Task RunAsync_should_succeed_when_configuration_is_valid()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
    }
}
