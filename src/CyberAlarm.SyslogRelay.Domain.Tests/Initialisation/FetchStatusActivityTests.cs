using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Tests;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Initialisation;

public sealed class FetchStatusActivityTests
{
    private readonly FetchStatusActivityBuilder _builder = new();

    [Fact]
    public async Task RunAsync_should_fail_when_refreshing_status_fails()
    {
        // Arrange
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Fail());

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
    }

    [Fact]
    public async Task RunAsync_should_fail_when_minimum_supported_version_is_not_parsable()
    {
        // Arrange
        var status = new RelayStatusBuilder()
            .WithMinimumSupportedVersion("x")
            .Build();

        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(status);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Minimum supported version 'x' could not be parsed.", result.ErrorMessage);
    }

    [Fact]
    public async Task RunAsync_should_fail_when_build_version_is_less_than_minimum_supported_version()
    {
        // Arrange
        var options = new RelayOptionsBuilder()
            .WithBuildVersion("1.0.0")
            .Build();

        var status = new RelayStatusBuilder()
            .WithMinimumSupportedVersion("1.0.1")
            .Build();

        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(status);

        var unitUnderTest = _builder
            .WithOptions(options)
            .Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Build version '1.0.0' is not supported. Minimum supported version is '1.0.1'.", result.ErrorMessage);
    }

    [Fact]
    public async Task RunAsync_should_fail_when_current_version_is_not_parsable()
    {
        // Arrange
        var status = new RelayStatusBuilder()
            .WithCurrentVersion("x")
            .Build();

        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(status);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Current version 'x' could not be parsed.", result.ErrorMessage);
    }

    [Fact]
    public async Task RunAsync_should_succeed_when_refreshing_status_and_version_checks_succeeds()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
    }
}
