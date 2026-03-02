using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using FluentResults;
using NSubstitute.ExceptionExtensions;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Status;

public sealed class CachedStatusServiceTests
{
    private readonly CachedStatusServiceBuilder _builder = new();

    [Fact]
    public async Task GetStatusAsync_should_throw_when_calling_inner_service_throws()
    {
        // Arrange
        _builder.StatusService
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync<InvalidOperationException>();

        var unitUnderTest = _builder.Build();

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unitUnderTest.GetStatusAsync(CancellationToken.None));

        await _builder.StatusService.Received(1).GetStatusAsync(CancellationToken.None);
    }

    [Fact]
    public async Task GetStatusAsync_should_call_inner_service_and_return_status()
    {
        // Arrange
        var status = new RelayStatusBuilder().Build();

        _builder.StatusService
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(status);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.GetStatusAsync(CancellationToken.None);

        // Assert
        Assert.Equal(status, result);
        await _builder.StatusService.Received(1).GetStatusAsync(CancellationToken.None);
    }

    [Fact]
    public async Task GetStatusAsync_should_not_call_inner_service_and_return_cached_status()
    {
        // Arrange
        var status = new RelayStatusBuilder().Build();

        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(status);

        var unitUnderTest = _builder.Build();
        await unitUnderTest.RefreshStatusAsync(CancellationToken.None);

        // Act
        var result = await unitUnderTest.GetStatusAsync(CancellationToken.None);

        // Assert
        Assert.Equal(status, result);
        await _builder.StatusService.Received(0).GetStatusAsync(CancellationToken.None);
    }

    [Fact]
    public async Task RefreshStatusAsync_should_fail_when_calling_inner_service_fails()
    {
        // Arrange
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Fail());

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RefreshStatusAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        await _builder.StatusService.Received(1).RefreshStatusAsync(CancellationToken.None);
    }

    [Fact]
    public async Task RefreshStatusAsync_should_cache_status_when_calling_inner_service_succeeds()
    {
        // Arrange
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStatusBuilder().Build());

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RefreshStatusAsync(CancellationToken.None);

        // Assert
        var expectedStatus = await unitUnderTest.GetStatusAsync(CancellationToken.None);
        Assert.Equal(expectedStatus, result.Value);
        await _builder.StatusService.Received(1).RefreshStatusAsync(CancellationToken.None);
        await _builder.StatusService.Received(0).GetStatusAsync(CancellationToken.None);
    }
}
