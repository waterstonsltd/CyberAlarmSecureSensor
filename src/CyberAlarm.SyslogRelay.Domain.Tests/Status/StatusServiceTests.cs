using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using FluentResults;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Status;

public sealed class StatusServiceTests
{
    private readonly StatusServiceBuilder _builder = new();

    [Fact]
    public async Task GetStatusAsync_should_return_status_when_data_is_read_from_file()
    {
        // Arrange
        var status = new RelayStatusBuilder().Build();

        _builder.FileManager
            .DeserialiseFromFileAsync<RelayStatus>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(status);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.GetStatusAsync(CancellationToken.None);

        // Assert
        Assert.Equal(status, result);
        await _builder.FileManager.Received(1).DeserialiseFromFileAsync<RelayStatus>(Arg.Any<string>(), CancellationToken.None);
        await _builder.StatusClient.Received(0).GetStatusAsync(CancellationToken.None);
    }

    [Fact]
    public async Task GetStatusAsync_should_throw_when_no_data_is_read_from_file()
    {
        // Arrange
        _builder.FileManager
            .DeserialiseFromFileAsync<RelayStatus>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(default(RelayStatus));

        var unitUnderTest = _builder.Build();

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await unitUnderTest.GetStatusAsync(CancellationToken.None));

        Assert.Equal("Failed to load status from file.", exception.Message);
        await _builder.StatusClient.Received(0).GetStatusAsync(CancellationToken.None);
    }

    [Fact]
    public async Task RefreshStatusAsync_should_persist_and_return_status_when_calling_status_client_succeeds()
    {
        // Arrange
        var status = new RelayStatusBuilder().Build();

        _builder.StatusClient
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(status);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RefreshStatusAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(status, result.Value);
        await _builder.StatusClient.Received(1).GetStatusAsync(CancellationToken.None);
        await _builder.FileManager.Received(1).SerialiseToFileAsync(status, Arg.Any<string>(), CancellationToken.None);
    }

    [Fact]
    public async Task RefreshStatusAsync_should_fail_when_calling_status_client_fails_and_no_data_is_read_from_file()
    {
        // Arrange
        _builder.StatusClient
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Fail());

        _builder.FileManager
            .DeserialiseFromFileAsync<RelayStatus>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(default(RelayStatus));

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RefreshStatusAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.StartsWith("Failed to refresh status from endpoint and file:", result.ErrorMessage);
    }

    [Fact]
    public async Task RefreshStatusAsync_should_return_status_when_calling_status_client_fails_and_data_is_read_from_file()
    {
        // Arrange
        var status = new RelayStatusBuilder().Build();

        _builder.StatusClient
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Fail());

        _builder.FileManager
            .DeserialiseFromFileAsync<RelayStatus>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(status);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RefreshStatusAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(status, result.Value);
        await _builder.StatusClient.Received(1).GetStatusAsync(CancellationToken.None);
        await _builder.FileManager.Received(0).SerialiseToFileAsync(status, Arg.Any<string>(), CancellationToken.None);
    }
}
