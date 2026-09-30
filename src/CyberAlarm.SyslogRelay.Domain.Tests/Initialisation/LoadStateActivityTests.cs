using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Tests;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Initialisation;

public sealed class LoadStateActivityTests
{
    private readonly LoadStateActivityBuilder _builder = new();

    [Fact]
    public async Task RunAsync_should_load_state()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        await _builder.StateService.Received(1).GetStateAsync(CancellationToken.None);
    }

    [Fact]
    public async Task RunAsync_should_fail_when_upload_is_blocked()
    {
        // Arrange
        _builder.StateService
            .GetStateAsync(Arg.Any<CancellationToken>())
            .Returns(new RelayStateBuilder().WithIsUploadBlocked(true).Build());

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Upload is blocked.", result.ErrorMessage);
    }
}
