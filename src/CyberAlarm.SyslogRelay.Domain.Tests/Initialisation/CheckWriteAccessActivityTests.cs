using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Services;
using CyberAlarm.SyslogRelay.Domain.Tests;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Initialisation;

public sealed class CheckWriteAccessActivityTests
{
    private readonly CheckWriteAccessActivityBuilder _builder = new();

    [Fact]
    public async Task RunAsync_should_fail_when_platform_is_not_supported()
    {
        // Arrange
        _builder.PlatformService
            .GetPlatformType()
            .Returns(PlatformType.NotSupported);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);
        // Assert

        Assert.True(result.IsFailed);
        Assert.Equal("Current platform is not supported.", result.ErrorMessage);
    }

    [Fact]
    public async Task RunAsync_should_fail_when_volume_is_not_writable()
    {
        // Arrange
        var dataPath = Guid.NewGuid().ToString();

        _builder.FileManager
            .GetDataPath()
            .Returns(dataPath);

        _builder.FileManager
            .CanWriteFile(Arg.Any<string>())
            .Returns(false);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal($"Data volume '{dataPath}' is not writable.", result.ErrorMessage);
    }

    [Fact]
    public async Task RunAsync_should_succeed_when_write_access_checks_pass()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.RunAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
    }
}
