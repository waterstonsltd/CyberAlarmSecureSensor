using System.Net;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Status;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Status;

public sealed class StatusClientTests : IDisposable
{
    private readonly StatusClientBuilder _builder = new();

    public void Dispose() => _builder.Dispose();

    [Fact]
    public async Task GetStatusAsync_should_fail_with_not_modified_warning_when_NotModified_status_code_is_returned()
    {
        // Arrange
        using var notModifiedResponse = new HttpResponseMessage(HttpStatusCode.NotModified);
        var unitUnderTest = _builder
            .WithResponse(notModifiedResponse)
            .Build();

        // Act
        var result = await unitUnderTest.GetStatusAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.True(result.HasError<StatusNotModifiedWarning>());
    }

    [Fact]
    public async Task GetStatusAsync_should_fail_when_success_status_code_is_not_returned()
    {
        // Arrange
        using var errorResponse = new HttpResponseMessage(HttpStatusCode.InternalServerError);
        var unitUnderTest = _builder
            .WithResponse(errorResponse)
            .Build();

        // Act
        var result = await unitUnderTest.GetStatusAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to get status.", result.ErrorMessage);
    }

    [Fact]
    public async Task GetStatusAsync_should_fail_when_exception_is_thrown()
    {
        // Arrange
        using var invalidResponse = new HttpResponseMessage()
        {
            StatusCode = HttpStatusCode.OK,
            Content = new StringContent("{}"),
        };

        var unitUnderTest = _builder
            .WithResponse(invalidResponse)
            .Build();

        // Act
        var result = await unitUnderTest.GetStatusAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.StartsWith("Error occurred when calling status endpoint:", result.ErrorMessage);
    }

    [Fact]
    public async Task GetStatusAsync_should_return_status_when_success_status_code_is_returned()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.GetStatusAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
    }
}
