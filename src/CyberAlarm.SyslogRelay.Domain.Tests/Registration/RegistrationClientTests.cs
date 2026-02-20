using System.Net;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Registration;

public sealed class RegistrationClientTests : IDisposable
{
    private readonly RegistrationClientBuilder _builder = new();

    public void Dispose() => _builder.Dispose();

    [Fact]
    public async Task PostRegistrationAsync_should_fail_when_success_status_code_is_not_returned()
    {
        // Arrange
        using var errorResponse = new HttpResponseMessage(HttpStatusCode.InternalServerError);
        var unitUnderTest = _builder
            .WithResponse(errorResponse)
            .Build();

        var request = new RegistrationRequestBuilder().Build();

        // Act
        var result = await unitUnderTest.PostRegistrationAsync(request, CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to register: received InternalServerError.", result.ErrorMessage);
    }

    [Fact]
    public async Task PostRegistrationAsync_should_fail_when_exception_is_thrown()
    {
        // Arrange
        var unitUnderTest = _builder
            .WithResponse(() => throw new HttpRequestException())
            .Build();

        var request = new RegistrationRequestBuilder().Build();

        // Act
        var result = await unitUnderTest.PostRegistrationAsync(request, CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
        Assert.StartsWith("Error occurred when calling register endpoint:", result.ErrorMessage);
    }

    [Fact]
    public async Task PostRegistrationAsync_should_succeed_when_success_status_code_is_returned()
    {
        // Arrange
        var unitUnderTest = _builder.Build();
        var request = new RegistrationRequestBuilder().Build();

        // Act
        var result = await unitUnderTest.PostRegistrationAsync(request, CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
    }
}
