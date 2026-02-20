using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Initialisation;

public sealed class InitialisationServiceTests
{
    private readonly InitialisationServiceBuilder _builder = new();

    [Fact]
    public async Task InitialiseAsync_should_run_all_assigned_activities()
    {
        // Arrange
        var unitUnderTest = _builder
            .AddSuccessfulActivity()
            .AddSuccessfulActivity()
            .AddSuccessfulActivity()
            .Build();

        // Act
        var result = await unitUnderTest.InitialiseAsync(CancellationToken.None);

        // Assert
        _builder.Activities.ForEach(x => x.Received(1).RunAsync(CancellationToken.None));
    }

    [Fact]
    public async Task InitialiseAsync_should_fail_when_an_activity_fails()
    {
        // Arrange
        var unitUnderTest = _builder
            .AddSuccessfulActivity()
            .AddSuccessfulActivity()
            .AddFailedActivity()
            .Build();

        // Act
        var result = await unitUnderTest.InitialiseAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsFailed);
    }

    [Fact]
    public async Task InitialiseAsync_should_succeed_when_all_activities_succeed()
    {
        // Arrange
        var unitUnderTest = _builder
            .AddSuccessfulActivity()
            .AddSuccessfulActivity()
            .AddSuccessfulActivity()
            .Build();

        // Act
        var result = await unitUnderTest.InitialiseAsync(CancellationToken.None);

        // Assert
        Assert.True(result.IsSuccess);
    }
}
