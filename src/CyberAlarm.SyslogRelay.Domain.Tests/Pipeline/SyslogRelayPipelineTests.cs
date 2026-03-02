using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Pipeline;

public sealed class SyslogRelayPipelineTests
{
    private readonly SyslogRelayPipelineBuilder<Guid> _builder = new();

    [Fact]
    public async Task EnqueueAsync_should_enqueue_input_into_initial_stage()
    {
        // Arrange
        var input = Guid.NewGuid();
        var unitUnderTest = _builder.Build();

        // Act
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);

        // Assert
        await _builder.InitialStage.Received(1).EnqueueAsync(input, CancellationToken.None);
    }

    [Fact]
    public async Task StartAsync_should_start_all_linked_stages()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);

        // Assert
        await _builder.InitialStage.Received(1).StartAsync(CancellationToken.None);
        await _builder.MiddleStage.Received(1).StartAsync(CancellationToken.None);
        await _builder.FinalStage.Received(1).StartAsync(CancellationToken.None);
    }

    [Fact]
    public async Task StopAsync_should_stop_all_linked_stages()
    {
        // Arrange
        var unitUnderTest = _builder.Build();

        // Act
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        await _builder.InitialStage.Received(1).StopAsync(CancellationToken.None);
        await _builder.MiddleStage.Received(1).StopAsync(CancellationToken.None);
        await _builder.FinalStage.Received(1).StopAsync(CancellationToken.None);
    }
}
