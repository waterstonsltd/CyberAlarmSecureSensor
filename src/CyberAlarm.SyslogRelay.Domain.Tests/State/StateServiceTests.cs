using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.State;

public sealed class StateServiceTests
{
    private readonly StateServiceBuilder _builder = new();

    [Fact]
    public async Task GetStateAsync_should_set_and_return_empty_state_when_no_data_is_read_from_file()
    {
        // Arrange
        _builder.FileManager
            .DeserialiseFromFileAsync<RelayState>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(default(RelayState));

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.GetStateAsync(CancellationToken.None);

        // Assert
        Assert.Equal(RelayState.Empty, result);
        await _builder.FileManager.Received(1).SerialiseToFileAsync(RelayState.Empty, Arg.Any<string>(), CancellationToken.None);
    }

    [Fact]
    public async Task GetStateAsync_should_return_state_when_data_is_read_from_file()
    {
        // Arrange
        var state = new RelayStateBuilder().Build();

        _builder.FileManager
            .DeserialiseFromFileAsync<RelayState>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(state);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.GetStateAsync(CancellationToken.None);

        // Assert
        Assert.Equal(state, result);
    }

    [Fact]
    public async Task SetStateAsync_should_write_state_to_file_and_return_state()
    {
        // Arrange
        var state = new RelayStateBuilder().Build();
        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.SetStateAsync(state, CancellationToken.None);

        // Assert
        Assert.Equal(state, result);
        await _builder.FileManager.Received(1).SerialiseToFileAsync(state, Arg.Any<string>(), CancellationToken.None);
    }

    [Fact]
    public async Task UpdateStateAsync_should_update_current_state_and_write_updated_state_to_file_and_return_state()
    {
        // Arrange
        var state = new RelayStateBuilder().Build();
        var updatedState = state with { StatusETag = string.Empty };

        _builder.FileManager
            .DeserialiseFromFileAsync<RelayState>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(state);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.UpdateStateAsync(state => updatedState, CancellationToken.None);

        // Assert
        Assert.Equal(updatedState, result);
        Assert.Equal(string.Empty, result.StatusETag);
        await _builder.FileManager.Received(1).SerialiseToFileAsync(updatedState, Arg.Any<string>(), CancellationToken.None);
    }
}
