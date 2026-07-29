using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.State;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.State;

public sealed class CachedStateServiceTests
{
    private readonly CachedStateServiceBuilder _builder = new();

    [Fact]
    public async Task GetStateAsync_should_call_inner_service_and_return_state_when_state_is_not_cached()
    {
        // Arrange
        var state = new RelayStateBuilder().Build();

        _builder.StateService
            .GetStateAsync(Arg.Any<CancellationToken>())
            .Returns(state);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.GetStateAsync(CancellationToken.None);

        // Assert
        Assert.Equal(state, result);
        await _builder.StateService.Received(1).GetStateAsync(CancellationToken.None);
    }

    [Fact]
    public async Task GetStateAsync_should_not_call_inner_service_and_return_cached_state()
    {
        // Arrange
        var state = new RelayStateBuilder().Build();

        _builder.StateService
            .SetStateAsync(state, Arg.Any<CancellationToken>())
            .Returns(state);

        var unitUnderTest = _builder.Build();
        await unitUnderTest.SetStateAsync(state, CancellationToken.None);

        // Act
        var result = await unitUnderTest.GetStateAsync(CancellationToken.None);

        // Assert
        Assert.Equal(state, result);
        await _builder.StateService.Received(0).GetStateAsync(CancellationToken.None);
    }

    [Fact]
    public async Task SetStateAsync_should_call_inner_service_and_cache_the_provided_status()
    {
        // Arrange
        var state = new RelayStateBuilder().Build();

        _builder.StateService
            .SetStateAsync(state, Arg.Any<CancellationToken>())
            .Returns(state);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.SetStateAsync(state, CancellationToken.None);

        // Assert
        Assert.Equal(state, result);
        Assert.Equal(state, await unitUnderTest.GetStateAsync(CancellationToken.None));
        await _builder.StateService.Received(1).SetStateAsync(state, CancellationToken.None);
    }

    [Fact]
    public async Task UpdateStateAsync_should_call_inner_service_and_cache_the_provided_status_when_state_is_not_cached()
    {
        // Arrange
        var state = new RelayStateBuilder().Build();
        var updatedState = state with { StatusETag = string.Empty };

        _builder.StateService
            .UpdateStateAsync(Arg.Any<Func<RelayState, RelayState>>(), Arg.Any<CancellationToken>())
            .Returns(updatedState);

        var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.UpdateStateAsync(state => updatedState, CancellationToken.None);

        // Assert
        Assert.Equal(updatedState, result);
        Assert.Equal(updatedState, await unitUnderTest.GetStateAsync(CancellationToken.None));
        Assert.Equal(string.Empty, result.StatusETag);
        await _builder.StateService.Received(1).UpdateStateAsync(Arg.Any<Func<RelayState, RelayState>>(), CancellationToken.None);
        await _builder.StateService.Received(0).SetStateAsync(Arg.Any<RelayState>(), CancellationToken.None);
    }

    [Fact]
    public async Task UpdateStateAsync_should_run_updater_and_call_inner_service_and_cache_the_provided_status_when_state_is_cached()
    {
        // Arrange
        var state = new RelayStateBuilder().Build();
        var updatedState = state with { StatusETag = string.Empty };

        _builder.StateService
            .SetStateAsync(Arg.Any<RelayState>(), Arg.Any<CancellationToken>())
            .Returns(state, updatedState);

        var unitUnderTest = _builder.Build();
        await unitUnderTest.SetStateAsync(state, CancellationToken.None);

        // Act
        var result = await unitUnderTest.UpdateStateAsync(state => updatedState, CancellationToken.None);

        // Assert
        Assert.Equal(updatedState, result);
        Assert.Equal(updatedState, await unitUnderTest.GetStateAsync(CancellationToken.None));
        Assert.Equal(string.Empty, result.StatusETag);
        await _builder.StateService.Received(0).UpdateStateAsync(Arg.Any<Func<RelayState, RelayState>>(), CancellationToken.None);
        await _builder.StateService.Received(2).SetStateAsync(Arg.Any<RelayState>(), CancellationToken.None);
    }
}
