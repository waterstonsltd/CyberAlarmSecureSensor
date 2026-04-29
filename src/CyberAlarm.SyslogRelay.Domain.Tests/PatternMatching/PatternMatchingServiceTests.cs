using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Status.Models;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;
using FluentResults;
using StatusPattern = CyberAlarm.SyslogRelay.Common.Status.Models.Pattern;

namespace CyberAlarm.SyslogRelay.Domain.Tests.PatternMatching;

public sealed class PatternMatchingServiceTests : IDisposable
{
    private readonly PatternMatchingServiceBuilder _builder = new();

    public void Dispose() => _builder.Dispose();

    [Fact]
    public async Task MatchPatternAsync_should_return_null_when_refresh_succeeds_and_status_has_no_patterns()
    {
        // Arrange
        var status = new RelayStatusBuilder().Build();
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Ok(status));

        using var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.MatchPatternAsync("test log", CancellationToken.None);

        // Assert
        Assert.Null(result);
        await _builder.StatusService.Received(1).RefreshStatusAsync(CancellationToken.None);
        await _builder.StatusService.DidNotReceive().GetStatusAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task MatchPatternAsync_should_fall_back_to_GetStatusAsync_when_refresh_fails()
    {
        // Arrange
        var status = new RelayStatusBuilder().Build();
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Fail("refresh failed"));
        _builder.StatusService
            .GetStatusAsync(Arg.Any<CancellationToken>())
            .Returns(status);

        using var unitUnderTest = _builder.Build();

        // Act
        await unitUnderTest.MatchPatternAsync("test log", CancellationToken.None);

        // Assert
        await _builder.StatusService.Received(1).RefreshStatusAsync(CancellationToken.None);
        await _builder.StatusService.Received(1).GetStatusAsync(CancellationToken.None);
    }

    [Fact]
    public async Task MatchPatternAsync_should_return_match_when_pattern_matches()
    {
        // Arrange
        var patternName = Guid.NewGuid().ToString();
        var statusPattern = new StatusPattern
        {
            Name = patternName,
            ParserClass = "TestParser",
            Priority = 100,
            Rules = [new PatternRule { Type = RuleType.StartsWith, Values = ["MATCH:"] }],
        };
        var status = new RelayStatusBuilder().WithPatterns(statusPattern).Build();
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Ok(status));
        _builder.ParserFactory
            .Create(Arg.Any<string>(), Arg.Any<object?>())
            .Returns(Substitute.For<IParser>());

        using var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.MatchPatternAsync("MATCH: test log", CancellationToken.None);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(patternName, result.PatternName);
    }

    [Fact]
    public async Task MatchPatternAsync_should_return_null_when_no_pattern_matches()
    {
        // Arrange
        var statusPattern = new StatusPattern
        {
            Name = Guid.NewGuid().ToString(),
            ParserClass = "TestParser",
            Priority = 100,
            Rules = [new PatternRule { Type = RuleType.StartsWith, Values = ["NOMATCH:"] }],
        };
        var status = new RelayStatusBuilder().WithPatterns(statusPattern).Build();
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Ok(status));
        _builder.ParserFactory
            .Create(Arg.Any<string>(), Arg.Any<object?>())
            .Returns(Substitute.For<IParser>());

        using var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.MatchPatternAsync("test log", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task MatchPatternAsync_should_not_call_status_service_on_second_call()
    {
        // Arrange
        var status = new RelayStatusBuilder().Build();
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Ok(status));

        using var unitUnderTest = _builder.Build();

        // Act
        await unitUnderTest.MatchPatternAsync("test log", CancellationToken.None);
        await unitUnderTest.MatchPatternAsync("test log", CancellationToken.None);

        // Assert
        await _builder.StatusService.Received(1).RefreshStatusAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task MatchPatternAsync_should_throw_when_patterns_have_duplicate_names()
    {
        // Arrange
        var patternName = Guid.NewGuid().ToString();
        var duplicate1 = new StatusPattern { Name = patternName, ParserClass = "TestParser" };
        var duplicate2 = new StatusPattern { Name = patternName, ParserClass = "TestParser" };
        var status = new RelayStatusBuilder().WithPatterns(duplicate1, duplicate2).Build();
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Ok(status));

        using var unitUnderTest = _builder.Build();

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await unitUnderTest.MatchPatternAsync("test log", CancellationToken.None));
    }

    [Fact]
    public async Task MatchPatternAsync_should_skip_pattern_when_parser_is_null()
    {
        // Arrange
        var statusPattern = new StatusPattern
        {
            Name = Guid.NewGuid().ToString(),
            ParserClass = "UnknownParser",
            Priority = 100,
            Rules = [new PatternRule { Type = RuleType.StartsWith, Values = ["MATCH:"] }],
        };
        var status = new RelayStatusBuilder().WithPatterns(statusPattern).Build();
        _builder.StatusService
            .RefreshStatusAsync(Arg.Any<CancellationToken>())
            .Returns(Result.Ok(status));
        _builder.ParserFactory
            .Create(Arg.Any<string>(), Arg.Any<object?>())
            .Returns((IParser?)null);

        using var unitUnderTest = _builder.Build();

        // Act
        var result = await unitUnderTest.MatchPatternAsync("MATCH: test log", CancellationToken.None);

        // Assert
        Assert.Null(result);
    }
}
