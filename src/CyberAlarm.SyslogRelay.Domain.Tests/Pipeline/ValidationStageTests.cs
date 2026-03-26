using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Pipeline;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Pipeline;

public sealed class ValidationStageTests
{
    private readonly ValidationStageBuilder _builder = new();

    [Fact]
    public async Task Should_return_unable_to_pattern_match_status_when_no_pattern_match_result_is_set()
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var input = new ParsingStageOutput(syslogEvent, null, null);

        var outputs = new List<ValidationStageOutput>();
        var unitUnderTest = _builder
            .WithOutputCollection(outputs)
            .Build();

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        var result = Assert.Single(outputs);
        Assert.Equal(ValidationStatus.UnableToPatternMatch, result.ValidationResult.ValidationStatus);
        Assert.Null(result.PatternMatchResult);
        Assert.Null(result.ParseResult);
    }

    [Fact]
    public async Task Should_return_unable_to_parse_status_when_no_parse_result_is_set()
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var input = new ParsingStageOutput(syslogEvent, patternMatchResult, null);

        var outputs = new List<ValidationStageOutput>();
        var unitUnderTest = _builder
            .WithOutputCollection(outputs)
            .Build();

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        var result = Assert.Single(outputs);
        Assert.Equal(ValidationStatus.UnableToParse, result.ValidationResult.ValidationStatus);
        Assert.Null(result.ParseResult);
    }

    [Fact]
    public async Task Should_return_ignored_status_when_is_ignored_is_set()
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("Fortigate", Substitute.For<IParser>(), ["type=\"siem\""]);
        var input = new ParsingStageOutput(syslogEvent, patternMatchResult, null, IsIgnored: true);

        var outputs = new List<ValidationStageOutput>();
        var unitUnderTest = _builder
            .WithOutputCollection(outputs)
            .Build();

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        var result = Assert.Single(outputs);
        Assert.Equal(ValidationStatus.Ignored, result.ValidationResult.ValidationStatus);
    }

    [Theory]
    [InlineData("10.0.0.1", null)]
    [InlineData("10.0.0.1", "192.0.2.1")]
    [InlineData("192.0.2.1", "10.0.0.1")]
    public async Task Should_not_return_local_only_event_status_when_either_source_or_destination_ip_is_not_local(string sourceIp, string? destinationIp)
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp(sourceIp)
            .WithDestinationIp(destinationIp)
            .Build();
        var input = new ParsingStageOutput(syslogEvent, patternMatchResult, parseResult);

        var outputs = new List<ValidationStageOutput>();
        var unitUnderTest = _builder
            .WithOutputCollection(outputs)
            .Build();

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        var result = Assert.Single(outputs);
        Assert.NotEqual(ValidationStatus.LocalOnlyEvent, result.ValidationResult.ValidationStatus);
    }

    [Theory]
    [InlineData("10.0.0.1", "10.1.0.1")]
    [InlineData("172.16.0.1", "172.16.1.1")]
    [InlineData("192.168.0.1", "192.168.1.1")]
    [InlineData("10.0.0.1", "192.168.0.1")]
    [InlineData("fc00::1", "fc00::2")]
    [InlineData("fd00::1", "fd00::2")]
    public async Task Should_return_local_only_event_status_when_both_source_and_destination_ips_are_local(string sourceIp, string destinationIp)
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp(sourceIp)
            .WithDestinationIp(destinationIp)
            .Build();
        var input = new ParsingStageOutput(syslogEvent, patternMatchResult, parseResult);

        var outputs = new List<ValidationStageOutput>();
        var unitUnderTest = _builder
            .WithOutputCollection(outputs)
            .Build();

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        var result = Assert.Single(outputs);
        Assert.Equal(ValidationStatus.LocalOnlyEvent, result.ValidationResult.ValidationStatus);
    }

    [Fact]
    public async Task Should_return_local_only_event_status_when_both_source_and_destination_ips_belong_to_configured_additional_local_subnet()
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp("198.51.100.1")
            .WithDestinationIp("198.51.100.2")
            .Build();
        var input = new ParsingStageOutput(syslogEvent, patternMatchResult, parseResult);

        var outputs = new List<ValidationStageOutput>();
        var unitUnderTest = _builder
            .WithOptions(new PipelineOptions { AdditionalLocalSubnet = "198.51.100.0/24", })
            .WithOutputCollection(outputs)
            .Build();

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        var result = Assert.Single(outputs);
        Assert.Equal(ValidationStatus.LocalOnlyEvent, result.ValidationResult.ValidationStatus);
    }

    [Fact]
    public async Task Should_return_success_status_when_all_validations_pass()
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder().Build();
        var input = new ParsingStageOutput(syslogEvent, patternMatchResult, parseResult);

        var outputs = new List<ValidationStageOutput>();
        var unitUnderTest = _builder
            .WithOutputCollection(outputs)
            .Build();

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        var result = Assert.Single(outputs);
        Assert.Equal(ValidationStatus.Success, result.ValidationResult.ValidationStatus);
    }
}
