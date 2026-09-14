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
    [InlineData("10.2.250.244", "169.254.169.254")]  // RFC 3927 link-local destination
    [InlineData("169.254.1.1", "169.254.2.2")]        // both link-local
    [InlineData("fe80::1", "fe80::2")]                 // IPv6 link-local
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

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("169.254.1.1", true)]    // IPv4 link-local
    [InlineData("fc00::1", true)]         // IPv6 unique local
    [InlineData("fd00::1", true)]         // IPv6 unique local
    [InlineData("fe80::1", true)]         // IPv6 link-local
    [InlineData("8.8.8.8", false)]        // Public IP
    [InlineData("192.0.2.1", false)]      // TEST-NET-1 (public)
    [InlineData("203.0.113.1", false)]    // TEST-NET-3 (public)
    public async Task Should_set_IsSourceLocal_flag_correctly(string sourceIp, bool expectedIsSourceLocal)
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp(sourceIp)
            .WithDestinationIp("8.8.8.8") // Public destination to avoid LocalOnlyEvent
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
        Assert.Equal(expectedIsSourceLocal, result.ParseResult?.IsSourceLocal);
    }

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("169.254.1.1", true)]    // IPv4 link-local
    [InlineData("8.8.8.8", false)]        // Public IP
    [InlineData("203.0.113.1", false)]    // TEST-NET-3 (public)
    public async Task Should_set_IsDestinationLocal_flag_correctly(string destinationIp, bool expectedIsDestinationLocal)
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp("8.8.8.8") // Public source to avoid LocalOnlyEvent
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
        Assert.Equal(expectedIsDestinationLocal, result.ParseResult?.IsDestinationLocal);
    }

    [Fact]
    public async Task Should_set_IsDestinationLocal_to_null_when_destination_ip_is_null()
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp("8.8.8.8")
            .WithDestinationIp(null)
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
        Assert.Null(result.ParseResult?.IsDestinationLocal);
        Assert.False(result.ParseResult?.IsSourceLocal);
    }

    [Fact]
    public async Task Should_set_IsSourceLocal_true_for_additional_configured_subnet()
    {
        // Arrange - 198.51.100.0/24 is TEST-NET-2 (normally public)
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp("198.51.100.50")
            .WithDestinationIp("8.8.8.8")
            .Build();
        var input = new ParsingStageOutput(syslogEvent, patternMatchResult, parseResult);

        var outputs = new List<ValidationStageOutput>();
        var unitUnderTest = _builder
            .WithOptions(new PipelineOptions { AdditionalLocalSubnet = "198.51.100.0/24" })
            .WithOutputCollection(outputs)
            .Build();

        // Act
        await unitUnderTest.StartAsync(CancellationToken.None);
        await unitUnderTest.EnqueueAsync(input, CancellationToken.None);
        await unitUnderTest.StopAsync(CancellationToken.None);

        // Assert
        var result = Assert.Single(outputs);
        Assert.True(result.ParseResult?.IsSourceLocal);
        Assert.False(result.ParseResult?.IsDestinationLocal);
    }

    [Fact]
    public async Task Should_set_both_locality_flags_when_both_ips_are_local()
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp("10.0.0.1")
            .WithDestinationIp("192.168.1.1")
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
        Assert.True(result.ParseResult?.IsSourceLocal);
        Assert.True(result.ParseResult?.IsDestinationLocal);
    }

    [Theory]
    [InlineData("flags=\"SD\"")]
    [InlineData("duration=\"128")]
    [InlineData("not-an-ip")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("256.256.256.256")]
    [InlineData("abc::xyz")]
    public async Task Should_return_unable_to_parse_status_when_source_ip_is_not_valid(string invalidSourceIp)
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp(invalidSourceIp)
            .WithDestinationIp("8.8.8.8")
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
        Assert.Equal(ValidationStatus.UnableToParse, result.ValidationResult.ValidationStatus);
        Assert.Null(result.ParseResult);
    }

    [Theory]
    [InlineData("flags=\"SD\"")]
    [InlineData("duration=\"128")]
    [InlineData("not-an-ip")]
    [InlineData("256.256.256.256")]
    [InlineData("abc::xyz")]
    public async Task Should_return_unable_to_parse_status_when_destination_ip_is_not_valid(string invalidDestinationIp)
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp("8.8.8.8")
            .WithDestinationIp(invalidDestinationIp)
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
        Assert.Equal(ValidationStatus.UnableToParse, result.ValidationResult.ValidationStatus);
        Assert.Null(result.ParseResult);
    }

    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("::1")]
    [InlineData("2001:db8::1")]
    [InlineData("fe80::1")]
    public async Task Should_accept_valid_ip_addresses(string validIp)
    {
        // Arrange
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp(validIp)
            .WithDestinationIp("8.8.8.8")
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
        Assert.NotEqual(ValidationStatus.UnableToParse, result.ValidationResult.ValidationStatus);
    }

    [Theory]
    [InlineData("10.0.0.1", "8.8.8.8")]
    [InlineData("192.168.1.1", "203.0.113.1")]
    public async Task Should_return_outbound_event_status_when_source_is_local_and_destination_is_external(string sourceIp, string destinationIp)
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
        Assert.Equal(ValidationStatus.OutboundEvent, result.ValidationResult.ValidationStatus);
    }

    [Theory]
    [InlineData("10.0.0.1", "8.8.8.8")]
    [InlineData("192.168.1.1", "203.0.113.1")]
    public async Task Should_return_success_when_source_is_local_and_destination_is_external_and_upload_outbound_data_is_true(string sourceIp, string destinationIp)
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
            .WithOptions(new PipelineOptions { UploadOutboundData = true })
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

    [Fact]
    public async Task Should_not_return_outbound_event_status_when_source_is_external_and_destination_is_local()
    {
        // Arrange — inbound traffic: source external, destination local
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp("8.8.8.8")
            .WithDestinationIp("192.168.1.1")
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
        Assert.NotEqual(ValidationStatus.OutboundEvent, result.ValidationResult.ValidationStatus);
    }

    [Fact]
    public async Task Should_not_return_outbound_event_status_when_destination_is_null()
    {
        // Arrange — no destination IP, so IsDestinationLocal is null — not outbound
        var syslogEvent = SyslogEvent.FromFile("root", "x");
        var patternMatchResult = new PatternMatchResult("x", Substitute.For<IParser>());
        var parseResult = new ParseResultBuilder()
            .WithSourceIp("10.0.0.1")
            .WithDestinationIp(null)
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
        Assert.NotEqual(ValidationStatus.OutboundEvent, result.ValidationResult.ValidationStatus);
    }
}
