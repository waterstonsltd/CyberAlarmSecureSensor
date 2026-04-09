using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class ParsingExtensionsTests
{
    [Fact]
    public void ParseConfig_should_return_null_when_called_on_an_invalid_object_type()
    {
        // Act
        var result = new { x = 1 }.ParseConfig<ParserConfig>();

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ParseConfig_should_return_config_when_called_on_a_valid_object_type()
    {
        // Arrange
        var config = new ParserConfigBuilder().Build();

        // Act
        var result = config.ParseConfig<ParserConfig>();

        // Assert
        Assert.NotNull(result);
        Assert.Equal(result.SourceIpKeys, config.SourceIpKeys);
        Assert.Equal(result.DestinationIpKeys, config.DestinationIpKeys);
        Assert.Equal(result.SourcePortKeys, config.SourcePortKeys);
        Assert.Equal(result.DestinationPortKeys, config.DestinationPortKeys);
        Assert.Equal(result.ProtocolKeys, config.ProtocolKeys);
        Assert.Equal(result.ActionKeys, config.ActionKeys);
        Assert.Equal(result.AllowActionValues, config.AllowActionValues);
        Assert.Equal(result.DenyActionValues, config.DenyActionValues);
    }

    [Fact]
    public void ParseConfig_should_throw_when_called_on_a_json_element_with_incorrect_structure()
    {
        // Arrange
        var config = JsonSerializer.Deserialize<object>("{\"x\":1}");

        // Act
        var exception = Assert.Throws<JsonException>(config.ParseConfig<ParserConfig>);

        // Assert
        Assert.StartsWith("JSON deserialization for type", exception.Message);
        Assert.Contains("was missing required properties", exception.Message);
    }

    [Fact]
    public void ParseConfig_should_return_config_when_called_on_a_json_element_with_correct_structure()
    {
        // Arrange
        var config = new
        {
            SourceIpKeys = new string[] { "srcip" },
            DestinationIpKeys = new string[] { "dstip" },
            SourcePortKeys = new string[] { "srcport" },
            DestinationPortKeys = new string[] { "dstport" },
            ProtocolKeys = new string[] { "proto" },
            ActionKeys = new string[] { "action" },
            AllowActionValues = new string[] { "allow" },
            DenyActionValues = new string[] { "deny" },
        };

        var configObject = JsonSerializer.Deserialize<object>(JsonSerializer.Serialize(config));

        // Act
        var result = configObject.ParseConfig<ParserConfig>();

        // Assert
        Assert.NotNull(result);
        Assert.Equal(result.SourceIpKeys, config.SourceIpKeys);
        Assert.Equal(result.DestinationIpKeys, config.DestinationIpKeys);
        Assert.Equal(result.SourcePortKeys, config.SourcePortKeys);
        Assert.Equal(result.DestinationPortKeys, config.DestinationPortKeys);
        Assert.Equal(result.ProtocolKeys, config.ProtocolKeys);
        Assert.Equal(result.ActionKeys, config.ActionKeys);
        Assert.Equal(result.AllowActionValues, config.AllowActionValues);
        Assert.Equal(result.DenyActionValues, config.DenyActionValues);
    }

    [Fact]
    public void ParseKeyValues_by_delimiters_should_return_empty_dictionary_when_no_key_value_matches_found()
    {
        // Act
        var result = "x".ParseKeyValues(' ', '=');

        // Assert
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void ParseKeyValues_by_delimiters_should_return_dictionary_with_parsed_key_value_pairs()
    {
        // Act
        var result = " x=1   y=2 ".ParseKeyValues(' ', '=');

        // Assert
        Assert.NotNull(result);
        Assert.Equal(2, result.Count);
        Assert.Equal("1", result["x"]);
        Assert.Equal("2", result["y"]);
    }

    [Fact]
    public void ParseKeyValues_by_regex_should_return_null_when_no_key_value_matches_found()
    {
        // Act
        var result = "x".ParseKeyValues([]);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void ParseKeyValues_by_regex_should_return_dictionary_with_parsed_key_value_pairs()
    {
        // Act
        var result = "x=1 y=\"2\"    z=3".ParseKeyValues([]);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(3, result.Count);
        Assert.Equal("1", result["x"]);
        Assert.Equal("2", result["y"]);
        Assert.Equal("3", result["z"]);
    }

    [Theory]
    [InlineData("", EventProtocol.Unknown)]
    [InlineData("x", EventProtocol.Unknown)]
    [InlineData("-1", EventProtocol.Unknown)]
    [InlineData("1", EventProtocol.Icmp)]
    [InlineData("icmp", EventProtocol.Icmp)]
    [InlineData("ICMP", EventProtocol.Icmp)]
    public void ToProtocol_should_return_protocol_enum(string value, EventProtocol expected)
    {
        // Act
        var result = value.ToProtocol();

        // Assert
        Assert.Equal(expected, result);
    }
}
