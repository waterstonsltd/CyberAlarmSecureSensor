using System.Text.Json;
using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Common.Models.ParserConfiguration;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing;
using CyberAlarm.SyslogRelay.Domain.Tests.Builders;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class KeyValueParserTests
{
    private readonly KeyValueParser _unitUnderTest = new();

    [Fact]
    public void Initialise_should_fail_when_config_is_not_a_valid_object_type()
    {
        // Act
        var result = _unitUnderTest.Initialise(1);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse config.", result.ErrorMessage);
    }

    [Fact]
    public void Initialise_should_fail_when_config_is_a_json_element_with_incorrect_structure()
    {
        // Arrange
        var config = JsonSerializer.Deserialize<object>("{\"x\":1}");

        // Act
        var result = _unitUnderTest.Initialise(config);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Contains("JSON deserialization", result.ErrorMessage);
        Assert.Contains("was missing required properties", result.ErrorMessage);
    }

    [Fact]
    public void Initialise_should_succeed_when_config_is_a_valid_type()
    {
        // Arrange
        var config = new KeyValueParserConfigBuilder().Build();

        // Act
        var result = _unitUnderTest.Initialise(config);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Parse_should_throw_when_log_is_empty(string? log)
    {
        // Act & Assert
        Assert.ThrowsAny<ArgumentException>(() => _unitUnderTest.Parse(log!));
    }

    [Fact]
    public void Parse_should_throw_when_it_has_not_been_initialised()
    {
        // Act & Assert
        Assert.ThrowsAny<ArgumentNullException>(() => _unitUnderTest.Parse(Guid.NewGuid().ToString()));
    }

    [Fact]
    public void Parse_should_fail_when_log_has_incorrect_format()
    {
        // Arrange
        var config = new KeyValueParserConfigBuilder().Build();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(Guid.NewGuid().ToString());

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("dstip=x srcport=x dstport=x protocol=x action=x")]
    [InlineData("srcip=x srcport=x dstport=x protocol=x action=x")]
    [InlineData("srcip=x dstip=x srcport=x protocol=x action=x")]
    [InlineData("srcip=x dstip=x dstport=x protocol=x action=x")]
    [InlineData("srcip=x dstip=x srcport=x dstport=x action=x")]
    [InlineData("srcip=x dstip=x srcport=x dstport=x protocol=x")]
    public void Parse_should_fail_when_log_does_not_contain_required_value(string log)
    {
        // Arrange
        var config = new KeyValueParserConfigBuilder()
            .WithSourceIpKeys("srcip")
            .WithDestinationIpKeys("dstip")
            .WithSourcePortKeys("srcport")
            .WithDestinationPortKeys("dstport")
            .WithProtocolKeys("proto")
            .WithActionKeys("action")
            .Build();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(TestLogsOptional), MemberType = typeof(KeyValueParserTests))]
    public void Parse_should_succeed_when_log_does_not_contain_optional_value(string log, ParseResult parseResult)
    {
        // Arrange
        var config = new KeyValueParserConfigBuilder()
            .WithSourceIpKeys("srcip")
            .WithDestinationIpKeys("dstip")
            .WithSourcePortKeys("srcport")
            .WithDestinationPortKeys("dstport")
            .WithProtocolKeys("proto")
            .WithActionKeys("action")
            .WithActionValues(["allow"], ["deny"])
            .WithOptional()
            .Build();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    [Theory]
    [MemberData(nameof(FortigateTestLogs), MemberType = typeof(KeyValueParserTests))]
    [MemberData(nameof(SophosTestLogs), MemberType = typeof(KeyValueParserTests))]
    [MemberData(nameof(SophosUtmTestLogs), MemberType = typeof(KeyValueParserTests))]
    [MemberData(nameof(TotalBytesTestLogs), MemberType = typeof(KeyValueParserTests))]
    public void Parse_should_succeed_when_log_has_correct_format(KeyValueParserConfig config, string log, ParseResult parseResult)
    {
        // Arrange
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    [Fact]
    public void Parse_should_succeed_and_correctly_parse_log_when_different_delimiters_are_provided()
    {
        // Arrange
        var config = new KeyValueParserConfigBuilder()
            .WithRegexPattern(@"\s*([^|,\s]+)\s*\|\s*(?:""([^""]*)""|([^,]*?))\s*(?:,|$)")
            .WithSourceIpKeys("srcip")
            .WithDestinationIpKeys("dstip")
            .WithOptional()
            .Build();
        _unitUnderTest.Initialise(config);

        // Act
        var result = _unitUnderTest.Parse(@"x, srcip | x , dstip | ""x, y | z"", x");

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(new ParseResult("x", "x, y | z", null, null, EventProtocol.Unknown, EventAction.Unknown), result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogsOptional =>
        new()
        {
            {
                "x srcip=192.0.2.1 srcport=1234 dstport=4321 proto=6 action=\"allow\" x",
                new("192.0.2.1", null, 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "x srcip=192.0.2.1 dstip=10.0.1.50 dstport=4321 proto=6 action=\"allow\" x",
                new("192.0.2.1", "10.0.1.50", null, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 proto=6 action=\"allow\" x",
                new("192.0.2.1", "10.0.1.50", 1234, null, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 action=\"allow\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Unknown, EventAction.Allow)
            },
            {
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Unknown)
            },
        };

    public static TheoryData<KeyValueParserConfig, string, ParseResult> FortigateTestLogs()
    {
        var config = new KeyValueParserConfigBuilder()
            .WithSourceIpKeys("srcip")
            .WithDestinationIpKeys("dstip")
            .WithSourcePortKeys("srcport")
            .WithDestinationPortKeys("dstport")
            .WithProtocolKeys("proto")
            .WithActionKeys("action")
            .WithActionValues(["accept", "pass", "passthrough", "exempt"], ["deny", "blocked"])
            .WithExtendedActionValues(closeValues: ["close"], resetValues: ["server-rst", "client-rst"], timeoutValues: ["timeout"])
            .WithDurationKeys(isSeconds: true, "duration")
            .WithBytesKeys(["sentbyte"], ["rcvdbyte"])
            .WithOptional(sourcePort: true, destinationPort: true)
            .Build();

        return new()
        {
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"close\" duration=\"196\" sentbyte=8118 rcvdbyte=2456 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Close, TimeSpan.FromSeconds(196), 10574)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"accept\" duration=0 sentbyte=1234 rcvdbyte=0 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow, TimeSpan.FromSeconds(0), 1234)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"timeout\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Timeout)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"server-rst\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Reset)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"client-rst\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Reset)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"deny\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"blocked\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"pass\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"passthrough\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=\"exempt\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            // ICMP / PING traffic has no srcport or dstport
            {
                config,
                "x srcip=10.0.0.1 identifier=8 dstip=10.0.0.2 proto=1 action=\"accept\" duration=60 sentbyte=52 rcvdbyte=52 x",
                new("10.0.0.1", "10.0.0.2", null, null, EventProtocol.Icmp, EventAction.Allow, TimeSpan.FromSeconds(60), 104)
            },
            {
                config,
                "x srcip=10.0.0.1 identifier=8 dstip=10.0.0.2 proto=1 action=\"deny\" duration=0 sentbyte=0 rcvdbyte=0 x",
                new("10.0.0.1", "10.0.0.2", null, null, EventProtocol.Icmp, EventAction.Deny, TimeSpan.FromSeconds(0), 0)
            },
        };
    }

    public static TheoryData<KeyValueParserConfig, string, ParseResult> SophosTestLogs()
    {
        var config = new KeyValueParserConfigBuilder()
            .WithSourceIpKeys("src_ip")
            .WithDestinationIpKeys("dst_ip")
            .WithSourcePortKeys("src_port")
            .WithDestinationPortKeys("dst_port")
            .WithProtocolKeys("protocol")
            .WithActionKeys("status", "log_subtype")
            .WithActionValues(
                ["Accept", "Allow", "Allowed"],
                ["block", "blocked", "deny", "denied", "detect"])
            .WithExtendedActionValues(dropValues: ["drop", "dropped"])
            .Build();

        return new()
        {
            {
                config,
                "x status=\"Allow\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                config,
                "x status=\"Deny\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x log_subtype=\"Accept\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                config,
                "x log_subtype=\"Allowed\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                config,
                "x log_subtype=\"Block\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x log_subtype=\"Blocked\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x log_subtype=\"Denied\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x log_subtype=\"Detect\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x log_subtype=\"Drop\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Drop)
            },
            {
                config,
                "x log_subtype=\"Dropped\" src_ip=192.0.2.1 dst_ip=10.0.1.50 protocol=\"TCP\" src_port=1234 dst_port=4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Drop)
            },
        };
    }

    public static TheoryData<KeyValueParserConfig, string, ParseResult> SophosUtmTestLogs()
    {
        var config = new KeyValueParserConfigBuilder()
            .WithSourceIpKeys("srcip")
            .WithDestinationIpKeys("dstip")
            .WithSourcePortKeys("srcport")
            .WithDestinationPortKeys("dstport")
            .WithProtocolKeys("proto")
            .WithActionKeys("action")
            .WithActionValues(["accept", "alert"], ["ICMP flood", "reject", "SYN flood", "UDP flood"])
            .WithExtendedActionValues(dropValues: ["drop"])
            .Build();

        return new()
        {
            {
                config,
                "x action=\"accept\" srcip=\"192.0.2.1\" dstip=\"10.0.1.50\" proto=\"6\" srcport=\"1234\" dstport=\"4321\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                config,
                "x action=\"drop\" srcip=\"192.0.2.1\" dstip=\"10.0.1.50\" proto=\"6\" srcport=\"1234\" dstport=\"4321\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Drop)
            },
            {
                config,
                "x action=\"reject\" srcip=\"192.0.2.1\" dstip=\"10.0.1.50\" proto=\"6\" srcport=\"1234\" dstport=\"4321\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x action=\"UDP flood\" srcip=\"192.0.2.1\" dstip=\"10.0.1.50\" proto=\"6\" srcport=\"1234\" dstport=\"4321\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x action=\"SYN flood\" srcip=\"192.0.2.1\" dstip=\"10.0.1.50\" proto=\"6\" srcport=\"1234\" dstport=\"4321\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x action=\"ICMP flood\" srcip=\"192.0.2.1\" dstip=\"10.0.1.50\" proto=\"6\" srcport=\"1234\" dstport=\"4321\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                config,
                "x action=\"alert\" srcip=\"192.0.2.1\" dstip=\"10.0.1.50\" proto=\"6\" srcport=\"1234\" dstport=\"4321\" x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
        };
    }

    public static TheoryData<KeyValueParserConfig, string, ParseResult> TotalBytesTestLogs()
    {
        var config = new KeyValueParserConfigBuilder()
            .WithSourceIpKeys("srcip")
            .WithDestinationIpKeys("dstip")
            .WithSourcePortKeys("srcport")
            .WithDestinationPortKeys("dstport")
            .WithProtocolKeys("proto")
            .WithActionKeys("action")
            .WithActionValues(["allow"], ["deny"])
            .WithTotalBytesKeys("totalbytes")
            .Build();

        return new()
        {
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=allow totalbytes=5000 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow, null, 5000)
            },
            {
                config,
                "x srcip=192.0.2.1 srcport=1234 dstip=10.0.1.50 dstport=4321 proto=6 action=allow x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
        };
    }
}
