using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class CiscoAsaParserTests
{
    private readonly CiscoAsaParser _unitUnderTest = new ();

    [Fact]
    public void Name_should_return_class_name()
    {
        // Act & Assert
        Assert.Equal(nameof(CiscoAsaParser), _unitUnderTest.Name);
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
    public void Parse_should_fail_when_log_has_incorrect_format()
    {
        // Act
        var result = _unitUnderTest.Parse(Guid.NewGuid().ToString());

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Log format is invalid.", result.ErrorMessage);
    }

    [Theory]
    [InlineData("%ASA-0-000000: x")]
    [InlineData("%ASA-0-106001: x")]
    public void Parse_should_fail_when_log_cannot_be_parsed(string log)
    {
        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsFailed);
        Assert.Equal("Failed to parse event.", result.ErrorMessage);
    }

    [Theory]
    [MemberData(nameof(TestLogs), MemberType = typeof(CiscoAsaParserTests))]
    public void Parse_should_succeed_when_log_has_correct_format(string log, ParseResult parseResult)
    {
        // Act
        var result = _unitUnderTest.Parse(log);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(parseResult, result.Value);
    }

    public static TheoryData<string, ParseResult> TestLogs =>
        new()
        {
            {
                "%ASA-0-106001: Inbound TCP connection denied from 192.0.2.1/1234 to 10.0.1.50/4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "%ASA-0-106006: Deny inbound UDP from 192.0.2.1/1234 to 10.0.1.50/4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Udp, EventAction.Deny)
            },
            {
                "%ASA-0-106007: Deny inbound UDP from outside:192.0.2.1/1234 to inside:10.0.1.50/4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Udp, EventAction.Deny)
            },
            {
                "%ASA-0-106014: Deny inbound icmp src outside:192.0.2.1 dst inside:10.0.1.50 x",
                new("192.0.2.1", "10.0.1.50", null, null, EventProtocol.Icmp, EventAction.Deny)
            },
            {
                "%ASA-0-106015: Deny TCP (no connection) from 192.0.2.1/1234 to 10.0.1.50/4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "%ASA-0-106018: ICMP packet from outside:192.0.2.1 to inside:10.0.1.50 x",
                new("192.0.2.1", "10.0.1.50", null, null, EventProtocol.Icmp, EventAction.Deny)
            },
            {
                "%ASA-0-106020: Deny IP from 192.0.2.1 to 10.0.1.50, x",
                new("192.0.2.1", "10.0.1.50", null, null, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "%ASA-0-106021: Deny protocol 1 reverse path check from 192.0.2.1 to 10.0.1.50 x",
                new("192.0.2.1", "10.0.1.50", null, null, EventProtocol.Icmp, EventAction.Deny)
            },
            {
                "%ASA-0-106021: Deny protocol 6 reverse path check from 192.0.2.1 to 10.0.1.50 x",
                new("192.0.2.1", "10.0.1.50", null, null, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "%ASA-0-106021: Deny protocol 17 reverse path check from 192.0.2.1 to 10.0.1.50 x",
                new("192.0.2.1", "10.0.1.50", null, null, EventProtocol.Udp, EventAction.Deny)
            },
            {
                "%ASA-0-106100: access-list outside_in permitted tcp outside/192.0.2.1(1234) -> inside/10.0.1.50(4321) x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "%ASA-0-302013: Built inbound TCP connection 3124260595 for outside:192.0.2.1/1234 (192.0.2.1/1234) to inside:10.0.1.50/4321 (10.0.1.50/443)",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "%ASA-0-302014: Teardown TCP connection 1861717444 for outside:192.0.2.1/1234 to FrontDMZ:10.0.1.50/4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "%ASA-0-302015: Built inbound UDP connection 123456 for outside:192.0.2.1/1234 (192.0.2.1/1234) to inside:10.0.1.50/4321 (10.0.1.50/4321)",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Udp, EventAction.Allow)
            },
            {
                "%ASA-0-302016: Teardown UDP connection 1861717608 for outside:192.0.2.1/1234 to inside:10.0.1.50/4321 duration 0:00:00 bytes 173",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Udp, EventAction.Allow)
            },
            {
                "%ASA-0-313001: Deny icmp src outside:192.0.2.1 dst inside:10.0.1.50 x",
                new("192.0.2.1", "10.0.1.50", null, null, EventProtocol.Icmp, EventAction.Deny)
            },
            {
                "%ASA-0-303002: Teardown TCP connection 1861717444 for outside:192.0.2.1/1234 to FrontDMZ:10.0.1.50/4321 x",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "%ASA-0-400000: IDS:2001 TCP connection from outside:192.0.2.1/1234 to inside:10.0.1.50/4321",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "%ASA-0-419001: Embryonic limit exceeded nconns 100 for outside:192.0.2.1/1234 to inside:10.0.1.50/4321",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "%ASA-0-419002: Dropping TCP embryonic connection from outside:192.0.2.1/1234 to inside:10.0.1.50/4321",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "%ASA-0-733101: [x] Host 192.0.2.1 is attacking x",
                new("192.0.2.1", null, null, null, EventProtocol.Unknown, EventAction.Unknown)
            },
            {
                "%ASA-0-733102: [x] Shunning host 192.0.2.1 x",
                new("192.0.2.1", null, null, null, EventProtocol.Unknown, EventAction.Unknown)
            },
            {
                "%ASA-0-733201: [x] Host 192.0.2.1 is attacking with remote access x",
                new("192.0.2.1", null, null, null, EventProtocol.Unknown, EventAction.Unknown)
            },
        };
}
