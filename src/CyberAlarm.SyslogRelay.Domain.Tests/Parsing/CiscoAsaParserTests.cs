using CyberAlarm.SyslogRelay.Common.Models;
using CyberAlarm.SyslogRelay.Domain.Extensions;
using CyberAlarm.SyslogRelay.Domain.Parsing.Cisco;

namespace CyberAlarm.SyslogRelay.Domain.Tests.Parsing;

public sealed class CiscoAsaParserTests
{
    private readonly CiscoAsaParser _unitUnderTest = new ();

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
                new("10.0.1.50", "192.0.2.1", 4321, 1234, EventProtocol.Tcp, EventAction.Close)
            },
            {
                "%ASA-0-302015: Built inbound UDP connection 123456 for outside:192.0.2.1/1234 (192.0.2.1/1234) to inside:10.0.1.50/4321 (10.0.1.50/4321)",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Udp, EventAction.Allow)
            },
            {
                "%ASA-0-302013: Built outbound TCP connection 2083285076 for outside:135.233.95.135/443 (135.233.95.135/443) to inside:172.16.255.194/61156 (91.220.118.130/61156)",
                new("172.16.255.194", "135.233.95.135", 61156, 443, EventProtocol.Tcp, EventAction.Allow)
            },
            {
                "%ASA-0-302015: Built outbound UDP connection 2083285079 for outside:1.1.1.1/53 (1.1.1.1/53) to inside:172.16.255.200/65383 (91.220.118.130/65383)",
                new("172.16.255.200", "1.1.1.1", 65383, 53, EventProtocol.Udp, EventAction.Allow)
            },
            {
                "%ASA-0-302016: Teardown UDP connection 1861717608 for outside:192.0.2.1/1234 to inside:10.0.1.50/4321 duration 0:00:00 bytes 173",
                new("10.0.1.50", "192.0.2.1", 4321, 1234, EventProtocol.Udp, EventAction.Timeout, TimeSpan.Zero, 173)
            },
            {
                "%ASA-0-106023: Deny tcp src outside:192.0.2.1/1234 dst inside:10.0.1.50/4321 by access-group \"outside_access_in\" [0x2c1c6a65, 0x0]",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "%ASA-4-106023: Deny icmp src outside:18.130.91.160 dst inside:172.16.255.212 (type 11, code 0) by access-group \"outside_access_in\" [0x2c1c6a65, 0x0]",
                new("18.130.91.160", "172.16.255.212", null, null, EventProtocol.Icmp, EventAction.Deny)
            },
            {
                "%ASA-0-313001: Deny icmp src outside:192.0.2.1 dst inside:10.0.1.50 x",
                new("192.0.2.1", "10.0.1.50", null, null, EventProtocol.Icmp, EventAction.Deny)
            },
            {
                "%ASA-3-313001: Denied ICMP type=3, code=3 from 52.112.190.120 on interface outside",
                new("52.112.190.120", null, null, null, EventProtocol.Icmp, EventAction.Deny)
            },
            {
                "<163>: %ASA-3-313001: Denied ICMP type=3, code=3 from 52.112.190.120 on interface outside",
                new("52.112.190.120", null, null, null, EventProtocol.Icmp, EventAction.Deny)
            },
            {
                "%ASA-0-303002: Teardown TCP connection 1861717444 for outside:192.0.2.1/1234 to FrontDMZ:10.0.1.50/4321 x",
                new("10.0.1.50", "192.0.2.1", 4321, 1234, EventProtocol.Tcp, EventAction.Close)
            },
            {
                "%ASA-6-302014: Teardown TCP connection 2083285066 for outside:3.235.189.123/443 to inside:172.16.255.212/52870 duration 0:00:00 bytes 10058 TCP FINs from inside",
                new("172.16.255.212", "3.235.189.123", 52870, 443, EventProtocol.Tcp, EventAction.Close, TimeSpan.Zero, 10058)
            },
            {
                "%ASA-6-302014: Teardown TCP connection 2083285085 for outside:51.124.57.123/8264 to FrontDMZ:192.168.21.105/5061 duration 0:00:00 bytes 0 TCP Reset-I from FrontDMZ",
                new("51.124.57.123", "192.168.21.105", 8264, 5061, EventProtocol.Tcp, EventAction.Reset, TimeSpan.Zero, 0)
            },
            {
                "%ASA-6-302014: Teardown TCP connection 123456789 for outside:203.0.113.10/443 to inside:10.0.1.50/41234 duration 0:05:00 bytes 4096 TCP timeout",
                new("10.0.1.50", "203.0.113.10", 41234, 443, EventProtocol.Tcp, EventAction.Timeout, TimeSpan.FromMinutes(5), 4096)
            },
            {
                "%ASA-6-302016: Teardown UDP connection 2083341754 for outside:1.1.1.1/53 to inside:172.16.255.201/61947 duration 0:00:00 bytes 189",
                new("172.16.255.201", "1.1.1.1", 61947, 53, EventProtocol.Udp, EventAction.Timeout, TimeSpan.Zero, 189)
            },
            {
                "%ASA-6-302014: Teardown TCP connection 2083341229 for inside:172.16.255.31/64922 to ClientVPNSubnet:10.5.202.11/49727 duration 0:00:56 bytes 10272 TCP FINs from inside",
                new("172.16.255.31", "10.5.202.11", 64922, 49727, EventProtocol.Tcp, EventAction.Close, TimeSpan.FromSeconds(56), 10272)
            },
            {
                "%ASA-0-400000: IDS:2001 TCP connection from outside:192.0.2.1/1234 to inside:10.0.1.50/4321",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Deny)
            },
            {
                "%ASA-0-419001: Embryonic limit exceeded nconns 100 for outside:192.0.2.1/1234 to inside:10.0.1.50/4321",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Drop)
            },
            {
                "%ASA-0-419002: Dropping TCP embryonic connection from outside:192.0.2.1/1234 to inside:10.0.1.50/4321",
                new("192.0.2.1", "10.0.1.50", 1234, 4321, EventProtocol.Tcp, EventAction.Drop)
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
